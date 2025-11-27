use std::{
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use garble_lang::literal::Literal;
use jsonwebtoken::{Algorithm, Header, encode};
use polytune_server_core::{
    ConstsRequest, MpcMsg, OutputError, Policy, PolicyClient, PolicyClientBuilder, RunRequest,
    ValidateRequest,
};
use reqwest_middleware::{ClientWithMiddleware, RequestBuilder};
use schemars::JsonSchema;
use serde::Serialize;
use tracing::{Level, debug, error, trace};
use url::Url;
use uuid::Uuid;

use crate::{format_error_chain, server::JwtConf};

#[derive(Clone)]
pub(crate) struct HttpClientBuilder {
    pub(crate) client: ClientWithMiddleware,
    pub(crate) jwt_conf: Option<JwtConf>,
}

impl PolicyClientBuilder for HttpClientBuilder {
    type Client = HttpClient;

    fn new_client(&self, policy: &Policy) -> Self::Client {
        let jwt_data = self.jwt_conf.as_ref().map(|conf| {
            Mutex::new(JwtData {
                expiry: SystemTime::now(),
                jwt: String::new(),
                conf: conf.clone(),
            })
        });
        HttpClient {
            client: self.client.clone(),
            participants: policy.participants.clone(),
            party: policy.party,
            computation_id: policy.computation_id,
            jwt_data,
        }
    }
}

pub(crate) struct HttpClient {
    client: ClientWithMiddleware,
    party: usize,
    computation_id: Uuid,
    participants: Vec<Url>,
    jwt_data: Option<Mutex<JwtData>>,
}

struct JwtData {
    expiry: SystemTime,
    jwt: String,
    conf: JwtConf,
}

#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    iat: u64,
    exp: u64,
    #[serde(flatten)]
    additional_claims: Option<serde_json::Map<String, serde_json::Value>>,
}

impl JwtData {
    fn update_jwt(&mut self) -> Result<(), jsonwebtoken::errors::Error> {
        // if we're less than 30 seconds from the JWT expiring
        if SystemTime::now()
            .checked_add(Duration::from_secs(30))
            .expect("Invalid SystemTime")
            > self.expiry
        {
            let now = SystemTime::now();
            let expiry = now + Duration::from_secs(self.conf.exp);
            let iat = now
                .duration_since(UNIX_EPOCH)
                .expect("invalid system time")
                .as_secs();
            let exp = expiry
                .duration_since(UNIX_EPOCH)
                .expect("invalid system time")
                .as_secs();
            let claims = JwtClaims {
                iss: self.conf.iss.clone(),
                iat,
                exp,
                additional_claims: self.conf.claims.clone(),
            };
            let header = Header::new(Algorithm::ES256);
            let jwt = encode(&header, &claims, &self.conf.key)?;
            debug!(?header, ?claims, "signed new JWT");
            self.expiry = expiry;
            self.jwt = jwt;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpClientError {
    #[error("failed request to {url}")]
    Request {
        url: Url,
        source: reqwest_middleware::Error,
    },
    #[error("validation request failed with error: {0}")]
    Validate(String),
    #[error("run request failed with error: {0}")]
    Run(String),
    #[error("consts request failed with error: {0}")]
    Consts(String),
    #[error("mpc msg request failed with error: {0}")]
    MpcMsg(String),
    #[error("output request failed with error: {0}")]
    Output(String),
    #[error("JWT signing failed")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("the {0} URL is not a base URL")]
    NoBaseUrl(Url),
}

impl HttpClient {
    fn jwt(&self) -> Result<Option<String>, jsonwebtoken::errors::Error> {
        if let Some(jwt_data) = &self.jwt_data {
            let mut jwt_data = jwt_data.lock().expect("jwt_data poison");
            jwt_data.update_jwt()?;
            Ok(Some(jwt_data.jwt.clone()))
        } else {
            Ok(None)
        }
    }

    async fn make_request<R, F>(
        &self,
        route: &str,
        to: usize,
        req: R,
        error_constructor: F,
    ) -> Result<(), HttpClientError>
    where
        R: Serialize,
        F: Fn(String) -> HttpClientError,
    {
        let url = extend_url(&self.participants[to], [route])?;
        debug!(%url, "making request to");
        let req = self.client.post(url.clone()).json(&req);
        self.send_request(req, route, url, error_constructor).await
    }

    async fn send_request<F>(
        &self,
        mut req: RequestBuilder,
        route: &str,
        url: Url,
        error_constructor: F,
    ) -> Result<(), HttpClientError>
    where
        F: Fn(String) -> HttpClientError,
    {
        if let Some(jwt) = self.jwt()? {
            trace!("setting authorization header to JWT");
            req = req.bearer_auth(jwt);
        }
        let resp = req
            .send()
            .await
            .map_err(|err| HttpClientError::Request { url, source: err })?;
        let status_code = resp.status();
        if status_code.is_success() {
            Ok(())
        } else {
            let err = error_constructor(
                resp.text()
                    .await
                    .unwrap_or_else(|err| format_error_chain(&err)),
            );
            error!(%err, %status_code, route);
            Err(err)
        }
    }
}

impl PolicyClient for HttpClient {
    type Error = HttpClientError;

    #[tracing::instrument(level = Level::DEBUG, skip(self))]
    async fn validate(&self, to: usize, req: ValidateRequest) -> Result<(), Self::Error> {
        self.make_request("validate", to, req, HttpClientError::Validate)
            .await
    }

    #[tracing::instrument(level = Level::DEBUG, skip(self))]
    async fn run(&self, to: usize, req: RunRequest) -> Result<(), Self::Error> {
        self.make_request("run", to, req, HttpClientError::Run)
            .await
    }

    #[tracing::instrument(level = Level::DEBUG, skip(self))]
    async fn consts(&self, to: usize, req: ConstsRequest) -> Result<(), Self::Error> {
        self.make_request("consts", to, req, HttpClientError::Consts)
            .await
    }

    #[tracing::instrument(level = Level::TRACE, skip(self))]
    async fn msg(&self, to: usize, msg: MpcMsg) -> Result<(), Self::Error> {
        let path_segments = [
            "msg",
            &format!("{}", self.computation_id),
            &format!("{}", self.party),
        ];
        let route = &format!("msg/{}/{}", self.computation_id, self.party);
        let url = extend_url(&self.participants[to], path_segments)?;
        let req = self.client.post(url.clone()).body(msg.data);
        self.send_request(req, route, url, HttpClientError::MpcMsg)
            .await
    }

    #[tracing::instrument(skip(self, result), fields(%to), err)]
    async fn output(
        &self,
        to: Url,
        result: Result<Literal, OutputError>,
    ) -> Result<(), Self::Error> {
        if let Err(err) = &result {
            error!(%err, "Sending error to output party");
        }
        let result = MpcResult::from(result);
        debug!(url = %to, "making request to");
        let req = self.client.post(to.clone()).json(&result);
        self.send_request(req, "", to, HttpClientError::Output)
            .await
    }
}

/// Result of the Policy evaluation.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(tag = "type", content = "details")]
#[serde(rename_all = "camelCase")]
pub enum MpcResult {
    /// The [`garble_lang`] output value.
    Success(Literal),
    /// The occured error.
    #[serde(serialize_with = "crate::serialize_error_chain")]
    #[schemars(with = "String")]
    Error(OutputError),
}

impl From<Result<Literal, OutputError>> for MpcResult {
    fn from(value: Result<Literal, OutputError>) -> Self {
        match value {
            Ok(lit) => MpcResult::Success(lit),
            Err(err) => MpcResult::Error(err),
        }
    }
}

/// Join URL with the specified path. Contrary to the [`Url::join`] method,
/// this method does not replace the last part of the base URL path if there
/// is no trailing slash.
///
/// ```ignore
/// let base = Url::parse("http://localhost:8000/some-path").unwrap();
/// let joined = extend_url(&base, ["validate"]).unwrap();
///
/// assert_eq!("http://localhost:8000/some-path/validate", joined.as_str());
///
/// // With trailing slash
/// let base = Url::parse("http://localhost:8000/some-path/").unwrap();
/// let joined = extend_url(&base, ["validate"]).unwrap();
///
/// assert_eq!("http://localhost:8000/some-path/validate", joined.as_str());
///
/// // Join multiple segments
/// let base = Url::parse("http://localhost:8000/some-path/").unwrap();
/// let joined = extend_url(&base, ["msg", "to-id", "party"]).unwrap();
///
/// assert_eq!(
///     "http://localhost:8000/some-path/msg/to-id/party",
///     joined.as_str()
/// );
/// ```
fn extend_url<'a>(
    url: &Url,
    segments: impl IntoIterator<Item = &'a str>,
) -> Result<Url, HttpClientError> {
    let mut url = url.clone();
    // limit scope of segments as otherwise drop conflicts with returning url
    {
        let Ok(mut path_segments) = url.path_segments_mut() else {
            return Err(HttpClientError::NoBaseUrl(url));
        };
        path_segments
            // Remove trailing slash if segment is empty, i.e. some-path/ -> some-path
            .pop_if_empty()
            // Add new segments, i.e. some-path -> some-path/validate
            .extend(segments);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use schemars::schema_for;
    use url::Url;

    use crate::{MpcResult, policy_client::extend_url};

    #[test]
    #[ignore = "Run manually with --include-ignored --nocapture to get MpcResult schema"]
    fn mpc_result_schema() {
        let schema = schema_for!(MpcResult);
        let serialized =
            serde_json::to_string_pretty(&schema).expect("schema serialization failed");
        println!("{serialized}");
    }

    #[test]
    fn test_join_url() {
        let base = Url::parse("http://localhost:8000/some-path").expect("Url parse failed");
        let joined = extend_url(&base, ["validate"]).expect("Url extend failed");

        assert_eq!("http://localhost:8000/some-path/validate", joined.as_str());

        // With trailing slash
        let base = Url::parse("http://localhost:8000/some-path/").expect("Url parse failed");
        let joined = extend_url(&base, ["validate"]).expect("Url extend failed");

        assert_eq!("http://localhost:8000/some-path/validate", joined.as_str());

        // Join multiple segments
        let base = Url::parse("http://localhost:8000/some-path/").expect("Url parse failed");
        let joined = extend_url(&base, ["msg", "to-id", "party"]).expect("Url extend failed");

        assert_eq!(
            "http://localhost:8000/some-path/msg/to-id/party",
            joined.as_str()
        );
    }
}
