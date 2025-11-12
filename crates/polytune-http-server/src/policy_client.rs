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
use reqwest_middleware::ClientWithMiddleware;
use schemars::JsonSchema;
use serde::Serialize;
use tracing::{Level, debug, error};
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
            debug!("signing new JWT");
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
        let url = self.participants[to]
            .join(route)
            .expect("unable to parse URL");
        let mut req = self.client.post(url.clone()).json(&req);
        if let Some(jwt) = self.jwt()? {
            req = req.bearer_auth(jwt);
        }
        let resp = req
            .send()
            .await
            .map_err(|err| HttpClientError::Request { url, source: err })?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let err = error_constructor(
                resp.text()
                    .await
                    .unwrap_or_else(|err| format_error_chain(&err)),
            );
            error!(%err, route);
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
        let route = &format!("msg/{}/{}", self.computation_id, self.party);
        let url = self.participants[to]
            .join(route)
            .expect("unable to parse URL");
        let mut req = self.client.post(url.clone()).body(msg.data);
        if let Some(jwt) = self.jwt()? {
            req = req.bearer_auth(jwt);
        }
        let resp = req
            .send()
            .await
            .map_err(|err| HttpClientError::Request { url, source: err })?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(HttpClientError::MpcMsg(
                resp.text()
                    .await
                    .unwrap_or_else(|err| format_error_chain(&err)),
            ))
        }
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
        let mut req = self.client.post(to.clone()).json(&result);
        if let Some(jwt) = self.jwt()? {
            req = req.bearer_auth(jwt);
        }
        let resp = req.send().await.map_err(|err| HttpClientError::Request {
            url: to,
            source: err,
        })?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(HttpClientError::Output(
                resp.text()
                    .await
                    .unwrap_or_else(|err| format_error_chain(&err)),
            ))
        }
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

#[cfg(test)]
mod tests {
    use schemars::schema_for;

    use crate::MpcResult;

    #[test]
    #[ignore = "Run manually with --include-ignored --nocapture to get MpcResult schema"]
    fn mpc_result_schema() {
        let schema = schema_for!(MpcResult);
        let serialized =
            serde_json::to_string_pretty(&schema).expect("schema serialization failed");
        println!("{serialized}");
    }
}
