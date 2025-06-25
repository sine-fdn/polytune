use std::time::Duration;

use polytune::channel::{Channel, RecvInfo, SendInfo};
use reqwest::StatusCode;
use tokio::time::sleep;

pub(crate) struct PollingHttpChannel {
    pub(crate) url: String,
    pub(crate) session: String,
    pub(crate) party: usize,
    pub(crate) client: reqwest::Client,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum HttpChannelError {
    Timeout,
    Reqwest(reqwest::Error),
    UnexpectedStatusCode(reqwest::StatusCode),
}

impl From<reqwest::Error> for HttpChannelError {
    fn from(e: reqwest::Error) -> Self {
        Self::Reqwest(e)
    }
}

impl PollingHttpChannel {
    pub(crate) fn new(url: &str, session: &str, party: usize) -> Self {
        Self {
            url: url.to_string(),
            session: session.to_string(),
            party,
            client: reqwest::Client::new(),
        }
    }

    pub(crate) async fn join(&self) -> Result<(), HttpChannelError> {
        let url = format!("{}/join/{}/{}", self.url, self.session, self.party);
        self.client.put(&url).send().await?;
        Ok(())
    }

    pub(crate) async fn participants(&self) -> Result<usize, HttpChannelError> {
        let url = format!("{}/participants/{}", self.url, self.session);
        let participants = self
            .client
            .get(&url)
            .send()
            .await?
            .json::<Vec<u32>>()
            .await?;
        Ok(participants.len())
    }
}

impl Channel for PollingHttpChannel {
    type SendError = HttpChannelError;
    type RecvError = HttpChannelError;

    async fn send_bytes_to(
        &self,
        p: usize,
        msg: Vec<u8>,
        _info: SendInfo,
    ) -> Result<(), HttpChannelError> {
        let url = format!("{}/send/{}/{}/{}", self.url, self.session, self.party, p);
        let resp: reqwest::Response = self.client.post(url).body(msg).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(HttpChannelError::UnexpectedStatusCode(resp.status()))
        }
    }

    async fn recv_bytes_from(
        &mut self,
        p: usize,
        _info: RecvInfo,
    ) -> Result<Vec<u8>, HttpChannelError> {
        let url = format!("{}/recv/{}/{}/{}", self.url, self.session, p, self.party);
        let mut attempts = 0;
        loop {
            let resp = self.client.post(&url).send().await?;
            if resp.status() == StatusCode::BAD_REQUEST {
                attempts += 1;
                if attempts >= 10 {
                    return Err(HttpChannelError::Timeout);
                }
                sleep(Duration::from_millis(200)).await;
                continue;
            }
            if !resp.status().is_success() {
                return Err(HttpChannelError::UnexpectedStatusCode(resp.status()));
            }
            let bytes: Vec<u8> = resp.bytes().await?.into();
            return Ok(bytes);
        }
    }
}
