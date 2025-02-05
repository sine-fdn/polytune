use polytune::{
    channel::Channel,
    garble_lang::compile,
    protocol::{mpc, Preprocessor},
};
use reqwest::StatusCode;
use url::Url;

struct HttpChannel {
    url: Url,
    party: usize,
}

impl HttpChannel {
    async fn new(url: Url, party: usize) -> Result<Self, String> {
        Ok(Self { url, party })
    }
}

impl Channel for HttpChannel {
    type SendError = String;
    type RecvError = String;

    async fn send_bytes_to(
        &mut self,
        p: usize,
        _phase: &str,
        _i: usize,
        _remaining: usize,
        msg: Vec<u8>,
    ) -> Result<(), Self::SendError> {
        let client = reqwest::Client::new();
        let url = format!("{}send/{}/{}", self.url, self.party, p);
        for _ in 0..50 {
            let Ok(resp) = client.post(&url).body(msg.clone()).send().await else {
                println!("Could not reach party {p} at {url}...");
                continue;
            };
            match resp.status() {
                StatusCode::OK => return Ok(()),
                StatusCode::NOT_FOUND => {
                    println!("Could not reach party {p} at {url}...");
                }
                status => return Err(format!("Unexpected status code: {status}")),
            }
        }
        return Err(format!("Could not reach {url}"));
    }

    async fn recv_bytes_from(
        &mut self,
        p: usize,
        _phase: &str,
        _i: usize,
    ) -> Result<Vec<u8>, Self::RecvError> {
        let client = reqwest::Client::new();
        let url = format!("{}recv/{}/{}", self.url, self.party, p);
        for _ in 0..50 {
            let Ok(resp) = client.post(&url).send().await else {
                println!("Could not reach party {p} at {url}...");
                continue;
            };
            match resp.status() {
                StatusCode::OK => match resp.bytes().await {
                    Ok(bytes) => return Ok(bytes.into()),
                    Err(e) => return Err(format!("Expected body to be bytes, {e}")),
                },
                StatusCode::NOT_FOUND => {
                    println!("Could not reach party {p} at {url}...");
                }
                status => return Err(format!("Unexpected status code: {status}")),
            }
        }
        return Err(format!("Could not reach {url}"));
    }
}
