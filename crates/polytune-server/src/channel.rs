use anyhow::{Context, anyhow};
use futures::future::try_join_all;
use polytune::channel::Channel;
use reqwest::StatusCode;
use std::{result::Result, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, Notify, mpsc::Receiver},
    time::sleep,
};
use tracing::{error, info};
use url::Url;

pub struct HttpChannel {
    pub client: reqwest::Client,
    pub urls: Vec<Url>,
    pub party: usize,
    pub recv: Vec<Mutex<Receiver<Vec<u8>>>>,
    pub sync_received: Arc<Notify>,
    pub sync_requested: Arc<Notify>,
}

impl HttpChannel {
    pub async fn barrier(&self) -> anyhow::Result<()> {
        if self.party == 0 {
            try_join_all(
                self.urls[1..]
                    .iter()
                    .map(|url| self.client.post(&format!("{url}sync")).send()),
            )
            .await
            .context("Sync error")?;
        } else {
            self.sync_requested.notify_one();
            self.sync_received.notified().await;
        }

        Ok(())
    }
}

impl Channel for HttpChannel {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    async fn send_bytes_to(
        &self,
        p: usize,
        msg: Vec<u8>,
        phase: &str,
    ) -> Result<(), Self::SendError> {
        let url = format!("{}msg/{}", self.urls[p], self.party);
        let mb = msg.len() as f64 / 1024.0 / 1024.0;
        info!("Sending msg {phase} to party {p} ({mb:.2}MB)...");
        let mut retries = 0;
        loop {
            let res = self.client.post(&url).body(msg.clone()).send().await?;
            match res.status() {
                StatusCode::OK => break Ok(()),
                // retry for 10 minutes
                StatusCode::NOT_FOUND if retries < 10 * 60 => {
                    retries += 1;
                    error!("Could not reach party {p} at {url}...");
                    sleep(Duration::from_millis(1000)).await;
                }
                status => {
                    error!("Unexpected status code: {status}");
                    anyhow::bail!("Unexpected status code: {status}")
                }
            }
        }
    }

    async fn recv_bytes_from(&self, p: usize, _phase: &str) -> Result<Vec<u8>, Self::RecvError> {
        let mut r = self.recv[p].lock().await;
        r.recv()
            .await
            .ok_or_else(|| anyhow!("Expected a message, but received `None`!"))
    }
}
