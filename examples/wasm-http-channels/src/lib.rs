use std::str::FromStr;

use gloo_timers::future::TimeoutFuture;
use polytune::{
    channel::Channel,
    garble_lang::{compile, literal::Literal, token::SignedNumType},
    protocol::{mpc, Preprocessor},
};
use reqwest::StatusCode;
use url::Url;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn compute(url: String, party: usize, input: i32, range: u32) -> Result<String, String> {
    let url = Url::from_str(&url).map_err(|e| format!("Invalid URL {url}: {e}"))?;
    let code = include_str!("../.benchmark.garble.rs").replace(
        "let range_in_percent = 10;",
        &format!("let range_in_percent = {range};"),
    );
    let prg = compile(&code).map_err(|e| e.prettify(&code))?;
    let input_literal = Literal::NumSigned(input as i64, SignedNumType::I32);
    let input = prg
        .literal_arg(party, input_literal)
        .map_err(|e| format!("Invalid i32 input: {e}"))?
        .as_bits();
    let fpre = Preprocessor::Untrusted;
    let p_out = vec![0, 1, 2];
    let mut channel = HttpChannel::new(url, party).await?;
    let output = mpc(&mut channel, &prg.circuit, &input, fpre, 0, party, &p_out)
        .await
        .map_err(|e| format!("MPC computation failed: {e}"))?;
    let output = prg
        .parse_output(&output)
        .map_err(|e| format!("Invalid output bits: {e}"))?;
    Ok(output.to_string())
}

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
                TimeoutFuture::new(100).await;
                continue;
            };
            match resp.status() {
                StatusCode::OK => return Ok(()),
                status => eprintln!("Unexpected status code: {status}"),
            }
            TimeoutFuture::new(100).await;
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
                TimeoutFuture::new(100).await;
                continue;
            };
            match resp.status() {
                StatusCode::OK => match resp.bytes().await {
                    Ok(bytes) => return Ok(bytes.into()),
                    Err(e) => return Err(format!("Expected body to be bytes, {e}")),
                },
                status => eprintln!("Unexpected status code: {status}"),
            }
            TimeoutFuture::new(100).await;
        }
        return Err(format!("Could not reach {url}"));
    }
}
