use std::str::FromStr;

use gloo_timers::future::TimeoutFuture;
use polytune::{
    channel::{Channel, RecvInfo, SendInfo},
    garble_lang::{compile, literal::Literal, token::SignedNumType},
    mpc,
};
use reqwest::StatusCode;
use url::Url;
use wasm_bindgen::prelude::*;
use web_sys::console;

#[wasm_bindgen]
pub async fn compute(url: String, party: usize, input: i32, range: u32) -> Result<JsValue, String> {
    let url = Url::from_str(&url).map_err(|e| format!("Invalid URL {url}: {e}"))?;
    let code = include_str!("../.benchmark.garble.rs").replace(
        "let range_in_percent = 10;",
        &format!("let range_in_percent = {range};"),
    );
    let prg = compile(&code).map_err(|e| e.prettify(&code))?;
    console::log_1(&prg.circuit.report_gates().into());
    let input_literal = Literal::NumSigned(input as i64, SignedNumType::I32);
    let input = prg
        .literal_arg(party, input_literal)
        .map_err(|e| format!("Invalid i32 input: {e}"))?
        .as_bits();
    let p_out = vec![0, 1, 2];
    let channel = HttpChannel::new(url, party).await?;
    let output = mpc(&channel, &prg.circuit, &input, 0, party, &p_out)
        .await
        .map_err(|e| format!("MPC computation failed: {e}"))?;
    let output = prg
        .parse_output(&output)
        .map_err(|e| format!("Invalid output bits: {e}"))?;
    match output {
        Literal::Array(elems) if elems.len() == 3 => Ok(elems
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .into()),
        output => Err(format!(
            "Expected an array of buckets as output, but found {output}"
        )),
    }
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
        &self,
        p: usize,
        msg: Vec<u8>,
        _info: SendInfo,
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

    async fn recv_bytes_from(&self, p: usize, _info: RecvInfo) -> Result<Vec<u8>, Self::RecvError> {
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
