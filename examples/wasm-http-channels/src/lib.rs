use std::str::FromStr;

use gloo_timers::future::TimeoutFuture;
use polytune::{
    channel::Channel,
    garble_lang::{
        CircuitKind, CompileOptions, compile_with_options, literal::Literal, token::SignedNumType,
    },
    mpc,
};
use reqwest::StatusCode;
use url::Url;
use wasm_bindgen::prelude::*;
use web_sys::console;

/// Routes `tracing` events to the browser/Node console instead of the
/// unavailable `stdout`/`stderr`. Runs once, automatically, when the wasm
/// module is instantiated.
///
/// Only this crate's own events are shown at `debug`; `polytune`'s internal
/// protocol tracing is left at its default (`warn`) since it fires far too
/// often to render through the wasm/JS console boundary without making the
/// computation itself dramatically slower.
#[wasm_bindgen(start)]
fn init_tracing() {
    use tracing_subscriber::{filter::Targets, prelude::*};

    let filter = Targets::new()
        .with_target("polytune_wasm_http_channels", tracing::Level::DEBUG)
        .with_default(tracing::Level::WARN);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .without_time()
        .with_writer(tracing_web::MakeWebConsoleWriter::new())
        .with_filter(filter);

    let _ = tracing_subscriber::registry().with(fmt_layer).try_init();
}

#[wasm_bindgen]
pub async fn compute(url: String, party: usize, input: i32, range: u32) -> Result<JsValue, String> {
    let url = Url::from_str(&url).map_err(|e| format!("Invalid URL {url}: {e}"))?;
    let code = include_str!("../.benchmark.garble.rs").replace(
        "let range_in_percent = 10;",
        &format!("let range_in_percent = {range};"),
    );
    let prg = compile_with_options(
        &code,
        CompileOptions {
            circuit_kind: CircuitKind::Register,
            ..Default::default()
        },
    )
    .map_err(|e| e.prettify(&code))?;
    let circuit = prg.circuit.unwrap_register_ref();
    let gates = format!(
        "Trying to execute circuit with {:.2}M instructions  ({:.2}M AND ops)",
        circuit.insts.len() as f64 / 1000.0 / 1000.0,
        circuit.and_ops as f64 / 1000.0 / 1000.0
    );
    console::log_1(&gates.into());
    let input_literal = Literal::NumSigned(input as i64, SignedNumType::I32);
    let input = prg
        .literal_arg(party, input_literal)
        .map_err(|e| format!("Invalid i32 input: {e}"))?
        .as_bits();
    let p_out = vec![0, 1, 2];
    let channel = HttpChannel::new(url, party).await?;
    let output = mpc(&channel, &circuit, &input, 0, party, &p_out, None)
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
        phase: &str,
    ) -> Result<(), Self::SendError> {
        let client = reqwest::Client::new();
        let url = format!("{}send/{}/{}", self.url, self.party, p);
        for _ in 0..50 {
            let Ok(resp) = client.post(&url).body(msg.clone()).send().await else {
                tracing::warn!("Could not reach party {p} at {url} during {phase}, retrying...");
                TimeoutFuture::new(100).await;
                continue;
            };
            match resp.status() {
                StatusCode::OK => return Ok(()),
                status => {
                    tracing::debug!(
                        "Broker returned unexpected status {status} for {url} during {phase}, retrying..."
                    )
                }
            }
            TimeoutFuture::new(100).await;
        }
        return Err(format!("Could not reach {url}"));
    }

    async fn recv_bytes_from(&self, p: usize, phase: &str) -> Result<Vec<u8>, Self::RecvError> {
        let client = reqwest::Client::new();
        let url = format!("{}recv/{}/{}", self.url, self.party, p);
        for _ in 0..50 {
            let Ok(resp) = client.post(&url).send().await else {
                tracing::warn!("Could not reach party {p} at {url} during {phase}, retrying...");
                TimeoutFuture::new(100).await;
                continue;
            };
            match resp.status() {
                StatusCode::OK => match resp.bytes().await {
                    Ok(bytes) => return Ok(bytes.into()),
                    Err(e) => return Err(format!("Expected body to be bytes, {e}")),
                },
                status => {
                    tracing::debug!(
                        "Broker returned unexpected status {status} for {url} during {phase}, retrying..."
                    )
                }
            }
            TimeoutFuture::new(100).await;
        }
        return Err(format!("Could not reach {url}"));
    }
}
