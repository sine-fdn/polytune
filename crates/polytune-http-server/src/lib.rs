//! An HTTP-based Polytune server.
//!
//! This crate implements an HTTP-based server atop the [`polytune_server_core`] crate.
use std::fmt::Write;

mod api;
mod policy_client;
mod router;
mod server;

pub use policy_client::MpcResult;
pub use server::{JwtConf, Server, ServerOpts};

fn serialize_error_chain<S>(
    err: &(dyn std::error::Error + 'static),
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format_error_chain(err))
}

fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut chain = anyhow::Chain::new(err).peekable();
    let mut f = String::new();
    if let Some(err) = chain.next() {
        let _ = writeln!(&mut f, "Error: {}", err);
    }
    if chain.peek().is_some() {
        let _ = writeln!(&mut f, "\nCaused by:");
    }
    for err in chain {
        let _ = writeln!(&mut f, "\t{}", err);
    }
    f
}
