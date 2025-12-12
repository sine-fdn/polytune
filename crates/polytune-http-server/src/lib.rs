#![allow(rustdoc::private_intra_doc_links)]
//! An HTTP-based Polytune server.
//!
//! This crate implements an HTTP-based server atop the [`polytune_server_core`] crate.
//! It provides a concrete implementation of the [`PolicyClient`] trait which acts as
//! an RPC client and an axum HTTP server which translates the HTTP requests of the
//! [`HttpClient`] into method calls on the corresponding [`PolicyStateHandle`] of the
//! executing policy state machine.
//!
//! The [`HttpClient`] implementing the [`PolicyClient`] is passed to the [`PolicyState`]
//! state machine. The state machine will call the various methods on the [`HttpClient`] to
//! coordinate and communicate with the other parties. The [`HttpClient`] issues HTTP requests
//! to the other parties [`api`] implementation. The HTTP routes will resolve to [`PolicyStateHandle`]
//! method calls on the remote [`PolicyState`] state machine. These will be handled by the
//! executing state machine, with a response potentially returned via the handle, as the response of
//! the API route, back to the original [`PolicyClient`].
//!
//! # CAUTION: Authentication
//!
//! Currently, the Polytune HTTP server does not perform authentication of the communication
//! between the parties. If you want to deploy Polytune in an environment where untrusted
//! requests can be sent to the server, you need to implement your own server atop the server-core,
//! or proxy the communication between Polytune using something like mTLS for mutual authentication.
//! To authenticate Polytune to a proxy, you can provide an ECDSA key in PKCS#8 as the `--jwt-key`
//! argument. Polytune will attach a JWT signed with this key to every outgoing request.
//!
//! [`PolicyClient`]: polytune_server_core::PolicyClient
//! [`PolicyStateHandle`]: polytune_server_core::PolicyStateHandle
//! [`HttpClient`]: crate::policy_client::HttpClient
//! [`PolicyState`]: polytune_server_core::PolicyState
use std::fmt::Write;

mod api;
mod policy_client;
mod router;
mod server;

pub use policy_client::MpcResult;
pub use server::{Cancel, JwtConf, Server, ServerOpts};

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
