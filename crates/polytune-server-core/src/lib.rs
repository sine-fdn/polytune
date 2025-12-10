//! The core library to implement a Polytune service.
//!
//! This library implements a state machine and asynchronous actor for the evaluation of
//! a Garble program among multiple parties using Polytune. The core type is the [`PolicyState`]
//! which is communicated with using a [`PolicyStateHandle`].
//!
//! # Example of using the server core
//!
//! To actually use the state machine implemented by [`PolicyState`] you need to supply a
//! [`PolicyClientBuilder`] which can create a [`PolicyClient`] for the participants
//! specified in a [`Policy`]. The example below shows the different parts of the server-core
//! crate and how they fit together. For a concrete implementation of a policy client, refer to
//! the implementation of the [Polytune HTTP Server].
//!
//! [Polytune HTTP Server]: https://github.com/sine-fdn/polytune/tree/main/crates/polytune-http-server
//!
//! ```no_run
//! # #[tokio::main]
//! # async fn main() {
//! # use polytune_server_core::*;
//! # use std::collections::HashMap;
//! # use std::sync::Arc;
//! # use tokio::sync::Semaphore;
//! # use tracing::debug;
//! # use url::Url;
//! # use uuid::Uuid;
//!
//! // The actual implementations would have some state, like an HTTP client.
//! struct ClientBuilder;
//! struct Client;
//!
//! // Create a Client for the participants specified in the Policy.
//! // This could e.g. clone an HTTP Client with existing configuration.
//! impl PolicyClientBuilder for ClientBuilder {
//!     type Client = Client;
//!
//!     fn new_client(&self, policy: &Policy) -> Self::Client {
//!         Client
//!     }
//! }
//!
//! // The PolicyClient implementation is effectively a remote procedure call (RPC) client
//! // implementation. The validate, run, consts and msg methods correspond to calls
//! // of `handle.<method>()`` on the remote party `to`. See the documentation of the
//! // PolicyStateHandle for details.
//! # #[rustfmt::skip]
//! impl PolicyClient for Client {
//!     type Error = std::convert::Infallible;
//!         
//!     async fn validate( &self, to: usize, req: ValidateRequest) -> Result<(), Self::Error> { todo!() }
//!         
//!     async fn run(&self, to: usize, req: RunRequest) -> Result<(), Self::Error> { todo!() }
//!         
//!     async fn consts(&self, to: usize, req: ConstsRequest, ) -> Result<(), Self::Error> { todo!() }
//!         
//!     async fn msg(&self, to: usize, msg: MpcMsg) -> Result<(), Self::Error> { todo!() }
//!         
//!     async fn output(&self, to: url::Url, result: Result<garble_lang::literal::Literal, OutputError>)
//!         -> Result<(), Self::Error> { todo!() }
//! }
//!
//! // This limits the number of concurrent policies that are evaluated as a leader.
//! let concurrency = Arc::new(Semaphore::new(4));
//! // Create a new PolicyState with this client builder and shared sempahore to control the concurrency
//! let (policy_state, handle) = PolicyState::new(ClientBuilder, concurrency);
//! // Start the policy state machine on tokio task
//! tokio::spawn(async {
//!     policy_state.start().await;
//!     debug!("Policy state machine has stopped")
//! });
//!
//! let computation_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
//!
//! // The handle can now be used to control the running policy state machine
//! handle
//!     .schedule(Policy {
//!         computation_id,
//!         participants: vec![
//!             Url::parse("http://localhost:8000").unwrap(),
//!             Url::parse("http://localhost:8001").unwrap(),
//!         ],
//!         program: "pub fn main(a: u8, b: u8) -> u8 { a + b }".to_string(),
//!         leader: 0,
//!         party: 0,
//!         input: garble_lang::literal::Literal::from(3_u8),
//!         output: Some(Url::parse("http://localhost:8100/output/").unwrap()),
//!         constants: HashMap::new(),
//!     })
//!     .await
//!     .unwrap();
//!
//! // messages such as the ValidateRequest need to be sent by the PolicyClient implementation
//! // to the correct party and then the corresponding handle method needs to be called.
//! handle
//!     .validate(ValidateRequest {
//!         computation_id,
//!         program_hash: "blake3-hash-of-program".to_string(),
//!         leader: 0,
//!     })
//!     .await
//!     .unwrap();
//! }
//! ```

mod client;
mod handle;
mod policy;
mod state;

pub use client::{PolicyClient, PolicyClientBuilder};
pub use handle::{HandleError, PolicyStateHandle};
pub use policy::Policy;
pub use state::{
    Consts, ConstsError, ConstsRequest, MpcMsg, MpcMsgError, OutputError, PolicyState, RunError,
    RunRequest, ScheduleError, ValidateError, ValidateRequest,
};
