//! A Rust implementation of secure multi-party computation (MPC) based on the paper [Global-Scale
//! Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
//!
//! This crate provides tools and protocols for performing secure computations across multiple
//! parties without revealing private inputs to other participants. The implementation uses garbled
//! circuits and other cryptographic primitives to ensure security.
//!
//! ## Features
//!
//! - Garbled circuit-based secure multi-party computation
//! - Support for both trusted dealer and untrusted preprocessing
//! - Efficient communication channels for distributed computation
//! - Boolean circuit evaluation with privacy guarantees
//!
//! ## Main Components
//!
//! The crate is structured into several modules:
//!
//! * [`protocol`]: The [`protocol::mpc`] function which executes the protocol for a single party.
//! * [`channel`]: Communication abstractions for exchanging data between parties.
//!
//! ## Basic Usage
//!
//! To run an MPC computation, each participating party needs to:
//!
//! 1. Set up communication channels with other parties
//! 2. Create or load a circuit definition
//! 3. Prepare private inputs
//! 4. Call the [`protocol::mpc`] function with appropriate parameters
//! 5. Process the resulting outputs
//!
//! For simulated environments (testing/development), you can use the [`protocol::simulate_mpc`]
//! function.
//!
//! ## Example
//!
//! ```ignore
//! use polytune::{
//!     channel::SimpleChannel,
//!     garble_lang::circuit::Circuit,
//!     protocol::mpc,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Set up a simple channel for communication
//! let mut channel = /* ... */
//!
//! // Load or define a circuit
//! let circuit = /* ... */
//!
//! // Define party roles and inputs
//! let my_inputs = vec![true, false, true];
//! let p_eval = 0; // Party 0 is the evaluator
//! let p_own = 1;  // This code is running as party 1
//! let p_out = vec![0, 1]; // Parties 0 and 1 receive the output
//!
//! // Execute the MPC protocol
//! let result = mpc(
//!     &mut channel,
//!     &circuit,
//!     &my_inputs,
//!     p_eval,
//!     p_own,
//!     &p_out,
//! ).await?;
//!
//! println!("Computation result: {:?}", result);
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Properties
//!
//! This implementation provides security against malicious adversaries. The protocol ensures that
//! no party learns anything beyond what can be inferred from their own inputs and the output of the
//! computation.
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub use garble_lang;

pub mod channel;
pub mod protocol;

mod data_types;
mod faand;
mod fpre;
mod garble;
mod ot;
mod swankyot;
