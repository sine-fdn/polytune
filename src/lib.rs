//! MPC Engine based on the paper
//! [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub use garble_lang;

pub mod channel;
pub mod fpre;
pub mod protocol;

mod data_types;
mod faand;
mod garble;
mod ot;
mod swankyot;
