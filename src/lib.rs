//! S-MPC Engine based on the paper
//! [Authenticated Garbling and Efficient Maliciously Secure Two-Party Computation](https://acmccs.github.io/papers/p21-wangA.pdf)
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod channel;
pub mod circuit;
pub mod protocol;

mod fpre;
mod hash;
