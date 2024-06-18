//! MPC Engine based on the paper
//! [Authenticated Garbling and Efficient Maliciously Secure Two-Party Computation](https://acmccs.github.io/papers/p21-wangA.pdf).
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub use garble_lang;

pub mod channel;
pub mod faand;
pub mod fpre;
pub mod protocol;

mod garble;

mod otext;