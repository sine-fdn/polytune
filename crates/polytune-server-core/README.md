# Polytune Server Core

This crate implements a state machine and actor for the evaluation of a [Garble] program using Polytune. It implements core datatypes like the [`Policy`] for specifying computations and the coordination of multiple Polytune instances in a transport agnostic way.

It implements a state machine that is spawned on a [tokio] task and controlled using a `PolicyHandle`. A user of the core library must supply an implementation of a `PolicyClient` which implements the necessary remote procedure calls. For a full-fledged implementation of a Polytune server based on HTTP communication, please look at the [Polytune HTTP server] crate.



[Garble]: https://garble-lang.org/
[`Policy`]: ./src/policy.rs
[tokio]: https://docs.rs/tokio/
[Polytune HTTP server]: ../polytune-http-server/
