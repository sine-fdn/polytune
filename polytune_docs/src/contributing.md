# Contributing

While Polytune was developed by us at the [SINE Foundation](https://sine.foundation/), we would love to see how you end up using Polytune and are happy to accept pull requests. Polytune is distributed under the MIT license and hosted on GitHub:

[![Github](github-mark.png "Contribute on Github")](https://github.com/sine-fdn/polytune)

The Polytune MPC Engine implements a complex protocol [[WRK17]](https://eprint.iacr.org/2017/189.pdf) with many steps. The different steps and their modules are as follows:

1. [`ot.rs`](https://github.com/sine-fdn/polytune/blob/main/src/ot.rs) implements a maliciously secure correlated OT receiver and sender based on (a modified version of) the KOS OT implementation of [swanky](https://github.com/GaloisInc/swanky/tree/dev/ocelot).
2. [`fpre.rs`](https://github.com/sine-fdn/polytune/blob/main/src/fpre.rs) implements the preprocessing phase with an additional party, the trusted dealer, who distributes the correlated randomness used in the MPC protocol. Note that this requires a different trust assumption and should only be used with caution.
3. [`faand.rs`](https://github.com/sine-fdn/polytune/blob/main/src/faand.rs) implements the preprocessing phase of the [[WRK17]](https://eprint.iacr.org/2017/189.pdf) protocol in a distributed manner. This means that the parties interactively generate random authenticated triples in a maliciously secure protocol in `faand::faand`, which is then used in the MPC protocol. For transforming random authenticated triples to concrete authenticated triples, [Beaver's method](https://securecomputation.org/docs/pragmaticmpc.pdf#section.3.4) is implemented in `faand::beaver_aand`.
4. [`protocol.rs`](https://github.com/sine-fdn/polytune/blob/main/src/protocol.rs) implements MPC protocol. Its online phase is implemented using the garbling method implemented in [`garble.rs`](https://github.com/sine-fdn/polytune/blob/main/src/garble.rs).

You can also reach us at [polytune@sine.foundation](mailto:polytune@sine.foundation).
