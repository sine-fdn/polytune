# The Polytune MPC Engine

[Secure Multi-Party Computation (MPC)](https://sine.foundation/library/002-smpc) allows two or more parties to interactively perform a computation on their private inputs, without revealing any additional information about their inputs to each other, other than what the result of the computation reveals.

Our aim at SINE is to make advanced technology, such as MPC, available to as many companies as possible. We are especially keen to apply [MPC for the exchange of sustainability data](https://sine.foundation/library/sine-is-partnering-with-wbcsd-to-decarbonise-the-economy).

Polytune, our MPC engine, aims at fulfilling our vision by providing an easy-to-use framework to apply this technology wherever there is a need to share data privately, without a third-party trustee.

Polytune implements the multi-party [[WRK17b]](https://eprint.iacr.org/2017/189.pdf) protocol and will include optimizations from [[YWZ20]](https://eprint.iacr.org/2019/1104.pdf). This protocol achieves the highest level of security an MPC protocol can achieve, i.e., it is secure against malicious adversaries that can control up to all-but-one of the parties. This means that even if all but one of the parties are corrupt and together try to obtain information about the honest party's input while actively deviating from the protocol, they are unable to do so, i.e., the input of the honest party remains private.

> ⚠️ **Note**
> Our MPC engine is being actively developed, so expect breaking changes.

Polytune is directly compatible with [Garble](https://github.com/sine-fdn/garble-lang), our programming language that allows us to describe computations on a high level and translate them to a Boolean circuit format that is required by the [[WRK17b]](https://eprint.iacr.org/2017/189.pdf) MPC protocol.
Learn more about Garble: [Garble Documentation](https://garble-lang.org/).

You can see examples for the usage with examples described in Garble, e.g., [`benches/.join.garble.rs`](https://github.com/sine-fdn/polytune/blob/main/benches/.join.garble.rs) or in [`examples/sql-integration/.example.garble.rs`](https://github.com/sine-fdn/polytune/blob/main/examples/sql-integration/.example.garble.rs).

## Funded by

<p float="left">
  <img src="logos/BMBF_Logo.jpg" alt="With funding from the: Federal Ministry of Research, Technology and Space" height="200" />
  <img src="logos/EU_Logo.png" alt="Funded by the European Union (NextGenerationEU)" height="200" style="background: white" />
</p>
