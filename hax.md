# Extracting and typechecking with `hax`

The file `hax-driver.py` can be used as a shorthand to invoke the
right commands for hax extraction to F* and F* typechecking.

To be able to use it, make sure the following environment variables
are set correctly:
- `FSTAR_HOME`: path to your [F* installation](https://github.com/FStarLang/FStar)
- `HACL_HOME`: path to the local copy of the [HACL* repository](https://github.com/hacl-star/hacl-star)
- `HAX_HOME`: path to the local copy to the [hax repository](https://github.com/cryspen/hax)

To run the extraction to F* , use `hax-driver.py extract-fstar`.

To attempt F* typechecking of the resulting extraction, use
`hax-driver.py typecheck-fstar`.

Currently, it extracts the following functions to F*:
- `polytune::faand::combine_two_leaky_ands`

## External dependencies
Since the hax proof library for F* does not contain models for
arbitrary Rust crates, we need to maintain local models for critical
dependencies. We chose the directory `polytune/proofs/fstar/dependencies` for
such models.

One way to obtain these models, besides writing them entirely from
scratch, is to run `cargo hax -i '-** +:**'` on a local copy of the
dependency. This will create a interface-only extraction of the
dependency's items in `<path-to-dependency>/proofs/fstar/extraction`,
which can then be copied over to
`polytune/proofs/fstar/dependencies`. The invocation of `cargo hax` on
the dependency can be made to extract interfaces for specific parts
only via a different argument to `-i`, see [the hax
manual](https://hax.cryspen.com/manual/faq/include-flags.html).
