#!/bin/sh

set -ex

# See https://docs.rs/getrandom/0.3.3/getrandom/#webassembly-support
export RUSTFLAGS='--cfg getrandom_backend="wasm_js"'

wasm-pack build --target web
python3 -m http.server 9000 --bind 127.0.0.1
