#!/bin/sh

set -ex

wasm-pack build --target web
python3 -m http.server 9000 --bind 127.0.0.1
