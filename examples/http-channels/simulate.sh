#!/bin/bash
errorhandler () {
    kill $(jobs -p) 2>/dev/null
}
trap errorhandler ERR EXIT
cargo run -- serve &
sleep 1
cargo run -- pre "http://127.0.0.1:8000" --session="test" --parties=3 &
cargo run -- party "http://127.0.0.1:8000" --session="test" --party=2 --input=4 &
cargo run -- party "http://127.0.0.1:8000" --session="test" --party=1 --input=3 &
cargo run -- party "http://127.0.0.1:8000" --session="test" --party=0 --input=2
