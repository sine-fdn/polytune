#!/bin/bash
errorhandler () {
    kill $(jobs -p)
}
trap errorhandler ERR EXIT
cargo run &
sleep 1
cargo run -- "http://127.0.0.1:8000" "test" 3 &
cargo run -- "http://127.0.0.1:8000" "test" 2 4 &
cargo run -- "http://127.0.0.1:8000" "test" 1 3 &
cargo run -- "http://127.0.0.1:8000" "test" 0 2
