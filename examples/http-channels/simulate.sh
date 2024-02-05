#!/bin/bash
errorhandler () {
    kill $(jobs -p) 2>/dev/null
}
trap errorhandler ERR EXIT
cargo build
cargo run -- serve &
sleep 1
cargo run -- pre "http://127.0.0.1:8000" --session="test" --parties=3 &
cargo run -- party "http://127.0.0.1:8000" --session="test" --program=".add.garble.rs" --party=2 --input="4u32" &
cargo run -- party "http://127.0.0.1:8000" --session="test" --program=".add.garble.rs" --party=1 --input="3u32" &
MPC=$(cargo run -- party "http://127.0.0.1:8000" --session="test" --program=".add.garble.rs" --party=0 --input="2u32")
ACTUAL=$(echo $MPC | tail -n 1)
EXPECT="The result is 9u32"
echo "Expect: $EXPECT"
echo "Actual: $ACTUAL"
[ "$ACTUAL" = "$EXPECT" ]
