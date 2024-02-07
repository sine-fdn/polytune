#!/bin/bash
cargo build
exec 3< <(cargo run -- pre -p 2 2>/dev/null | head -n 5 | tail -n 1)
read <&3 JOIN
echo $JOIN
eval $JOIN --program .add.garble.rs --party 0 --input 1u32
eval $JOIN --program .add.garble.rs --party=1 --input 2u32
