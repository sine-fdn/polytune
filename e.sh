#!/bin/bash
# This script extracts to F*, fixes an issue arising from
# https://github.com/cryspen/hax/issues/1434 and subsequently attempts
# to typecheck F*

set -euo pipefail

rm -f proofs/fstar/extraction/Polytune.*
# rm -rf proofs/fstar/extraction/.cache
# rm -rf proofs/fstar/extraction/.depend 

./hax-driver.py extract-fstar
# sed -i 's/((ei_uij_k\.\[ j \] <: Alloc\.Vec\.t_Vec (bool & u128) Alloc\.Alloc\.t_Global)\.\[ ll \])/((ei_uij_k.[ j ] <: Alloc.Vec.t_Vec (bool \& u128) Alloc.Alloc.t_Global).[ ll ] <: (bool \& u128))/' ./proofs/fstar/extraction/Polytune.Faand.fst 
./hax-driver.py typecheck-fstar
