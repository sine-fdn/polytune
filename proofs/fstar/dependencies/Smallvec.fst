module Smallvec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

assume
val t_SmallVec': v_T: Type0 -> v_N: usize -> eqtype

let t_SmallVec (v_T: Type0) (v_N: usize) = t_SmallVec' v_T v_N
