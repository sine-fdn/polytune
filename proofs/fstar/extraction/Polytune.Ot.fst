module Polytune.Ot
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Polytune.Channel in
  ()

assume
val kos_ot_sender':
    #iimpl_951670863_: Type0 ->
    {| i1: Polytune.Channel.t_Channel iimpl_951670863_ |} ->
    channel: iimpl_951670863_ ->
    delta: u128 ->
    lprime: usize ->
    p_to: usize ->
    shared_rand: Rand_chacha.Chacha.t_ChaCha20Rng
  -> (iimpl_951670863_ &
      Core.Result.t_Result
        (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global & Rand_chacha.Chacha.t_ChaCha20Rng)
        Polytune.Swankyot.t_Error)

let kos_ot_sender
      (#iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Polytune.Channel.t_Channel iimpl_951670863_)
     = kos_ot_sender' #iimpl_951670863_ #i1

assume
val kos_ot_receiver':
    #iimpl_951670863_: Type0 ->
    {| i1: Polytune.Channel.t_Channel iimpl_951670863_ |} ->
    channel: iimpl_951670863_ ->
    bs: t_Slice bool ->
    p_to: usize ->
    shared_rand: Rand_chacha.Chacha.t_ChaCha20Rng
  -> (iimpl_951670863_ &
      Core.Result.t_Result
        (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global & Rand_chacha.Chacha.t_ChaCha20Rng)
        Polytune.Swankyot.t_Error)

let kos_ot_receiver
      (#iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Polytune.Channel.t_Channel iimpl_951670863_)
     = kos_ot_receiver' #iimpl_951670863_ #i1
