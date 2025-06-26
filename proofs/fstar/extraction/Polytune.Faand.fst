module Polytune.Faand
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Polytune.Data_types in
  ()

assume
val lsb_of_hash__lsb_of_hash_inner': input: u128 -> bool

unfold
let lsb_of_hash__lsb_of_hash_inner = lsb_of_hash__lsb_of_hash_inner'

let lsb_of_hash
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Convert.t_Into v_T u128)
      (input: v_T)
    : bool =
  lsb_of_hash__lsb_of_hash_inner (Core.Convert.f_into #v_T
        #u128
        #FStar.Tactics.Typeclasses.solve
        input
      <:
      u128)

let compute_hash_pointwise
      (delta: Polytune.Data_types.t_Delta)
      (y_i: bool)
      (key_xj: Polytune.Data_types.t_Key)
      (s_j: bool)
    : (bool & bool) =
  let mac_xj_0_:Polytune.Data_types.t_Key = key_xj in
  let mac_xj_1_:Polytune.Data_types.t_Mac =
    Core.Ops.Bit.f_bitxor #Polytune.Data_types.t_Key
      #Polytune.Data_types.t_Delta
      #FStar.Tactics.Typeclasses.solve
      key_xj
      delta
  in
  Core.Ops.Bit.f_bitxor (lsb_of_hash #Polytune.Data_types.t_Key mac_xj_0_ <: bool) s_j,
  Core.Ops.Bit.f_bitxor (Core.Ops.Bit.f_bitxor (lsb_of_hash #Polytune.Data_types.t_Mac mac_xj_1_
          <:
          bool)
        s_j
      <:
      bool)
    y_i
  <:
  (bool & bool)

let compute_t_pointwise (x_i: bool) (mac_by_j: Polytune.Data_types.t_Mac) (h0h1_j: (bool & bool))
    : bool =
  if x_i
  then Core.Ops.Bit.f_bitxor h0h1_j._2 (lsb_of_hash #Polytune.Data_types.t_Mac mac_by_j <: bool)
  else Core.Ops.Bit.f_bitxor h0h1_j._1 (lsb_of_hash #Polytune.Data_types.t_Mac mac_by_j <: bool)

let lemma_compute_ts_pointwise
      (i j: usize)
      (share_at_i share_at_j: Polytune.Data_types.t_Share)
      (delta_j: Polytune.Data_types.t_Delta)
      (s_j y_j: bool)
    : Lemma
        (requires (
             (Alloc.Vec.impl_1__len (Polytune.Data_types.impl_Auth__macs share_at_i._1) >. j)
           /\ (Alloc.Vec.impl_1__len (Polytune.Data_types.impl_Auth__keys share_at_j._1) >. i)
          ))
    (ensures
      (let x_i:bool = Polytune.Data_types.impl_Share__bit share_at_i in
        let hashes:(bool & bool) =
          compute_hash_pointwise delta_j
            y_j
            (Polytune.Data_types.key_for share_at_j i <: Polytune.Data_types.t_Key)
            s_j
        in
        let t:bool =
          compute_t_pointwise x_i
            (Polytune.Data_types.mac_by share_at_i j <: Polytune.Data_types.t_Mac)
            hashes
        in
        if x_i then t =. (Core.Ops.Bit.f_bitxor y_j s_j <: bool) else t =. s_j)) =
  let _:Prims.unit = Polytune.Faand.Spec.share_is_authenticated share_at_i share_at_j i j delta_j in
  ()
