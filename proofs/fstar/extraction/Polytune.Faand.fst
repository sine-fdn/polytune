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

let fhaand_compute_vi (i n: usize) (s ts: t_Slice bool)
    : Prims.Pure bool
      (requires
        b2t ((Core.Slice.impl__len #bool ts <: usize) =. n <: bool) /\
        b2t ((Core.Slice.impl__len #bool s <: usize) =. n <: bool))
      (fun _ -> Prims.l_True) =
  let vi:bool = false in
  Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
    n
    (fun vi temp_1_ ->
        let vi:bool = vi in
        let _:usize = temp_1_ in
        true)
    vi
    (fun vi j ->
        let vi:bool = vi in
        let j:usize = j in
        if j =. i <: bool
        then vi
        else
          Core.Ops.Bit.f_bitxor (Core.Ops.Bit.f_bitxor vi (ts.[ j ] <: bool) <: bool)
            (s.[ j ] <: bool)
          <:
          bool)

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

let fhaand_compute_hashes
      (delta: Polytune.Data_types.t_Delta)
      (i n: usize)
      (xshare: Polytune.Data_types.t_Share)
      (yi: bool)
      (randomness: t_Slice bool)
    : Prims.Pure (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
      (requires
        b2t
        ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Key
              #Alloc.Alloc.t_Global
              (Polytune.Data_types.impl_Auth__keys xshare.Polytune.Data_types._1
                <:
                Alloc.Vec.t_Vec Polytune.Data_types.t_Key Alloc.Alloc.t_Global)
            <:
            usize) >=.
          n
          <:
          bool) /\ b2t ((Core.Slice.impl__len #bool randomness <: usize) >=. n <: bool))
      (ensures
        fun result ->
          let result:Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global = result in
          b2t
          ((Alloc.Vec.impl_1__len #(bool & bool) #Alloc.Alloc.t_Global result <: usize) =. n <: bool
          )) =
  let h0h1:Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #(bool & bool) (false, false <: (bool & bool)) n
  in
  Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
    n
    (fun h0h1 temp_1_ ->
        let h0h1:Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global = h0h1 in
        let _:usize = temp_1_ in
        b2t
        ((Alloc.Vec.impl_1__len #(bool & bool) #Alloc.Alloc.t_Global h0h1 <: usize) =. n <: bool))
    h0h1
    (fun h0h1 j ->
        let h0h1:Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global = h0h1 in
        let j:usize = j in
        if j =. i <: bool
        then h0h1
        else
          let key_xj:Polytune.Data_types.t_Key = Polytune.Data_types.key_for xshare j in
          let s_j:bool = randomness.[ j ] in
          let h0, h1:(bool & bool) = compute_hash_pointwise delta yi key_xj s_j in
          let h0h1:Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global =
            Rust_primitives.Hax.Monomorphized_update_at.update_at_usize h0h1
              j
              ({ (h0h1.[ j ] <: (bool & bool)) with _1 = h0 } <: (bool & bool))
          in
          Rust_primitives.Hax.Monomorphized_update_at.update_at_usize h0h1
            j
            ({ (h0h1.[ j ] <: (bool & bool)) with _2 = h1 } <: (bool & bool)))

let compute_t_pointwise (x_i: bool) (mac_by_j: Polytune.Data_types.t_Mac) (h0h1_j: (bool & bool))
    : bool =
  if x_i
  then Core.Ops.Bit.f_bitxor h0h1_j._2 (lsb_of_hash #Polytune.Data_types.t_Mac mac_by_j <: bool)
  else Core.Ops.Bit.f_bitxor h0h1_j._1 (lsb_of_hash #Polytune.Data_types.t_Mac mac_by_j <: bool)

let fhaand_compute_ts
      (i n: usize)
      (xshare: Polytune.Data_types.t_Share)
      (h0h1_j: t_Slice (bool & bool))
    : Prims.Pure (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
      (requires
        b2t
        ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Mac
              #Alloc.Alloc.t_Global
              (Polytune.Data_types.impl_Share__macs xshare
                <:
                Alloc.Vec.t_Vec Polytune.Data_types.t_Mac Alloc.Alloc.t_Global)
            <:
            usize) >=.
          n
          <:
          bool) /\ b2t ((Core.Slice.impl__len #(bool & bool) h0h1_j <: usize) >=. n <: bool))
      (fun _ -> Prims.l_True) =
  let ts:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = Alloc.Vec.from_elem #bool false n in
  Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
    n
    (fun ts temp_1_ ->
        let ts:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = ts in
        let _:usize = temp_1_ in
        b2t ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global ts <: usize) =. n <: bool))
    ts
    (fun ts j ->
        let ts:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = ts in
        let j:usize = j in
        if j =. i <: bool
        then ts
        else
          let mac_by_j:Polytune.Data_types.t_Mac = Polytune.Data_types.mac_by xshare j in
          Rust_primitives.Hax.Monomorphized_update_at.update_at_usize ts
            j
            (compute_t_pointwise (Polytune.Data_types.impl_Share__bit xshare <: bool)
                mac_by_j
                (h0h1_j.[ j ] <: (bool & bool))
              <:
              bool))

let lemma_compute_ts_pointwise
      (i j: usize)
      (share_at_i share_at_j: Polytune.Data_types.t_Share)
      (delta_j: Polytune.Data_types.t_Delta)
      (s_j y_j: bool)
    : Lemma
    (requires (
      (Alloc.Vec.impl_1__len (Polytune.Data_types.impl_Auth__macs share_at_i._1) >. j)
        /\ (Alloc.Vec.impl_1__len (Polytune.Data_types.impl_Auth__keys share_at_j._1) >. i)))
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
        if x_i then t =. (Core.Ops.Bit.f_bitxor y_j s_j <: bool) else t =. s_j))
        = Polytune.Faand.Spec.share_is_authenticated share_at_i share_at_j i j delta_j;
        ()

let lemma_vis_correct
      (v_NUM_PARTIES: usize)
      (parties: t_Array (Polytune.Faand.Spec.t_PartyState v_NUM_PARTIES) v_NUM_PARTIES)
    : Lemma
    (ensures
      (let (hashes: t_Array (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) v_NUM_PARTIES):t_Array
          (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) v_NUM_PARTIES =
          Core.Array.from_fn #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
            v_NUM_PARTIES
            (fun i ->
                let i:usize = i in
                let party:Polytune.Faand.Spec.t_PartyState v_NUM_PARTIES = parties.[ i ] in
                let xshare:Polytune.Data_types.t_Share = party.Polytune.Faand.Spec.f_xshare in
                let yi:bool =
                  Polytune.Data_types.impl_Share__bit party.Polytune.Faand.Spec.f_yshare
                in
                fhaand_compute_hashes party.Polytune.Faand.Spec.f_delta
                  i
                  v_NUM_PARTIES
                  xshare
                  yi
                  (party.Polytune.Faand.Spec.f_randomness <: t_Slice bool))
        in
        let
        (hashes_transposed:
          t_Array (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) v_NUM_PARTIES):t_Array
          (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) v_NUM_PARTIES =
          Core.Array.from_fn #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
            v_NUM_PARTIES
            (fun j ->
                let j:usize = j in
                Core.Iter.Traits.Iterator.f_collect #(Core.Iter.Adapters.Map.t_Map
                      (Core.Slice.Iter.t_Iter (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global))
                      (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global -> (bool & bool)))
                  #FStar.Tactics.Typeclasses.solve
                  #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                  (Core.Iter.Traits.Iterator.f_map #(Core.Slice.Iter.t_Iter
                        (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global))
                      #FStar.Tactics.Typeclasses.solve
                      #(bool & bool)
                      (Core.Slice.impl__iter #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                          (hashes <: t_Slice (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global))
                        <:
                        Core.Slice.Iter.t_Iter (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global))
                      (fun vec ->
                          let vec:Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global = vec in
                          Core.Clone.f_clone #(bool & bool)
                            #FStar.Tactics.Typeclasses.solve
                            (vec.[ j ] <: (bool & bool))
                          <:
                          (bool & bool))
                    <:
                    Core.Iter.Adapters.Map.t_Map
                      (Core.Slice.Iter.t_Iter (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global))
                      (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global -> (bool & bool)))
                <:
                Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
        in
        let (ts: t_Array (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) v_NUM_PARTIES):t_Array
          (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) v_NUM_PARTIES =
          Core.Array.from_fn #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
            v_NUM_PARTIES
            (fun i ->
                let i:usize = i in
                let party:Polytune.Faand.Spec.t_PartyState v_NUM_PARTIES = parties.[ i ] in
                fhaand_compute_ts i
                  v_NUM_PARTIES
                  party.Polytune.Faand.Spec.f_xshare
                  (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                      #FStar.Tactics.Typeclasses.solve
                      (hashes_transposed.[ i ] <: Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global
                      )
                    <:
                    t_Slice (bool & bool)))
        in
        let (vis: t_Array bool v_NUM_PARTIES):t_Array bool v_NUM_PARTIES =
          Core.Array.from_fn #bool
            v_NUM_PARTIES
            (fun i ->
                let i:usize = i in
                let party:Polytune.Faand.Spec.t_PartyState v_NUM_PARTIES = parties.[ i ] in
                fhaand_compute_vi i
                  v_NUM_PARTIES
                  (party.Polytune.Faand.Spec.f_randomness <: t_Slice bool)
                  (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                      #FStar.Tactics.Typeclasses.solve
                      (ts.[ i ] <: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                    <:
                    t_Slice bool))
        in
        let xor_vis:bool = false in
        let xor_vis:bool =
          Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
            v_NUM_PARTIES
            (fun xor_vis temp_1_ ->
                let xor_vis:bool = xor_vis in
                let _:usize = temp_1_ in
                true)
            xor_vis
            (fun xor_vis i ->
                let xor_vis:bool = xor_vis in
                let i:usize = i in
                Core.Ops.Bit.f_bitxor xor_vis (vis.[ i ] <: bool) <: bool)
        in
        let expected_result:bool = false in
        let expected_result:bool =
          Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
            v_NUM_PARTIES
            (fun expected_result temp_1_ ->
                let expected_result:bool = expected_result in
                let _:usize = temp_1_ in
                true)
            expected_result
            (fun expected_result i ->
                let expected_result:bool = expected_result in
                let i:usize = i in
                Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                  v_NUM_PARTIES
                  (fun expected_result temp_1_ ->
                      let expected_result:bool = expected_result in
                      let _:usize = temp_1_ in
                      true)
                  expected_result
                  (fun expected_result j ->
                      let expected_result:bool = expected_result in
                      let j:usize = j in
                      if i =. j <: bool
                      then expected_result
                      else
                        let half_and_i_j:bool =
                          Core.Ops.Bit.f_bitand (Polytune.Data_types.impl_Share__bit (parties.[ i ]
                                  <:
                                  Polytune.Faand.Spec.t_PartyState v_NUM_PARTIES)
                                  .Polytune.Faand.Spec.f_xshare
                              <:
                              bool)
                            (Polytune.Data_types.impl_Share__bit (parties.[ j ]
                                  <:
                                  Polytune.Faand.Spec.t_PartyState v_NUM_PARTIES)
                                  .Polytune.Faand.Spec.f_yshare
                              <:
                              bool)
                        in
                        Core.Ops.Bit.f_bitxor expected_result half_and_i_j)
                <:
                bool)
        in
        xor_vis =. expected_result)) = ()
