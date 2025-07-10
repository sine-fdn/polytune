module Polytune.Faand
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Polytune.Data_types in
  ()

/// Errors occurring during preprocessing.
type t_Error =
  | Error_ChannelErr : Polytune.Channel.t_Error -> t_Error
  | Error_InvalidBitValue : t_Error
  | Error_CommitmentCouldNotBeOpened : t_Error
  | Error_EmptyVector : t_Error
  | Error_ConversionErr : t_Error
  | Error_EmptyBucket : t_Error
  | Error_EmptyMsg : t_Error
  | Error_InvalidLength : t_Error
  | Error_InconsistentBroadcast : t_Error
  | Error_ABitWrongMAC : t_Error
  | Error_AShareWrongMAC : t_Error
  | Error_LaANDXorNotZero : t_Error
  | Error_AANDWrongMAC : t_Error
  | Error_BeaverWrongMAC : t_Error
  | Error_InvalidHashLength : t_Error
  | Error_OtErr : Polytune.Swankyot.t_Error -> t_Error

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

/// Combine two leaky ANDs into one non-leaky AND.
let combine_two_leaky_ands (i n: usize) (x1 y1 z1 x2 z2: Polytune.Data_types.t_Share) (d: bool)
    : Prims.Pure
      (Core.Result.t_Result
          (Polytune.Data_types.t_Share & Polytune.Data_types.t_Share & Polytune.Data_types.t_Share)
          t_Error)
      (requires
        (Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
            #Alloc.Alloc.t_Global
            x1.Polytune.Data_types._1.Polytune.Data_types._0
          <:
          usize) >=.
        n &&
        (Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
            #Alloc.Alloc.t_Global
            x2.Polytune.Data_types._1.Polytune.Data_types._0
          <:
          usize) >=.
        n &&
        (Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
            #Alloc.Alloc.t_Global
            z1.Polytune.Data_types._1.Polytune.Data_types._0
          <:
          usize) >=.
        n &&
        (Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
            #Alloc.Alloc.t_Global
            z2.Polytune.Data_types._1.Polytune.Data_types._0
          <:
          usize) >=.
        n)
      (fun _ -> Prims.l_True) =
  let xbit:bool = Core.Ops.Bit.f_bitxor x1.Polytune.Data_types._0 x2.Polytune.Data_types._0 in
  let xauth:Polytune.Data_types.t_Auth =
    Polytune.Data_types.Auth
    (Alloc.Vec.from_elem #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
        ((Polytune.Data_types.Mac (mk_u128 0) <: Polytune.Data_types.t_Mac),
          (Polytune.Data_types.Key (mk_u128 0) <: Polytune.Data_types.t_Key)
          <:
          (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key))
        n)
    <:
    Polytune.Data_types.t_Auth
  in
  let xauth:Polytune.Data_types.t_Auth =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      n
      (fun xauth k ->
          let xauth:Polytune.Data_types.t_Auth = xauth in
          let k:usize = k in
          (Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
              #Alloc.Alloc.t_Global
              xauth.Polytune.Data_types._0
            <:
            usize) =.
          n
          <:
          bool)
      xauth
      (fun xauth k ->
          let xauth:Polytune.Data_types.t_Auth = xauth in
          let k:usize = k in
          if k =. i <: bool
          then xauth
          else
            let mk_x1, ki_x1:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
              x1.Polytune.Data_types._1.Polytune.Data_types._0.[ k ]
            in
            let mk_x2, ki_x2:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
              x2.Polytune.Data_types._1.Polytune.Data_types._0.[ k ]
            in
            {
              xauth with
              Polytune.Data_types._0
              =
              Rust_primitives.Hax.Monomorphized_update_at.update_at_usize xauth
                  .Polytune.Data_types._0
                k
                ((Core.Ops.Bit.f_bitxor #Polytune.Data_types.t_Mac
                      #Polytune.Data_types.t_Mac
                      #FStar.Tactics.Typeclasses.solve
                      mk_x1
                      mk_x2
                    <:
                    Polytune.Data_types.t_Mac),
                  (Core.Ops.Bit.f_bitxor #Polytune.Data_types.t_Key
                      #Polytune.Data_types.t_Key
                      #FStar.Tactics.Typeclasses.solve
                      ki_x1
                      ki_x2
                    <:
                    Polytune.Data_types.t_Key)
                  <:
                  (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key))
            }
            <:
            Polytune.Data_types.t_Auth)
  in
  let xshare:Polytune.Data_types.t_Share =
    Polytune.Data_types.Share xbit xauth <: Polytune.Data_types.t_Share
  in
  let zbit:bool =
    Core.Ops.Bit.f_bitxor (Core.Ops.Bit.f_bitxor z1.Polytune.Data_types._0 z2.Polytune.Data_types._0
        <:
        bool)
      (Core.Ops.Bit.f_bitand d x2.Polytune.Data_types._0 <: bool)
  in
  let zauth:Polytune.Data_types.t_Auth =
    Polytune.Data_types.Auth
    (Alloc.Vec.from_elem #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
        ((Polytune.Data_types.Mac (mk_u128 0) <: Polytune.Data_types.t_Mac),
          (Polytune.Data_types.Key (mk_u128 0) <: Polytune.Data_types.t_Key)
          <:
          (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key))
        n)
    <:
    Polytune.Data_types.t_Auth
  in
  let zauth:Polytune.Data_types.t_Auth =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      n
      (fun zauth k ->
          let zauth:Polytune.Data_types.t_Auth = zauth in
          let k:usize = k in
          (Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
              #Alloc.Alloc.t_Global
              zauth.Polytune.Data_types._0
            <:
            usize) =.
          n
          <:
          bool)
      zauth
      (fun zauth k ->
          let zauth:Polytune.Data_types.t_Auth = zauth in
          let k:usize = k in
          if k =. i <: bool
          then zauth
          else
            let mk_z1, ki_z1:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
              z1.Polytune.Data_types._1.Polytune.Data_types._0.[ k ]
            in
            let mk_z2, ki_z2:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
              z2.Polytune.Data_types._1.Polytune.Data_types._0.[ k ]
            in
            let mk_x2, ki_x2:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
              x2.Polytune.Data_types._1.Polytune.Data_types._0.[ k ]
            in
            {
              zauth with
              Polytune.Data_types._0
              =
              Rust_primitives.Hax.Monomorphized_update_at.update_at_usize zauth
                  .Polytune.Data_types._0
                k
                ((Core.Ops.Bit.f_bitxor #Polytune.Data_types.t_Mac
                      #Polytune.Data_types.t_Mac
                      #FStar.Tactics.Typeclasses.solve
                      (Core.Ops.Bit.f_bitxor #Polytune.Data_types.t_Mac
                          #Polytune.Data_types.t_Mac
                          #FStar.Tactics.Typeclasses.solve
                          mk_z1
                          mk_z2
                        <:
                        Polytune.Data_types.t_Mac)
                      (Polytune.Data_types.Mac
                        ((cast (d <: bool) <: u128) *! mk_x2.Polytune.Data_types._0 <: u128)
                        <:
                        Polytune.Data_types.t_Mac)
                    <:
                    Polytune.Data_types.t_Mac),
                  (Core.Ops.Bit.f_bitxor #Polytune.Data_types.t_Key
                      #Polytune.Data_types.t_Key
                      #FStar.Tactics.Typeclasses.solve
                      (Core.Ops.Bit.f_bitxor #Polytune.Data_types.t_Key
                          #Polytune.Data_types.t_Key
                          #FStar.Tactics.Typeclasses.solve
                          ki_z1
                          ki_z2
                        <:
                        Polytune.Data_types.t_Key)
                      (Polytune.Data_types.Key
                        ((cast (d <: bool) <: u128) *! ki_x2.Polytune.Data_types._0 <: u128)
                        <:
                        Polytune.Data_types.t_Key)
                    <:
                    Polytune.Data_types.t_Key)
                  <:
                  (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key))
            }
            <:
            Polytune.Data_types.t_Auth)
  in
  let zshare:Polytune.Data_types.t_Share =
    Polytune.Data_types.Share zbit zauth <: Polytune.Data_types.t_Share
  in
  Core.Result.Result_Ok
  (xshare, y1, zshare
    <:
    (Polytune.Data_types.t_Share & Polytune.Data_types.t_Share & Polytune.Data_types.t_Share))
  <:
  Core.Result.t_Result
    (Polytune.Data_types.t_Share & Polytune.Data_types.t_Share & Polytune.Data_types.t_Share)
    t_Error

let rec xor_bits (a: t_Slice bool) : bool =
  if (Core.Slice.impl__len #bool a <: usize) =. mk_usize 0
  then false
  else
    Core.Ops.Bit.f_bitxor (a.[ mk_usize 0 ] <: bool)
      (xor_bits (a.[ { Core.Ops.Range.f_start = mk_usize 1 } <: Core.Ops.Range.t_RangeFrom usize ]
            <:
            t_Slice bool)
        <:
        bool)

let rec xor_zip (a b: t_Slice bool)
    : Prims.Pure (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
      (requires (Core.Slice.impl__len #bool a <: usize) =. (Core.Slice.impl__len #bool b <: usize))
      (ensures
        fun result ->
          let result:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = result in
          (Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global result <: usize) =.
          (Core.Slice.impl__len #bool a <: usize)) =
  if (Core.Slice.impl__len #bool a <: usize) =. mk_usize 0
  then Alloc.Vec.impl__new #bool ()
  else
    let rest:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
      xor_zip (a.[ { Core.Ops.Range.f_start = mk_usize 1 } <: Core.Ops.Range.t_RangeFrom usize ]
          <:
          t_Slice bool)
        (b.[ { Core.Ops.Range.f_start = mk_usize 1 } <: Core.Ops.Range.t_RangeFrom usize ]
          <:
          t_Slice bool)
    in
    let rest:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #bool
        #Alloc.Alloc.t_Global
        rest
        ((let list =
              [Core.Ops.Bit.f_bitxor (a.[ mk_usize 0 ] <: bool) (b.[ mk_usize 0 ] <: bool)]
            in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list)
          <:
          t_Slice bool)
    in
    rest

let lemma_xor_distributivity (v_LEN: usize) (a b: t_Array bool v_LEN)
    : Lemma
    (ensures
      (xor_bits (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              (xor_zip (Core.Array.impl_23__as_slice #bool v_LEN a <: t_Slice bool)
                  (Core.Array.impl_23__as_slice #bool v_LEN b <: t_Slice bool)
                <:
                Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
            <:
            t_Slice bool)
        <:
        bool) =.
      (Core.Ops.Bit.f_bitxor (xor_bits (Core.Array.impl_23__as_slice #bool v_LEN a <: t_Slice bool)
            <:
            bool)
          (xor_bits (Core.Array.impl_23__as_slice #bool v_LEN b <: t_Slice bool) <: bool)
        <:
        bool)) = ()
