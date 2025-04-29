module Polytune.Faand
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Polytune.Channel in
  let open Polytune.Data_types in
  let open Serde.De in
  let open Serde.De.Impls in
  let open Serde.Ser in
  let open Serde.Ser.Impls in
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
  | Error_KOSConsistencyCheckFailed : t_Error
  | Error_ABitWrongMAC : t_Error
  | Error_AShareWrongMAC : t_Error
  | Error_LaANDXorNotZero : t_Error
  | Error_AANDWrongMAC : t_Error
  | Error_BeaverWrongMAC : t_Error
  | Error_InvalidHashLength : t_Error

/// Converts a `channel::Error` into a custom `Error` type.
[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl: Core.Convert.t_From t_Error Polytune.Channel.t_Error =
  {
    f_from_pre = (fun (e: Polytune.Channel.t_Error) -> true);
    f_from_post = (fun (e: Polytune.Channel.t_Error) (out: t_Error) -> true);
    f_from = fun (e: Polytune.Channel.t_Error) -> Error_ChannelErr e <: t_Error
  }

/// Represents a cryptographic commitment as a fixed-size 32-byte array (a BLAKE3 hash).
type t_Commitment = | Commitment : t_Array u8 (mk_usize 32) -> t_Commitment

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Core.Fmt.t_Debug t_Commitment

unfold
let impl_2 = impl_2'

let impl_3: Core.Clone.t_Clone t_Commitment = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val e___impl': Serde.Ser.t_Serialize t_Commitment

unfold
let e___impl = e___impl'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val e_ee_1__impl': Serde.De.t_Deserialize t_Commitment

unfold
let e_ee_1__impl = e_ee_1__impl'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_6': Core.Cmp.t_PartialEq t_Commitment t_Commitment

unfold
let impl_6 = impl_6'

/// Commits to a value using the BLAKE3 cryptographic hash function.
/// This is not a general-purpose commitment scheme, the input value is assumed to have high entropy.
assume
val commit': value: t_Slice u8 -> t_Commitment

unfold
let commit = commit'

/// Verifies if a given value matches a previously generated commitment.
/// This is not a general-purpose commitment scheme, the input value is assumed to have high entropy.
let open_commitment (commitment: t_Commitment) (value: t_Slice u8) : bool =
  (Blake3.impl_Hash__as_bytes (Blake3.hash value <: Blake3.t_Hash) <: t_Array u8 (mk_usize 32)) =.
  commitment._0

/// Implements broadcast with abort based on Goldwasser and Lindell\'s protocol
/// for all parties at once, where each party sends its vector to all others.
/// The function returns the vector received and verified by broadcast.
assume
val broadcast':
    #v_T: Type0 ->
    #iimpl_951670863_: Type0 ->
    {| i2: Core.Clone.t_Clone v_T |} ->
    {| i3: Serde.Ser.t_Serialize v_T |} ->
    {| i4: Serde.De.t_DeserializeOwned v_T |} ->
    {| i5: Core.Fmt.t_Debug v_T |} ->
    {| i6: Core.Cmp.t_PartialEq v_T v_T |} ->
    {| i7: Polytune.Channel.t_Channel iimpl_951670863_ |} ->
    channel: iimpl_951670863_ ->
    i: usize ->
    n: usize ->
    phase: string ->
    vec: t_Slice v_T ->
    len: usize
  -> (iimpl_951670863_ &
      Core.Result.t_Result
        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) t_Error)

unfold
let broadcast
      (#v_T #iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Serde.Ser.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Serde.De.t_DeserializeOwned v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: Core.Fmt.t_Debug v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i6: Core.Cmp.t_PartialEq v_T v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i7: Polytune.Channel.t_Channel iimpl_951670863_)
     = broadcast' #v_T #iimpl_951670863_ #i2 #i3 #i4 #i5 #i6 #i7

/// Implements same broadcast with abort as broadcast, but only the first element of the tuple in
/// the vector is broadcasted, the second element is simply sent to all parties.
assume
val broadcast_first_send_second':
    #v_T: Type0 ->
    #v_S: Type0 ->
    #iimpl_951670863_: Type0 ->
    {| i3: Core.Clone.t_Clone v_T |} ->
    {| i4: Serde.Ser.t_Serialize v_T |} ->
    {| i5: Serde.De.t_DeserializeOwned v_T |} ->
    {| i6: Core.Fmt.t_Debug v_T |} ->
    {| i7: Core.Cmp.t_PartialEq v_T v_T |} ->
    {| i8: Core.Clone.t_Clone v_S |} ->
    {| i9: Serde.Ser.t_Serialize v_S |} ->
    {| i10: Serde.De.t_DeserializeOwned v_S |} ->
    {| i11: Core.Fmt.t_Debug v_S |} ->
    {| i12: Core.Cmp.t_PartialEq v_S v_S |} ->
    {| i13: Polytune.Channel.t_Channel iimpl_951670863_ |} ->
    channel: iimpl_951670863_ ->
    i: usize ->
    n: usize ->
    phase: string ->
    vec: t_Slice (Alloc.Vec.t_Vec (v_T & v_S) Alloc.Alloc.t_Global) ->
    len: usize
  -> (iimpl_951670863_ &
      Core.Result.t_Result
        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (v_T & v_S) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
        t_Error)

unfold
let broadcast_first_send_second
      (#v_T #v_S #iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Clone.t_Clone v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Serde.Ser.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: Serde.De.t_DeserializeOwned v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i6: Core.Fmt.t_Debug v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i7: Core.Cmp.t_PartialEq v_T v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i8: Core.Clone.t_Clone v_S)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i9: Serde.Ser.t_Serialize v_S)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i10: Serde.De.t_DeserializeOwned v_S)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i11: Core.Fmt.t_Debug v_S)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i12: Core.Cmp.t_PartialEq v_S v_S)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i13: Polytune.Channel.t_Channel iimpl_951670863_)
     =
  broadcast_first_send_second' #v_T #v_S #iimpl_951670863_ #i3 #i4 #i5 #i6 #i7 #i8 #i9 #i10 #i11
    #i12 #i13

assume
val random_bool': Prims.unit -> bool

unfold
let random_bool = random_bool'

/// Protocol Pi_HaAND that performs F_HaAND from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
/// This protocol computes the half-authenticated AND of two bit strings.
/// The XOR of xiyj values are generated obliviously, which is half of the z value in an
/// authenticated share, i.e., a half-authenticated share.
let fhaand
      (#iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Polytune.Channel.t_Channel iimpl_951670863_)
      (channel: iimpl_951670863_)
      (delta: Polytune.Data_types.t_Delta)
      (i n l: usize)
      (xshares: t_Slice Polytune.Data_types.t_Share)
      (yi: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
    : (iimpl_951670863_ & Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error) =
  if (Core.Slice.impl__len #Polytune.Data_types.t_Share xshares <: usize) <>. l
  then
    channel,
    (Core.Result.Result_Err (Error_InvalidLength <: t_Error)
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
    <:
    (iimpl_951670863_ & Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
  else
    let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = Alloc.Vec.from_elem #bool false l in
    let h0h1:Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global =
      Alloc.Vec.from_elem #(bool & bool) (false, false <: (bool & bool)) l
    in
    match
      Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
        n
        (fun temp_0_ temp_1_ ->
            let channel, h0h1, vi:(iimpl_951670863_ &
              Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
              temp_0_
            in
            let _:usize = temp_1_ in
            true)
        (channel, h0h1, vi
          <:
          (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
        (fun temp_0_ j ->
            let channel, h0h1, vi:(iimpl_951670863_ &
              Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
              temp_0_
            in
            let j:usize = j in
            if j =. i <: bool
            then
              Core.Ops.Control_flow.ControlFlow_Continue
              (channel, h0h1, vi
                <:
                (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
              <:
              Core.Ops.Control_flow.t_ControlFlow
                (Core.Ops.Control_flow.t_ControlFlow
                    (iimpl_951670863_ &
                      Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
                    (Prims.unit &
                      (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)))
                (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
            else
              let h0h1, vi:(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
                Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                  l
                  (fun temp_0_ temp_1_ ->
                      let h0h1, vi:(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let _:usize = temp_1_ in
                      true)
                  (h0h1, vi
                    <:
                    (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                  (fun temp_0_ ll ->
                      let h0h1, vi:(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let ll:usize = ll in
                      let (sj: bool):bool = random_bool () in
                      let _, kixj:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
                        (xshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                          .Polytune.Data_types._0.[ j ]
                      in
                      let hash_kixj:Blake3.t_Hash =
                        Blake3.hash (Core.Num.impl_u128__to_le_bytes kixj.Polytune.Data_types._0
                            <:
                            t_Slice u8)
                      in
                      let hash_kixj_delta:Blake3.t_Hash =
                        Blake3.hash (Core.Num.impl_u128__to_le_bytes (kixj.Polytune.Data_types._0 ^.
                                delta.Polytune.Data_types._0
                                <:
                                u128)
                            <:
                            t_Slice u8)
                      in
                      let h0h1:Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize h0h1
                          ll
                          ({
                              (h0h1.[ ll ] <: (bool & bool)) with
                              _1
                              =
                              Core.Ops.Bit.f_bitxor ((((Blake3.impl_Hash__as_bytes hash_kixj
                                        <:
                                        t_Array u8 (mk_usize 32)).[ mk_usize 31 ]
                                      <:
                                      u8) &.
                                    mk_u8 1
                                    <:
                                    u8) <>.
                                  mk_u8 0
                                  <:
                                  bool)
                                sj
                              <:
                              bool
                            }
                            <:
                            (bool & bool))
                      in
                      let h0h1:Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize h0h1
                          ll
                          ({
                              (h0h1.[ ll ] <: (bool & bool)) with
                              _2
                              =
                              Core.Ops.Bit.f_bitxor (Core.Ops.Bit.f_bitxor ((((Blake3.impl_Hash__as_bytes
                                              hash_kixj_delta
                                            <:
                                            t_Array u8 (mk_usize 32)).[ mk_usize 31 ]
                                          <:
                                          u8) &.
                                        mk_u8 1
                                        <:
                                        u8) <>.
                                      mk_u8 0
                                      <:
                                      bool)
                                    sj
                                  <:
                                  bool)
                                (yi.[ ll ] <: bool)
                              <:
                              bool
                            }
                            <:
                            (bool & bool))
                      in
                      let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize vi
                          ll
                          (Core.Ops.Bit.f_bitxor (vi.[ ll ] <: bool) sj <: bool)
                      in
                      h0h1, vi
                      <:
                      (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
              in
              let tmp0, out:(iimpl_951670863_ &
                Core.Result.t_Result Prims.unit Polytune.Channel.t_Error) =
                Polytune.Channel.send_to #(bool & bool)
                  #iimpl_951670863_
                  channel
                  j
                  "haand"
                  (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                      #FStar.Tactics.Typeclasses.solve
                      h0h1
                    <:
                    t_Slice (bool & bool))
              in
              let channel:iimpl_951670863_ = tmp0 in
              match out <: Core.Result.t_Result Prims.unit Polytune.Channel.t_Error with
              | Core.Result.Result_Ok _ ->
                Core.Ops.Control_flow.ControlFlow_Continue
                (channel, h0h1, vi
                  <:
                  (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (iimpl_951670863_ &
                        Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
                      (Prims.unit &
                        (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)))
                  (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (channel,
                    (Core.Result.Result_Err
                      (Core.Convert.f_from #t_Error
                          #Polytune.Channel.t_Error
                          #FStar.Tactics.Typeclasses.solve
                          err)
                      <:
                      Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
                    <:
                    (iimpl_951670863_ &
                      Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (iimpl_951670863_ &
                      Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
                    (Prims.unit &
                      (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (iimpl_951670863_ &
                        Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
                      (Prims.unit &
                        (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)))
                  (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
      <:
      Core.Ops.Control_flow.t_ControlFlow
        (iimpl_951670863_ & Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error
        )
        (iimpl_951670863_ & Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
    with
    | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
    | Core.Ops.Control_flow.ControlFlow_Continue (channel, h0h1, vi) ->
      match
        Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
          n
          (fun temp_0_ temp_1_ ->
              let channel, vi:(iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
                temp_0_
              in
              let _:usize = temp_1_ in
              true)
          (channel, vi <: (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
          (fun temp_0_ j ->
              let channel, vi:(iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
                temp_0_
              in
              let j:usize = j in
              if j =. i <: bool
              then
                Core.Ops.Control_flow.ControlFlow_Continue
                (channel, vi <: (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (iimpl_951670863_ &
                        Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
                      (Prims.unit & (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)))
                  (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
              else
                let tmp0, out:(iimpl_951670863_ &
                  Core.Result.t_Result (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                    Polytune.Channel.t_Error) =
                  Polytune.Channel.recv_vec_from #(bool & bool)
                    #iimpl_951670863_
                    channel
                    j
                    "haand"
                    l
                in
                let channel:iimpl_951670863_ = tmp0 in
                match
                  out
                  <:
                  Core.Result.t_Result (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                    Polytune.Channel.t_Error
                with
                | Core.Result.Result_Ok h0h1_j ->
                  let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                      l
                      (fun vi temp_1_ ->
                          let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = vi in
                          let _:usize = temp_1_ in
                          true)
                      vi
                      (fun vi ll ->
                          let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = vi in
                          let ll:usize = ll in
                          let mixj, _:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
                            (xshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                              .Polytune.Data_types._0.[ j ]
                          in
                          let hash_mixj:Blake3.t_Hash =
                            Blake3.hash (Core.Num.impl_u128__to_le_bytes mixj.Polytune.Data_types._0
                                <:
                                t_Slice u8)
                          in
                          let t:bool =
                            (((Blake3.impl_Hash__as_bytes hash_mixj <: t_Array u8 (mk_usize 32)).[ mk_usize
                                  31 ]
                                <:
                                u8) &.
                              mk_u8 1
                              <:
                              u8) <>.
                            mk_u8 0
                          in
                          let t:bool =
                            Core.Ops.Bit.f_bitxor t
                              (if
                                  (xshares.[ ll ] <: Polytune.Data_types.t_Share)
                                    .Polytune.Data_types._0
                                then (h0h1_j.[ ll ] <: (bool & bool))._2
                                else (h0h1_j.[ ll ] <: (bool & bool))._1)
                          in
                          let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
                            Rust_primitives.Hax.Monomorphized_update_at.update_at_usize vi
                              ll
                              (Core.Ops.Bit.f_bitxor (vi.[ ll ] <: bool) t <: bool)
                          in
                          vi)
                  in
                  Core.Ops.Control_flow.ControlFlow_Continue
                  (channel, vi <: (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Ops.Control_flow.t_ControlFlow
                        (iimpl_951670863_ &
                          Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
                        (Prims.unit & (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                        )) (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                | Core.Result.Result_Err err ->
                  Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Ops.Control_flow.ControlFlow_Break
                    (channel,
                      (Core.Result.Result_Err
                        (Core.Convert.f_from #t_Error
                            #Polytune.Channel.t_Error
                            #FStar.Tactics.Typeclasses.solve
                            err)
                        <:
                        Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
                      <:
                      (iimpl_951670863_ &
                        Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (iimpl_951670863_ &
                        Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
                      (Prims.unit & (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Ops.Control_flow.t_ControlFlow
                        (iimpl_951670863_ &
                          Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
                        (Prims.unit & (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                        )) (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (iimpl_951670863_ &
            Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error)
          (iimpl_951670863_ & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (channel, vi) ->
        let hax_temp_output:Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error
        =
          Core.Result.Result_Ok vi
          <:
          Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error
        in
        channel, hax_temp_output
        <:
        (iimpl_951670863_ & Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error
        )

/// This function takes a 128-bit unsigned integer (`u128`) as input and produces a 128-bit hash value.
/// We use the BLAKE3 cryptographic hash function to hash the input value and return the resulting hash.
/// The hash is truncated to 128 bits to match the input size. Due to the truncation, the security
/// guarantees of the hash function are reduced to 64-bit collision resistance and 128-bit preimage
/// resistance. This is sufficient for the purposes of the protocol if RHO <= 64, which we expect
/// to be the case in all real-world usages of our protocol.
assume
val hash128': input: u128 -> Core.Result.t_Result u128 t_Error

unfold
let hash128 = hash128'

/// Protocol Pi_LaAND that performs F_LaAND from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
/// This asynchronous function implements the \"leaky authenticated AND\" protocol. It computes
/// shares <x>, <y>, and <z> such that the AND of the XORs of the input values x and y equals
/// the XOR of the output values z.
let flaand
      (#iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Polytune.Channel.t_Channel iimpl_951670863_)
      (channel: iimpl_951670863_)
      (delta: Polytune.Data_types.t_Delta)
      (xshares, yshares, rshares:
          (t_Slice Polytune.Data_types.t_Share & t_Slice Polytune.Data_types.t_Share &
            t_Slice Polytune.Data_types.t_Share))
      (i: usize)
      (n: usize)
      (l: usize)
    : (iimpl_951670863_ &
      Core.Result.t_Result (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
        t_Error) =
  if
    (Core.Slice.impl__len #Polytune.Data_types.t_Share xshares <: usize) <>. l ||
    (Core.Slice.impl__len #Polytune.Data_types.t_Share yshares <: usize) <>. l ||
    (Core.Slice.impl__len #Polytune.Data_types.t_Share rshares <: usize) <>. l
  then
    channel,
    (Core.Result.Result_Err (Error_InvalidLength <: t_Error)
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
        t_Error)
    <:
    (iimpl_951670863_ &
      Core.Result.t_Result (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
        t_Error)
  else
    let y:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
      Core.Iter.Traits.Iterator.f_collect #(Core.Iter.Adapters.Map.t_Map
            (Core.Iter.Adapters.Take.t_Take (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share))
            (Polytune.Data_types.t_Share -> bool))
        #FStar.Tactics.Typeclasses.solve
        #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
        (Core.Iter.Traits.Iterator.f_map #(Core.Iter.Adapters.Take.t_Take
              (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share))
            #FStar.Tactics.Typeclasses.solve
            #bool
            (Core.Iter.Traits.Iterator.f_take #(Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share)
                #FStar.Tactics.Typeclasses.solve
                (Core.Slice.impl__iter #Polytune.Data_types.t_Share yshares
                  <:
                  Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share)
                l
              <:
              Core.Iter.Adapters.Take.t_Take (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share))
            (fun share ->
                let share:Polytune.Data_types.t_Share = share in
                share.Polytune.Data_types._0)
          <:
          Core.Iter.Adapters.Map.t_Map
            (Core.Iter.Adapters.Take.t_Take (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share))
            (Polytune.Data_types.t_Share -> bool))
    in
    let tmp0, out:(iimpl_951670863_ &
      Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error) =
      fhaand #iimpl_951670863_ channel delta i n l xshares y
    in
    let channel:iimpl_951670863_ = tmp0 in
    match out <: Core.Result.t_Result (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) t_Error with
    | Core.Result.Result_Ok v ->
      let z:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = Alloc.Vec.from_elem #bool false l in
      let e:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = Alloc.Vec.from_elem #bool false l in
      let zshares:Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global =
        Alloc.Vec.from_elem #Polytune.Data_types.t_Share
          (Polytune.Data_types.Share false
              (Polytune.Data_types.Auth
                (Alloc.Vec.from_elem #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                    ((Polytune.Data_types.Mac (mk_u128 0) <: Polytune.Data_types.t_Mac),
                      (Polytune.Data_types.Key (mk_u128 0) <: Polytune.Data_types.t_Key)
                      <:
                      (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key))
                    n
                  <:
                  Alloc.Vec.t_Vec (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                    Alloc.Alloc.t_Global)
                <:
                Polytune.Data_types.t_Auth)
            <:
            Polytune.Data_types.t_Share)
          l
      in
      let e, z, zshares:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) =
        Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
          l
          (fun temp_0_ temp_1_ ->
              let e, z, zshares:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
                Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
                Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) =
                temp_0_
              in
              let _:usize = temp_1_ in
              true)
          (e, z, zshares
            <:
            (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
          (fun temp_0_ ll ->
              let e, z, zshares:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
                Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
                Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) =
                temp_0_
              in
              let ll:usize = ll in
              let z:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
                Rust_primitives.Hax.Monomorphized_update_at.update_at_usize z
                  ll
                  (Core.Ops.Bit.f_bitxor (v.[ ll ] <: bool)
                      (Core.Ops.Bit.f_bitand (xshares.[ ll ] <: Polytune.Data_types.t_Share)
                            .Polytune.Data_types._0
                          (yshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._0
                        <:
                        bool)
                    <:
                    bool)
              in
              let e:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
                Rust_primitives.Hax.Monomorphized_update_at.update_at_usize e
                  ll
                  (Core.Ops.Bit.f_bitxor (z.[ ll ] <: bool)
                      (rshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._0
                    <:
                    bool)
              in
              let zshares:Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global =
                Rust_primitives.Hax.Monomorphized_update_at.update_at_usize zshares
                  ll
                  ({
                      (zshares.[ ll ] <: Polytune.Data_types.t_Share) with
                      Polytune.Data_types._0 = z.[ ll ] <: bool
                    }
                    <:
                    Polytune.Data_types.t_Share)
              in
              e, z, zshares
              <:
              (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
                Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
      in
      let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = Alloc.Vec.from_elem #u128 (mk_u128 0) l in
      let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
        Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
          l
          (fun phi temp_1_ ->
              let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = phi in
              let _:usize = temp_1_ in
              true)
          phi
          (fun phi ll ->
              let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = phi in
              let ll:usize = ll in
              let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                  n
                  (fun phi temp_1_ ->
                      let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = phi in
                      let _:usize = temp_1_ in
                      true)
                  phi
                  (fun phi k ->
                      let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = phi in
                      let k:usize = k in
                      if k =. i <: bool
                      then phi
                      else
                        let mk_yi, ki_yk:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
                          (yshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                            .Polytune.Data_types._0.[ k ]
                        in
                        let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                          Rust_primitives.Hax.Monomorphized_update_at.update_at_usize phi
                            ll
                            (((phi.[ ll ] <: u128) ^. ki_yk.Polytune.Data_types._0 <: u128) ^.
                              mk_yi.Polytune.Data_types._0
                              <:
                              u128)
                        in
                        phi)
              in
              let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                Rust_primitives.Hax.Monomorphized_update_at.update_at_usize phi
                  ll
                  ((phi.[ ll ] <: u128) ^.
                    ((cast ((yshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._0
                            <:
                            bool)
                        <:
                        u128) *!
                      delta.Polytune.Data_types._0
                      <:
                      u128)
                    <:
                    u128)
              in
              phi)
      in
      let ki_xj_phi:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global
      =
        Alloc.Vec.from_elem #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
          (Alloc.Vec.from_elem #u128 (mk_u128 0) l <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
          n
      in
      let ei_uij:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
        Alloc.Alloc.t_Global =
        Alloc.Vec.from_elem #(Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
          (Alloc.Vec.impl__new #(bool & u128) ()
            <:
            Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
          n
      in
      (match
          Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
            n
            (fun temp_0_ temp_1_ ->
                let ei_uij, ki_xj_phi:(Alloc.Vec.t_Vec
                    (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                =
                  temp_0_
                in
                let _:usize = temp_1_ in
                true)
            (ei_uij, ki_xj_phi
              <:
              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global &
                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global))
            (fun temp_0_ j ->
                let ei_uij, ki_xj_phi:(Alloc.Vec.t_Vec
                    (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                =
                  temp_0_
                in
                let j:usize = j in
                if j =. i <: bool
                then
                  Core.Ops.Control_flow.ControlFlow_Continue
                  (ei_uij, ki_xj_phi
                    <:
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Ops.Control_flow.t_ControlFlow
                        (iimpl_951670863_ &
                          Core.Result.t_Result
                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                            t_Error)
                        (Prims.unit &
                          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global)))
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global)
                else
                  match
                    Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Iter.Adapters.Take.t_Take
                            (Core.Iter.Adapters.Enumerate.t_Enumerate (Core.Slice.Iter.t_Iter u128))
                          )
                          #FStar.Tactics.Typeclasses.solve
                          (Core.Iter.Traits.Iterator.f_take #(Core.Iter.Adapters.Enumerate.t_Enumerate
                                (Core.Slice.Iter.t_Iter u128))
                              #FStar.Tactics.Typeclasses.solve
                              (Core.Iter.Traits.Iterator.f_enumerate #(Core.Slice.Iter.t_Iter u128)
                                  #FStar.Tactics.Typeclasses.solve
                                  (Core.Slice.impl__iter #u128
                                      (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u128
                                              Alloc.Alloc.t_Global)
                                          #FStar.Tactics.Typeclasses.solve
                                          phi
                                        <:
                                        t_Slice u128)
                                    <:
                                    Core.Slice.Iter.t_Iter u128)
                                <:
                                Core.Iter.Adapters.Enumerate.t_Enumerate
                                (Core.Slice.Iter.t_Iter u128))
                              l
                            <:
                            Core.Iter.Adapters.Take.t_Take
                            (Core.Iter.Adapters.Enumerate.t_Enumerate (Core.Slice.Iter.t_Iter u128))
                          )
                        <:
                        Core.Iter.Adapters.Take.t_Take
                        (Core.Iter.Adapters.Enumerate.t_Enumerate (Core.Slice.Iter.t_Iter u128)))
                      (ei_uij, ki_xj_phi
                        <:
                        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global))
                      (fun temp_0_ temp_1_ ->
                          let ei_uij, ki_xj_phi:(Alloc.Vec.t_Vec
                              (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global) =
                            temp_0_
                          in
                          let ll, phi_l:(usize & u128) = temp_1_ in
                          let _, ki_xj:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
                            (xshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                              .Polytune.Data_types._0.[ j ]
                          in
                          match
                            hash128 ki_xj.Polytune.Data_types._0
                            <:
                            Core.Result.t_Result u128 t_Error
                          with
                          | Core.Result.Result_Ok hoist9 ->
                            let ki_xj_phi:Alloc.Vec.t_Vec
                              (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
                              Rust_primitives.Hax.Monomorphized_update_at.update_at_usize ki_xj_phi
                                j
                                (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (ki_xj_phi.[
                                        j ]
                                      <:
                                      Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                    ll
                                    hoist9
                                  <:
                                  Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            in
                            (match
                                hash128 (ki_xj.Polytune.Data_types._0 ^.
                                    delta.Polytune.Data_types._0
                                    <:
                                    u128)
                                <:
                                Core.Result.t_Result u128 t_Error
                              with
                              | Core.Result.Result_Ok hoist12 ->
                                let uij:u128 =
                                  (hoist12 ^.
                                    ((ki_xj_phi.[ j ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[
                                        ll ]
                                      <:
                                      u128)
                                    <:
                                    u128) ^.
                                  phi_l
                                in
                                let ei_uij:Alloc.Vec.t_Vec
                                  (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global =
                                  Rust_primitives.Hax.Monomorphized_update_at.update_at_usize ei_uij
                                    j
                                    (Alloc.Vec.impl_1__push #(bool & u128)
                                        #Alloc.Alloc.t_Global
                                        (ei_uij.[ j ]
                                          <:
                                          Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                        ((e.[ ll ] <: bool), uij <: (bool & u128))
                                      <:
                                      Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                in
                                Core.Ops.Control_flow.ControlFlow_Continue
                                (ei_uij, ki_xj_phi
                                  <:
                                  (Alloc.Vec.t_Vec
                                      (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global &
                                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global))
                                <:
                                Core.Ops.Control_flow.t_ControlFlow
                                  (Core.Ops.Control_flow.t_ControlFlow
                                      (iimpl_951670863_ &
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global) t_Error)
                                      (Prims.unit &
                                        (Alloc.Vec.t_Vec
                                            (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                            Alloc.Alloc.t_Global &
                                          Alloc.Vec.t_Vec
                                            (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                            Alloc.Alloc.t_Global)))
                                  (Alloc.Vec.t_Vec
                                      (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global &
                                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global)
                              | Core.Result.Result_Err err ->
                                Core.Ops.Control_flow.ControlFlow_Break
                                (Core.Ops.Control_flow.ControlFlow_Break
                                  (channel,
                                    (Core.Result.Result_Err err
                                      <:
                                      Core.Result.t_Result
                                        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                            Alloc.Alloc.t_Global) t_Error)
                                    <:
                                    (iimpl_951670863_ &
                                      Core.Result.t_Result
                                        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                            Alloc.Alloc.t_Global) t_Error))
                                  <:
                                  Core.Ops.Control_flow.t_ControlFlow
                                    (iimpl_951670863_ &
                                      Core.Result.t_Result
                                        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                            Alloc.Alloc.t_Global) t_Error)
                                    (Prims.unit &
                                      (Alloc.Vec.t_Vec
                                          (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                          Alloc.Alloc.t_Global &
                                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                          Alloc.Alloc.t_Global)))
                                <:
                                Core.Ops.Control_flow.t_ControlFlow
                                  (Core.Ops.Control_flow.t_ControlFlow
                                      (iimpl_951670863_ &
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global) t_Error)
                                      (Prims.unit &
                                        (Alloc.Vec.t_Vec
                                            (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                            Alloc.Alloc.t_Global &
                                          Alloc.Vec.t_Vec
                                            (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                            Alloc.Alloc.t_Global)))
                                  (Alloc.Vec.t_Vec
                                      (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global &
                                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global))
                          | Core.Result.Result_Err err ->
                            Core.Ops.Control_flow.ControlFlow_Break
                            (Core.Ops.Control_flow.ControlFlow_Break
                              (channel,
                                (Core.Result.Result_Err err
                                  <:
                                  Core.Result.t_Result
                                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                        Alloc.Alloc.t_Global) t_Error)
                                <:
                                (iimpl_951670863_ &
                                  Core.Result.t_Result
                                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                        Alloc.Alloc.t_Global) t_Error))
                              <:
                              Core.Ops.Control_flow.t_ControlFlow
                                (iimpl_951670863_ &
                                  Core.Result.t_Result
                                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                        Alloc.Alloc.t_Global) t_Error)
                                (Prims.unit &
                                  (Alloc.Vec.t_Vec
                                      (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global &
                                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global)))
                            <:
                            Core.Ops.Control_flow.t_ControlFlow
                              (Core.Ops.Control_flow.t_ControlFlow
                                  (iimpl_951670863_ &
                                    Core.Result.t_Result
                                      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                          Alloc.Alloc.t_Global) t_Error)
                                  (Prims.unit &
                                    (Alloc.Vec.t_Vec
                                        (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                        Alloc.Alloc.t_Global &
                                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                        Alloc.Alloc.t_Global)))
                              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global &
                                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (iimpl_951670863_ &
                        Core.Result.t_Result
                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) t_Error
                      )
                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global)
                  with
                  | Core.Ops.Control_flow.ControlFlow_Break ret ->
                    Core.Ops.Control_flow.ControlFlow_Break
                    (Core.Ops.Control_flow.ControlFlow_Break ret
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (iimpl_951670863_ &
                          Core.Result.t_Result
                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                            t_Error)
                        (Prims.unit &
                          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global)))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (Core.Ops.Control_flow.t_ControlFlow
                          (iimpl_951670863_ &
                            Core.Result.t_Result
                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                              t_Error)
                          (Prims.unit &
                            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global)))
                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global)
                  | Core.Ops.Control_flow.ControlFlow_Continue loop_res ->
                    Core.Ops.Control_flow.ControlFlow_Continue loop_res
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (Core.Ops.Control_flow.t_ControlFlow
                          (iimpl_951670863_ &
                            Core.Result.t_Result
                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                              t_Error)
                          (Prims.unit &
                            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global)))
                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global))
          <:
          Core.Ops.Control_flow.t_ControlFlow
            (iimpl_951670863_ &
              Core.Result.t_Result
                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) t_Error)
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
        with
        | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
        | Core.Ops.Control_flow.ControlFlow_Continue (ei_uij, ki_xj_phi) ->
          let tmp0, out:(iimpl_951670863_ &
            Core.Result.t_Result
              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global) t_Error) =
            broadcast_first_send_second #bool
              #u128
              #iimpl_951670863_
              channel
              i
              n
              "flaand"
              (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                      (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                  #FStar.Tactics.Typeclasses.solve
                  ei_uij
                <:
                t_Slice (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global))
              l
          in
          let channel:iimpl_951670863_ = tmp0 in
          match
            out
            <:
            Core.Result.t_Result
              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global) t_Error
          with
          | Core.Result.Result_Ok ei_uij_k ->
            (match
                Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
                  n
                  (fun temp_0_ temp_1_ ->
                      let ki_xj_phi, zshares:(Alloc.Vec.t_Vec
                          (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let _:usize = temp_1_ in
                      true)
                  (ki_xj_phi, zshares
                    <:
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
                  (fun temp_0_ j ->
                      let ki_xj_phi, zshares:(Alloc.Vec.t_Vec
                          (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let j:usize = j in
                      if j =. i <: bool
                      then
                        Core.Ops.Control_flow.ControlFlow_Continue
                        (ki_xj_phi, zshares
                          <:
                          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (Core.Ops.Control_flow.t_ControlFlow
                              (iimpl_951670863_ &
                                Core.Result.t_Result
                                  (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                                  t_Error)
                              (Prims.unit &
                                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                    Alloc.Alloc.t_Global &
                                  Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
                          )
                          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                      else
                        match
                          Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter
                                #(Core.Iter.Adapters.Take.t_Take
                                  (Core.Iter.Adapters.Enumerate.t_Enumerate
                                    (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share)))
                                #FStar.Tactics.Typeclasses.solve
                                (Core.Iter.Traits.Iterator.f_take #(Core.Iter.Adapters.Enumerate.t_Enumerate
                                      (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share))
                                    #FStar.Tactics.Typeclasses.solve
                                    (Core.Iter.Traits.Iterator.f_enumerate #(Core.Slice.Iter.t_Iter
                                          Polytune.Data_types.t_Share)
                                        #FStar.Tactics.Typeclasses.solve
                                        (Core.Slice.impl__iter #Polytune.Data_types.t_Share xshares
                                          <:
                                          Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share)
                                      <:
                                      Core.Iter.Adapters.Enumerate.t_Enumerate
                                      (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share))
                                    l
                                  <:
                                  Core.Iter.Adapters.Take.t_Take
                                  (Core.Iter.Adapters.Enumerate.t_Enumerate
                                    (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share)))
                              <:
                              Core.Iter.Adapters.Take.t_Take
                              (Core.Iter.Adapters.Enumerate.t_Enumerate
                                (Core.Slice.Iter.t_Iter Polytune.Data_types.t_Share)))
                            (ki_xj_phi, zshares
                              <:
                              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global &
                                Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
                            (fun temp_0_ temp_1_ ->
                                let ki_xj_phi, zshares:(Alloc.Vec.t_Vec
                                    (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                                  Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                                =
                                  temp_0_
                                in
                                let ll, xbit:(usize & Polytune.Data_types.t_Share) = temp_1_ in
                                let mi_xj, _:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                                =
                                  (xshares.[ ll ] <: Polytune.Data_types.t_Share)
                                    .Polytune.Data_types._1
                                    .Polytune.Data_types._0.[ j ]
                                in
                                match
                                  hash128 mi_xj.Polytune.Data_types._0
                                  <:
                                  Core.Result.t_Result u128 t_Error
                                with
                                | Core.Result.Result_Ok hoist16 ->
                                  let ki_xj_phi:Alloc.Vec.t_Vec
                                    (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global
                                  =
                                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize ki_xj_phi
                                      j
                                      (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (ki_xj_phi.[
                                              j ]
                                            <:
                                            Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                          ll
                                          ((((ki_xj_phi.[ j ]
                                                  <:
                                                  Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ ll ]
                                                <:
                                                u128) ^.
                                              hoist16
                                              <:
                                              u128) ^.
                                            ((cast (xbit.Polytune.Data_types._0 <: bool) <: u128) *!
                                              ((ei_uij_k.[ j ]
                                                  <:
                                                  Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global
                                                ).[ ll ]
                                                <:
                                                (bool & u128))
                                                ._2
                                              <:
                                              u128)
                                            <:
                                            u128)
                                        <:
                                        Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  in
                                  let mac, key:(Polytune.Data_types.t_Mac &
                                    Polytune.Data_types.t_Key) =
                                    (rshares.[ ll ] <: Polytune.Data_types.t_Share)
                                      .Polytune.Data_types._1
                                      .Polytune.Data_types._0.[ j ]
                                  in
                                  if
                                    ((ei_uij_k.[ j ]
                                        <:
                                        Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global).[ ll ])
                                      ._1
                                  then
                                    let zshares:Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                      Alloc.Alloc.t_Global =
                                      Rust_primitives.Hax.Monomorphized_update_at.update_at_usize zshares
                                        ll
                                        ({
                                            (zshares.[ ll ] <: Polytune.Data_types.t_Share) with
                                            Polytune.Data_types._1
                                            =
                                            {
                                              (zshares.[ ll ] <: Polytune.Data_types.t_Share)
                                                .Polytune.Data_types._1 with
                                              Polytune.Data_types._0
                                              =
                                              Rust_primitives.Hax.Monomorphized_update_at.update_at_usize
                                                (zshares.[ ll ] <: Polytune.Data_types.t_Share)
                                                  .Polytune.Data_types._1
                                                  .Polytune.Data_types._0
                                                j
                                                (mac,
                                                  (Polytune.Data_types.Key
                                                    (key.Polytune.Data_types._0 ^.
                                                      delta.Polytune.Data_types._0
                                                      <:
                                                      u128)
                                                    <:
                                                    Polytune.Data_types.t_Key)
                                                  <:
                                                  (Polytune.Data_types.t_Mac &
                                                    Polytune.Data_types.t_Key))
                                              <:
                                              Alloc.Vec.t_Vec
                                                (Polytune.Data_types.t_Mac &
                                                  Polytune.Data_types.t_Key) Alloc.Alloc.t_Global
                                            }
                                            <:
                                            Polytune.Data_types.t_Auth
                                          }
                                          <:
                                          Polytune.Data_types.t_Share)
                                    in
                                    Core.Ops.Control_flow.ControlFlow_Continue
                                    (ki_xj_phi, zshares
                                      <:
                                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                          Alloc.Alloc.t_Global &
                                        Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                          Alloc.Alloc.t_Global))
                                    <:
                                    Core.Ops.Control_flow.t_ControlFlow
                                      (Core.Ops.Control_flow.t_ControlFlow
                                          (iimpl_951670863_ &
                                            Core.Result.t_Result
                                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                  Alloc.Alloc.t_Global) t_Error)
                                          (Prims.unit &
                                            (Alloc.Vec.t_Vec
                                                (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                Alloc.Alloc.t_Global &
                                              Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global)))
                                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                          Alloc.Alloc.t_Global &
                                        Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                          Alloc.Alloc.t_Global)
                                  else
                                    let zshares:Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                      Alloc.Alloc.t_Global =
                                      Rust_primitives.Hax.Monomorphized_update_at.update_at_usize zshares
                                        ll
                                        ({
                                            (zshares.[ ll ] <: Polytune.Data_types.t_Share) with
                                            Polytune.Data_types._1
                                            =
                                            {
                                              (zshares.[ ll ] <: Polytune.Data_types.t_Share)
                                                .Polytune.Data_types._1 with
                                              Polytune.Data_types._0
                                              =
                                              Rust_primitives.Hax.Monomorphized_update_at.update_at_usize
                                                (zshares.[ ll ] <: Polytune.Data_types.t_Share)
                                                  .Polytune.Data_types._1
                                                  .Polytune.Data_types._0
                                                j
                                                (mac, key
                                                  <:
                                                  (Polytune.Data_types.t_Mac &
                                                    Polytune.Data_types.t_Key))
                                              <:
                                              Alloc.Vec.t_Vec
                                                (Polytune.Data_types.t_Mac &
                                                  Polytune.Data_types.t_Key) Alloc.Alloc.t_Global
                                            }
                                            <:
                                            Polytune.Data_types.t_Auth
                                          }
                                          <:
                                          Polytune.Data_types.t_Share)
                                    in
                                    Core.Ops.Control_flow.ControlFlow_Continue
                                    (ki_xj_phi, zshares
                                      <:
                                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                          Alloc.Alloc.t_Global &
                                        Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                          Alloc.Alloc.t_Global))
                                    <:
                                    Core.Ops.Control_flow.t_ControlFlow
                                      (Core.Ops.Control_flow.t_ControlFlow
                                          (iimpl_951670863_ &
                                            Core.Result.t_Result
                                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                  Alloc.Alloc.t_Global) t_Error)
                                          (Prims.unit &
                                            (Alloc.Vec.t_Vec
                                                (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                Alloc.Alloc.t_Global &
                                              Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global)))
                                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                          Alloc.Alloc.t_Global &
                                        Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                          Alloc.Alloc.t_Global)
                                | Core.Result.Result_Err err ->
                                  Core.Ops.Control_flow.ControlFlow_Break
                                  (Core.Ops.Control_flow.ControlFlow_Break
                                    (channel,
                                      (Core.Result.Result_Err err
                                        <:
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global) t_Error)
                                      <:
                                      (iimpl_951670863_ &
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global) t_Error))
                                    <:
                                    Core.Ops.Control_flow.t_ControlFlow
                                      (iimpl_951670863_ &
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global) t_Error)
                                      (Prims.unit &
                                        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                            Alloc.Alloc.t_Global &
                                          Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                            Alloc.Alloc.t_Global)))
                                  <:
                                  Core.Ops.Control_flow.t_ControlFlow
                                    (Core.Ops.Control_flow.t_ControlFlow
                                        (iimpl_951670863_ &
                                          Core.Result.t_Result
                                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global) t_Error)
                                        (Prims.unit &
                                          (Alloc.Vec.t_Vec
                                              (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                              Alloc.Alloc.t_Global &
                                            Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global)))
                                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                        Alloc.Alloc.t_Global &
                                      Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                        Alloc.Alloc.t_Global))
                          <:
                          Core.Ops.Control_flow.t_ControlFlow
                            (iimpl_951670863_ &
                              Core.Result.t_Result
                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                                t_Error)
                            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                        with
                        | Core.Ops.Control_flow.ControlFlow_Break ret ->
                          Core.Ops.Control_flow.ControlFlow_Break
                          (Core.Ops.Control_flow.ControlFlow_Break ret
                            <:
                            Core.Ops.Control_flow.t_ControlFlow
                              (iimpl_951670863_ &
                                Core.Result.t_Result
                                  (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                                  t_Error)
                              (Prims.unit &
                                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                    Alloc.Alloc.t_Global &
                                  Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
                          )
                          <:
                          Core.Ops.Control_flow.t_ControlFlow
                            (Core.Ops.Control_flow.t_ControlFlow
                                (iimpl_951670863_ &
                                  Core.Result.t_Result
                                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                        Alloc.Alloc.t_Global) t_Error)
                                (Prims.unit &
                                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global &
                                    Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global
                                  )))
                            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                        | Core.Ops.Control_flow.ControlFlow_Continue loop_res ->
                          Core.Ops.Control_flow.ControlFlow_Continue loop_res
                          <:
                          Core.Ops.Control_flow.t_ControlFlow
                            (Core.Ops.Control_flow.t_ControlFlow
                                (iimpl_951670863_ &
                                  Core.Result.t_Result
                                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                        Alloc.Alloc.t_Global) t_Error)
                                (Prims.unit &
                                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global &
                                    Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global
                                  )))
                            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (iimpl_951670863_ &
                    Core.Result.t_Result
                      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) t_Error)
                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
              with
              | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
              | Core.Ops.Control_flow.ControlFlow_Continue (ki_xj_phi, zshares) ->
                let hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                  Alloc.Vec.from_elem #u128 (mk_u128 0) l
                in
                let commhi:Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global =
                  Alloc.Vec.impl__with_capacity #t_Commitment l
                in
                let commhi, hi:(Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) =
                  Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                    l
                    (fun temp_0_ temp_1_ ->
                        let commhi, hi:(Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) =
                          temp_0_
                        in
                        let _:usize = temp_1_ in
                        true)
                    (commhi, hi
                      <:
                      (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                    (fun temp_0_ ll ->
                        let commhi, hi:(Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) =
                          temp_0_
                        in
                        let ll:usize = ll in
                        let hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                          Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                            n
                            (fun hi temp_1_ ->
                                let hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = hi in
                                let _:usize = temp_1_ in
                                true)
                            hi
                            (fun hi k ->
                                let hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = hi in
                                let k:usize = k in
                                if k =. i <: bool
                                then hi
                                else
                                  let mk_zi, ki_zk:(Polytune.Data_types.t_Mac &
                                    Polytune.Data_types.t_Key) =
                                    (zshares.[ ll ] <: Polytune.Data_types.t_Share)
                                      .Polytune.Data_types._1
                                      .Polytune.Data_types._0.[ k ]
                                  in
                                  Rust_primitives.Hax.Monomorphized_update_at.update_at_usize hi
                                    ll
                                    ((((hi.[ ll ] <: u128) ^. mk_zi.Polytune.Data_types._0 <: u128) ^.
                                        ki_zk.Polytune.Data_types._0
                                        <:
                                        u128) ^.
                                      ((ki_xj_phi.[ k ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global
                                        ).[ ll ]
                                        <:
                                        u128)
                                      <:
                                      u128))
                        in
                        let hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                          Rust_primitives.Hax.Monomorphized_update_at.update_at_usize hi
                            ll
                            (((hi.[ ll ] <: u128) ^.
                                ((cast ((xshares.[ ll ] <: Polytune.Data_types.t_Share)
                                          .Polytune.Data_types._0
                                        <:
                                        bool)
                                    <:
                                    u128) *!
                                  (phi.[ ll ] <: u128)
                                  <:
                                  u128)
                                <:
                                u128) ^.
                              ((cast ((zshares.[ ll ] <: Polytune.Data_types.t_Share)
                                        .Polytune.Data_types._0
                                      <:
                                      bool)
                                  <:
                                  u128) *!
                                delta.Polytune.Data_types._0
                                <:
                                u128)
                              <:
                              u128)
                        in
                        let commhi:Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global =
                          Alloc.Vec.impl_1__push #t_Commitment
                            #Alloc.Alloc.t_Global
                            commhi
                            (commit (Core.Num.impl_u128__to_be_bytes (hi.[ ll ] <: u128)
                                  <:
                                  t_Slice u8)
                              <:
                              t_Commitment)
                        in
                        commhi, hi
                        <:
                        (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                in
                let tmp0, out:(iimpl_951670863_ &
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global) t_Error) =
                  broadcast #t_Commitment
                    #iimpl_951670863_
                    channel
                    i
                    n
                    "flaand comm"
                    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global)
                        #FStar.Tactics.Typeclasses.solve
                        commhi
                      <:
                      t_Slice t_Commitment)
                    l
                in
                let channel:iimpl_951670863_ = tmp0 in
                match
                  out
                  <:
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global) t_Error
                with
                | Core.Result.Result_Ok commhi_k ->
                  let tmp0, out:(iimpl_951670863_ &
                    Core.Result.t_Result
                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global) t_Error) =
                    broadcast #u128
                      #iimpl_951670863_
                      channel
                      i
                      n
                      "flaand hash"
                      (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          #FStar.Tactics.Typeclasses.solve
                          hi
                        <:
                        t_Slice u128)
                      l
                  in
                  let channel:iimpl_951670863_ = tmp0 in
                  (match
                      out
                      <:
                      Core.Result.t_Result
                        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global) t_Error
                    with
                    | Core.Result.Result_Ok hi_k_outer ->
                      let xor_all_hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = hi in
                      (match
                          Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
                            n
                            (fun xor_all_hi temp_1_ ->
                                let xor_all_hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                                  xor_all_hi
                                in
                                let _:usize = temp_1_ in
                                true)
                            xor_all_hi
                            (fun xor_all_hi k ->
                                let xor_all_hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                                  xor_all_hi
                                in
                                let k:usize = k in
                                if k =. i <: bool
                                then
                                  Core.Ops.Control_flow.ControlFlow_Continue xor_all_hi
                                  <:
                                  Core.Ops.Control_flow.t_ControlFlow
                                    (Core.Ops.Control_flow.t_ControlFlow
                                        (iimpl_951670863_ &
                                          Core.Result.t_Result
                                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global) t_Error)
                                        (Prims.unit & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                                    (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                else
                                  match
                                    Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
                                      (Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global xor_all_hi
                                        <:
                                        usize)
                                      (fun xor_all_hi temp_1_ ->
                                          let xor_all_hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                                            xor_all_hi
                                          in
                                          let _:usize = temp_1_ in
                                          true)
                                      xor_all_hi
                                      (fun xor_all_hi ll ->
                                          let xor_all_hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                                            xor_all_hi
                                          in
                                          let ll:usize = ll in
                                          if
                                            ~.(open_commitment ((commhi_k.[ k ]
                                                    <:
                                                    Alloc.Vec.t_Vec t_Commitment
                                                      Alloc.Alloc.t_Global).[ ll ]
                                                  <:
                                                  t_Commitment)
                                                (Core.Num.impl_u128__to_be_bytes ((hi_k_outer.[ k ]
                                                        <:
                                                        Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[
                                                        ll ]
                                                      <:
                                                      u128)
                                                  <:
                                                  t_Slice u8)
                                              <:
                                              bool)
                                            <:
                                            bool
                                          then
                                            Core.Ops.Control_flow.ControlFlow_Break
                                            (Core.Ops.Control_flow.ControlFlow_Break
                                              (channel,
                                                (Core.Result.Result_Err
                                                  (Error_CommitmentCouldNotBeOpened <: t_Error)
                                                  <:
                                                  Core.Result.t_Result
                                                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                        Alloc.Alloc.t_Global) t_Error)
                                                <:
                                                (iimpl_951670863_ &
                                                  Core.Result.t_Result
                                                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                        Alloc.Alloc.t_Global) t_Error))
                                              <:
                                              Core.Ops.Control_flow.t_ControlFlow
                                                (iimpl_951670863_ &
                                                  Core.Result.t_Result
                                                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                        Alloc.Alloc.t_Global) t_Error)
                                                (Prims.unit &
                                                  Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                                            <:
                                            Core.Ops.Control_flow.t_ControlFlow
                                              (Core.Ops.Control_flow.t_ControlFlow
                                                  (iimpl_951670863_ &
                                                    Core.Result.t_Result
                                                      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                          Alloc.Alloc.t_Global) t_Error)
                                                  (Prims.unit &
                                                    Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                                              (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                          else
                                            Core.Ops.Control_flow.ControlFlow_Continue
                                            (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize
                                                xor_all_hi
                                                ll
                                                ((xor_all_hi.[ ll ] <: u128) ^.
                                                  ((hi_k_outer.[ k ]
                                                      <:
                                                      Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ ll
                                                    ]
                                                    <:
                                                    u128)
                                                  <:
                                                  u128)
                                              <:
                                              Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                            <:
                                            Core.Ops.Control_flow.t_ControlFlow
                                              (Core.Ops.Control_flow.t_ControlFlow
                                                  (iimpl_951670863_ &
                                                    Core.Result.t_Result
                                                      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                          Alloc.Alloc.t_Global) t_Error)
                                                  (Prims.unit &
                                                    Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                                              (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                                    <:
                                    Core.Ops.Control_flow.t_ControlFlow
                                      (iimpl_951670863_ &
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global) t_Error)
                                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  with
                                  | Core.Ops.Control_flow.ControlFlow_Break ret ->
                                    Core.Ops.Control_flow.ControlFlow_Break
                                    (Core.Ops.Control_flow.ControlFlow_Break ret
                                      <:
                                      Core.Ops.Control_flow.t_ControlFlow
                                        (iimpl_951670863_ &
                                          Core.Result.t_Result
                                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global) t_Error)
                                        (Prims.unit & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                                    <:
                                    Core.Ops.Control_flow.t_ControlFlow
                                      (Core.Ops.Control_flow.t_ControlFlow
                                          (iimpl_951670863_ &
                                            Core.Result.t_Result
                                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                  Alloc.Alloc.t_Global) t_Error)
                                          (Prims.unit & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  | Core.Ops.Control_flow.ControlFlow_Continue loop_res ->
                                    Core.Ops.Control_flow.ControlFlow_Continue loop_res
                                    <:
                                    Core.Ops.Control_flow.t_ControlFlow
                                      (Core.Ops.Control_flow.t_ControlFlow
                                          (iimpl_951670863_ &
                                            Core.Result.t_Result
                                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                  Alloc.Alloc.t_Global) t_Error)
                                          (Prims.unit & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                          <:
                          Core.Ops.Control_flow.t_ControlFlow
                            (iimpl_951670863_ &
                              Core.Result.t_Result
                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                                t_Error) (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        with
                        | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
                        | Core.Ops.Control_flow.ControlFlow_Continue xor_all_hi ->
                          match
                            Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
                              l
                              (fun temp_0_ temp_1_ ->
                                  let _:Prims.unit = temp_0_ in
                                  let _:usize = temp_1_ in
                                  true)
                              ()
                              (fun temp_0_ i ->
                                  let _:Prims.unit = temp_0_ in
                                  let i:usize = i in
                                  if (xor_all_hi.[ i ] <: u128) <>. mk_u128 0 <: bool
                                  then
                                    Core.Ops.Control_flow.ControlFlow_Break
                                    (Core.Ops.Control_flow.ControlFlow_Break
                                      (channel,
                                        (Core.Result.Result_Err (Error_LaANDXorNotZero <: t_Error)
                                          <:
                                          Core.Result.t_Result
                                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global) t_Error)
                                        <:
                                        (iimpl_951670863_ &
                                          Core.Result.t_Result
                                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global) t_Error))
                                      <:
                                      Core.Ops.Control_flow.t_ControlFlow
                                        (iimpl_951670863_ &
                                          Core.Result.t_Result
                                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global) t_Error)
                                        (Prims.unit & Prims.unit))
                                    <:
                                    Core.Ops.Control_flow.t_ControlFlow
                                      (Core.Ops.Control_flow.t_ControlFlow
                                          (iimpl_951670863_ &
                                            Core.Result.t_Result
                                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                  Alloc.Alloc.t_Global) t_Error)
                                          (Prims.unit & Prims.unit)) Prims.unit
                                  else
                                    Core.Ops.Control_flow.ControlFlow_Continue ()
                                    <:
                                    Core.Ops.Control_flow.t_ControlFlow
                                      (Core.Ops.Control_flow.t_ControlFlow
                                          (iimpl_951670863_ &
                                            Core.Result.t_Result
                                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                  Alloc.Alloc.t_Global) t_Error)
                                          (Prims.unit & Prims.unit)) Prims.unit)
                            <:
                            Core.Ops.Control_flow.t_ControlFlow
                              (iimpl_951670863_ &
                                Core.Result.t_Result
                                  (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                                  t_Error) Prims.unit
                          with
                          | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
                          | Core.Ops.Control_flow.ControlFlow_Continue _ ->
                            let hax_temp_output:Core.Result.t_Result
                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                              t_Error =
                              Core.Result.Result_Ok zshares
                              <:
                              Core.Result.t_Result
                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                                t_Error
                            in
                            channel, hax_temp_output
                            <:
                            (iimpl_951670863_ &
                              Core.Result.t_Result
                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                                t_Error))
                    | Core.Result.Result_Err err ->
                      channel,
                      (Core.Result.Result_Err err
                        <:
                        Core.Result.t_Result
                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) t_Error
                      )
                      <:
                      (iimpl_951670863_ &
                        Core.Result.t_Result
                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) t_Error
                      ))
                | Core.Result.Result_Err err ->
                  channel,
                  (Core.Result.Result_Err err
                    <:
                    Core.Result.t_Result
                      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) t_Error)
                  <:
                  (iimpl_951670863_ &
                    Core.Result.t_Result
                      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) t_Error))
          | Core.Result.Result_Err err ->
            channel,
            (Core.Result.Result_Err err
              <:
              Core.Result.t_Result
                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) t_Error)
            <:
            (iimpl_951670863_ &
              Core.Result.t_Result
                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) t_Error))
    | Core.Result.Result_Err err ->
      channel,
      (Core.Result.Result_Err err
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
          t_Error)
      <:
      (iimpl_951670863_ &
        Core.Result.t_Result (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
          t_Error)
