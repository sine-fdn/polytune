module Polytune.Faand
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Polytune.Channel in
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
