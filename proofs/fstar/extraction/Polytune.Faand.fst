module Polytune.Faand
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Polytune.Channel in
  let open Rand_chacha.Chacha in
  let open Serde.De in
  let open Serde.De.Impls in
  let open Serde.Ser in
  let open Serde.Ser.Impls in
  ()

/// The statistical security parameter `RHO` used for cryptographic operations.
let v_RHO: usize = mk_usize 40

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

/// Converts an `ot::Error` into a custom `Error` type.
[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1: Core.Convert.t_From t_Error Polytune.Swankyot.t_Error =
  {
    f_from_pre = (fun (e: Polytune.Swankyot.t_Error) -> true);
    f_from_post = (fun (e: Polytune.Swankyot.t_Error) (out: t_Error) -> true);
    f_from = fun (e: Polytune.Swankyot.t_Error) -> Error_OtErr e <: t_Error
  }

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

/// Multi-party coin tossing to generate shared randomness in a secure, distributed manner.
/// This function generates a shared random number generator (RNG) using multi-party
/// coin tossing in a secure multi-party computation (MPC) setting. Each participant contributes
/// to the randomness generation, and all contributions are combined securely to generate
/// a final shared random seed. This shared seed is then used to create a `ChaCha20Rng`, a
/// cryptographically secure random number generator.
assume
val shared_rng':
    #iimpl_951670863_: Type0 ->
    {| i1: Polytune.Channel.t_Channel iimpl_951670863_ |} ->
    channel: iimpl_951670863_ ->
    i: usize ->
    n: usize
  -> (iimpl_951670863_ & Core.Result.t_Result Rand_chacha.Chacha.t_ChaCha20Rng t_Error)

unfold
let shared_rng
      (#iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Polytune.Channel.t_Channel iimpl_951670863_)
     = shared_rng' #iimpl_951670863_ #i1

assume
val zero_rng': Prims.unit -> Rand_chacha.Chacha.t_ChaCha20Rng

unfold
let zero_rng = zero_rng'

assume
val random_bool': Prims.unit -> bool

unfold
let random_bool = random_bool'

assume
val rand_gen': rng: Rand_chacha.Chacha.t_ChaCha20Rng -> (Rand_chacha.Chacha.t_ChaCha20Rng & bool)

unfold
let rand_gen = rand_gen'

assume
val drop_func': #v_T: Type0 -> vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global -> Prims.unit

unfold
let drop_func (#v_T: Type0) = drop_func' #v_T

/// Protocol PI_aBit^n that performs F_aBit^n from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
/// This function implements a secure multi-party computation protocol to generate a random
/// bit-string and the corresponding keys and MACs (the latter are sent to the other parties),
/// i.e., shares of random authenticated bits.
/// The two main steps of the protocol are running two-party oblivious transfers (OTs) for
/// each pair of parties and then checking the validity of the MACs and keys by checking the XOR
/// of a linear combination of the bits, keys and the MACs and then removing 2 * RHO objects,
/// where RHO is the statistical security parameter.
let fabitn
      (#iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Polytune.Channel.t_Channel iimpl_951670863_)
      (channel: iimpl_951670863_)
      (delta: Polytune.Data_types.t_Delta)
      (i n l: usize)
      (shared_two_by_two: Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)
    : Prims.Pure
      (iimpl_951670863_ &
        Core.Result.t_Result
          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
      (requires l <=. (Core.Num.impl_usize__MAX -! (mk_usize 3 *! v_RHO <: usize) <: usize))
      (fun _ -> Prims.l_True) =
  let three_rho:usize = mk_usize 3 *! v_RHO in
  let lprime:usize = l +! three_rho in
  let (x: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global):Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
    Core.Iter.Traits.Iterator.f_collect #(Core.Iter.Adapters.Map.t_Map
          (Core.Ops.Range.t_Range usize) (usize -> bool))
      #FStar.Tactics.Typeclasses.solve
      #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
      (Core.Iter.Traits.Iterator.f_map #(Core.Ops.Range.t_Range usize)
          #FStar.Tactics.Typeclasses.solve
          #bool
          ({ Core.Ops.Range.f_start = mk_usize 0; Core.Ops.Range.f_end = lprime }
            <:
            Core.Ops.Range.t_Range usize)
          (fun temp_0_ ->
              let _:usize = temp_0_ in
              random_bool () <: bool)
        <:
        Core.Iter.Adapters.Map.t_Map (Core.Ops.Range.t_Range usize) (usize -> bool))
  in
  let keys:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
      (Alloc.Vec.from_elem #u128 (mk_u128 0) lprime <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
      n
  in
  let macs:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
      (Alloc.Vec.from_elem #u128 (mk_u128 0) lprime <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
      n
  in
  if
    ~.((Alloc.Vec.impl_1__len #Rand_chacha.Chacha.t_ChaCha20Rng
          #Alloc.Alloc.t_Global
          shared_two_by_two
        <:
        usize) =.
      n
      <:
      bool)
  then
    channel,
    (Core.Result.Result_Err (Error_InvalidLength <: t_Error)
      <:
      Core.Result.t_Result
        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
    <:
    (iimpl_951670863_ &
      Core.Result.t_Result
        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
  else
    let (shared_rand: Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global):Alloc.Vec.t_Vec
      Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global =
      Alloc.Vec.from_elem #Rand_chacha.Chacha.t_ChaCha20Rng
        (zero_rng () <: Rand_chacha.Chacha.t_ChaCha20Rng)
        n
    in
    match
      Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
        n
        (fun temp_0_ temp_1_ ->
            let channel, keys, macs, shared_rand:(iimpl_951670863_ &
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global) =
              temp_0_
            in
            let _:usize = temp_1_ in
            b2t
            ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                  #Alloc.Alloc.t_Global
                  keys
                <:
                usize) =.
              n
              <:
              bool) /\
            (forall (j: usize).
                b2t
                ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
                  ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        #Alloc.Alloc.t_Global
                        keys
                      <:
                      usize) =.
                    n
                    <:
                    bool)) ==>
                b2t
                ((Alloc.Vec.impl_1__len #u128
                      #Alloc.Alloc.t_Global
                      (keys.[ j ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                    <:
                    usize) =.
                  l
                  <:
                  bool)) /\
            b2t
            ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                  #Alloc.Alloc.t_Global
                  macs
                <:
                usize) =.
              n
              <:
              bool) /\
            (forall (j: usize).
                b2t
                ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
                  ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        #Alloc.Alloc.t_Global
                        macs
                      <:
                      usize) =.
                    n
                    <:
                    bool)) ==>
                b2t
                ((Alloc.Vec.impl_1__len #u128
                      #Alloc.Alloc.t_Global
                      (macs.[ j ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                    <:
                    usize) =.
                  l
                  <:
                  bool)))
        (channel, keys, macs, shared_rand
          <:
          (iimpl_951670863_ &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global))
        (fun temp_0_ k ->
            let channel, keys, macs, shared_rand:(iimpl_951670863_ &
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global) =
              temp_0_
            in
            let k:usize = k in
            if k =. i <: bool
            then
              Core.Ops.Control_flow.ControlFlow_Continue
              (channel, keys, macs, shared_rand
                <:
                (iimpl_951670863_ &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global))
              <:
              Core.Ops.Control_flow.t_ControlFlow
                (Core.Ops.Control_flow.t_ControlFlow
                    (iimpl_951670863_ &
                      Core.Result.t_Result
                        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                    (Prims.unit &
                      (iimpl_951670863_ &
                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)))
                (iimpl_951670863_ &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)
            else
              let shared:Rand_chacha.Chacha.t_ChaCha20Rng = shared_two_by_two.[ k ] in
              if i <. k
              then
                let tmp0, out:(iimpl_951670863_ &
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global & Rand_chacha.Chacha.t_ChaCha20Rng)
                    Polytune.Swankyot.t_Error) =
                  Polytune.Ot.kos_ot_sender #iimpl_951670863_
                    channel
                    delta.Polytune.Data_types._0
                    lprime
                    k
                    shared
                in
                let channel:iimpl_951670863_ = tmp0 in
                match
                  out
                  <:
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global & Rand_chacha.Chacha.t_ChaCha20Rng)
                    Polytune.Swankyot.t_Error
                with
                | Core.Result.Result_Ok (lhs, lhs_1_) ->
                  let keys:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize keys k lhs
                  in
                  let shared_rand:Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng
                    Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize shared_rand k lhs_1_
                  in
                  let _:Prims.unit = () in
                  let tmp0, out:(iimpl_951670863_ &
                    Core.Result.t_Result
                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global & Rand_chacha.Chacha.t_ChaCha20Rng)
                      Polytune.Swankyot.t_Error) =
                    Polytune.Ot.kos_ot_receiver #iimpl_951670863_
                      channel
                      (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                          #FStar.Tactics.Typeclasses.solve
                          x
                        <:
                        t_Slice bool)
                      k
                      shared
                  in
                  let channel:iimpl_951670863_ = tmp0 in
                  (match
                      out
                      <:
                      Core.Result.t_Result
                        (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
                          Rand_chacha.Chacha.t_ChaCha20Rng) Polytune.Swankyot.t_Error
                    with
                    | Core.Result.Result_Ok (lhs, lhs_2_) ->
                      let macs:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize macs k lhs
                      in
                      let shared_rand:Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng
                        Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize shared_rand
                          k
                          lhs_2_
                      in
                      let _:Prims.unit = () in
                      Core.Ops.Control_flow.ControlFlow_Continue
                      (channel, keys, macs, shared_rand
                        <:
                        (iimpl_951670863_ &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Ops.Control_flow.t_ControlFlow
                            (iimpl_951670863_ &
                              Core.Result.t_Result
                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                  Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                            (Prims.unit &
                              (iimpl_951670863_ &
                                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global &
                                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global &
                                Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng
                                  Alloc.Alloc.t_Global)))
                        (iimpl_951670863_ &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)
                    | Core.Result.Result_Err err ->
                      Core.Ops.Control_flow.ControlFlow_Break
                      (Core.Ops.Control_flow.ControlFlow_Break
                        (channel,
                          (Core.Result.Result_Err
                            (Core.Convert.f_from #t_Error
                                #Polytune.Swankyot.t_Error
                                #FStar.Tactics.Typeclasses.solve
                                err)
                            <:
                            Core.Result.t_Result
                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                          <:
                          (iimpl_951670863_ &
                            Core.Result.t_Result
                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                Rand_chacha.Chacha.t_ChaCha20Rng) t_Error))
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (iimpl_951670863_ &
                            Core.Result.t_Result
                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                          (Prims.unit &
                            (iimpl_951670863_ &
                              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)
                          ))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Ops.Control_flow.t_ControlFlow
                            (iimpl_951670863_ &
                              Core.Result.t_Result
                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                  Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                            (Prims.unit &
                              (iimpl_951670863_ &
                                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global &
                                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global &
                                Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng
                                  Alloc.Alloc.t_Global)))
                        (iimpl_951670863_ &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global))
                | Core.Result.Result_Err err ->
                  Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Ops.Control_flow.ControlFlow_Break
                    (channel,
                      (Core.Result.Result_Err
                        (Core.Convert.f_from #t_Error
                            #Polytune.Swankyot.t_Error
                            #FStar.Tactics.Typeclasses.solve
                            err)
                        <:
                        Core.Result.t_Result
                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                      <:
                      (iimpl_951670863_ &
                        Core.Result.t_Result
                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (iimpl_951670863_ &
                        Core.Result.t_Result
                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                      (Prims.unit &
                        (iimpl_951670863_ &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Ops.Control_flow.t_ControlFlow
                        (iimpl_951670863_ &
                          Core.Result.t_Result
                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                              Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                        (Prims.unit &
                          (iimpl_951670863_ &
                            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)))
                    (iimpl_951670863_ &
                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)
              else
                let tmp0, out:(iimpl_951670863_ &
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global & Rand_chacha.Chacha.t_ChaCha20Rng)
                    Polytune.Swankyot.t_Error) =
                  Polytune.Ot.kos_ot_receiver #iimpl_951670863_
                    channel
                    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                        #FStar.Tactics.Typeclasses.solve
                        x
                      <:
                      t_Slice bool)
                    k
                    shared
                in
                let channel:iimpl_951670863_ = tmp0 in
                match
                  out
                  <:
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global & Rand_chacha.Chacha.t_ChaCha20Rng)
                    Polytune.Swankyot.t_Error
                with
                | Core.Result.Result_Ok (lhs, lhs_3_) ->
                  let macs:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize macs k lhs
                  in
                  let shared_rand:Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng
                    Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize shared_rand k lhs_3_
                  in
                  let _:Prims.unit = () in
                  let tmp0, out:(iimpl_951670863_ &
                    Core.Result.t_Result
                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global & Rand_chacha.Chacha.t_ChaCha20Rng)
                      Polytune.Swankyot.t_Error) =
                    Polytune.Ot.kos_ot_sender #iimpl_951670863_
                      channel
                      delta.Polytune.Data_types._0
                      lprime
                      k
                      shared
                  in
                  let channel:iimpl_951670863_ = tmp0 in
                  (match
                      out
                      <:
                      Core.Result.t_Result
                        (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
                          Rand_chacha.Chacha.t_ChaCha20Rng) Polytune.Swankyot.t_Error
                    with
                    | Core.Result.Result_Ok (lhs, lhs_4_) ->
                      let keys:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize keys k lhs
                      in
                      let shared_rand:Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng
                        Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize shared_rand
                          k
                          lhs_4_
                      in
                      let _:Prims.unit = () in
                      Core.Ops.Control_flow.ControlFlow_Continue
                      (channel, keys, macs, shared_rand
                        <:
                        (iimpl_951670863_ &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Ops.Control_flow.t_ControlFlow
                            (iimpl_951670863_ &
                              Core.Result.t_Result
                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                  Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                            (Prims.unit &
                              (iimpl_951670863_ &
                                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global &
                                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global &
                                Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng
                                  Alloc.Alloc.t_Global)))
                        (iimpl_951670863_ &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)
                    | Core.Result.Result_Err err ->
                      Core.Ops.Control_flow.ControlFlow_Break
                      (Core.Ops.Control_flow.ControlFlow_Break
                        (channel,
                          (Core.Result.Result_Err
                            (Core.Convert.f_from #t_Error
                                #Polytune.Swankyot.t_Error
                                #FStar.Tactics.Typeclasses.solve
                                err)
                            <:
                            Core.Result.t_Result
                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                          <:
                          (iimpl_951670863_ &
                            Core.Result.t_Result
                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                Rand_chacha.Chacha.t_ChaCha20Rng) t_Error))
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (iimpl_951670863_ &
                            Core.Result.t_Result
                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                          (Prims.unit &
                            (iimpl_951670863_ &
                              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)
                          ))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Ops.Control_flow.t_ControlFlow
                            (iimpl_951670863_ &
                              Core.Result.t_Result
                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                  Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                            (Prims.unit &
                              (iimpl_951670863_ &
                                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global &
                                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  Alloc.Alloc.t_Global &
                                Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng
                                  Alloc.Alloc.t_Global)))
                        (iimpl_951670863_ &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global))
                | Core.Result.Result_Err err ->
                  Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Ops.Control_flow.ControlFlow_Break
                    (channel,
                      (Core.Result.Result_Err
                        (Core.Convert.f_from #t_Error
                            #Polytune.Swankyot.t_Error
                            #FStar.Tactics.Typeclasses.solve
                            err)
                        <:
                        Core.Result.t_Result
                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                      <:
                      (iimpl_951670863_ &
                        Core.Result.t_Result
                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (iimpl_951670863_ &
                        Core.Result.t_Result
                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                      (Prims.unit &
                        (iimpl_951670863_ &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Ops.Control_flow.t_ControlFlow
                        (iimpl_951670863_ &
                          Core.Result.t_Result
                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                              Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                        (Prims.unit &
                          (iimpl_951670863_ &
                            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)))
                    (iimpl_951670863_ &
                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global))
      <:
      Core.Ops.Control_flow.t_ControlFlow
        (iimpl_951670863_ &
          Core.Result.t_Result
            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
              Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
        (iimpl_951670863_ &
          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)
    with
    | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
    | Core.Ops.Control_flow.ControlFlow_Continue (channel, keys, macs, shared_rand) ->
      let tmp0, out:(iimpl_951670863_ &
        Core.Result.t_Result Rand_chacha.Chacha.t_ChaCha20Rng t_Error) =
        shared_rng #iimpl_951670863_ channel i n
      in
      let channel:iimpl_951670863_ = tmp0 in
      match out <: Core.Result.t_Result Rand_chacha.Chacha.t_ChaCha20Rng t_Error with
      | Core.Result.Result_Ok multi_shared_rand ->
        let r:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
          Alloc.Vec.impl__with_capacity #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) three_rho
        in
        let multi_shared_rand, r:(Rand_chacha.Chacha.t_ChaCha20Rng &
          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
          Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
            three_rho
            (fun temp_0_ temp_1_ ->
                let multi_shared_rand, r:(Rand_chacha.Chacha.t_ChaCha20Rng &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                =
                  temp_0_
                in
                let _:usize = temp_1_ in
                true)
            (multi_shared_rand, r
              <:
              (Rand_chacha.Chacha.t_ChaCha20Rng &
                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global))
            (fun temp_0_ temp_1_ ->
                let multi_shared_rand, r:(Rand_chacha.Chacha.t_ChaCha20Rng &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                =
                  temp_0_
                in
                let _:usize = temp_1_ in
                let inner:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
                  Alloc.Vec.impl__with_capacity #bool lprime
                in
                let inner, multi_shared_rand:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
                  Rand_chacha.Chacha.t_ChaCha20Rng) =
                  Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                    lprime
                    (fun temp_0_ temp_1_ ->
                        let inner, multi_shared_rand:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
                          Rand_chacha.Chacha.t_ChaCha20Rng) =
                          temp_0_
                        in
                        let _:usize = temp_1_ in
                        true)
                    (inner, multi_shared_rand
                      <:
                      (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global & Rand_chacha.Chacha.t_ChaCha20Rng)
                    )
                    (fun temp_0_ temp_1_ ->
                        let inner, multi_shared_rand:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
                          Rand_chacha.Chacha.t_ChaCha20Rng) =
                          temp_0_
                        in
                        let _:usize = temp_1_ in
                        let tmp0, out:(Rand_chacha.Chacha.t_ChaCha20Rng & bool) =
                          rand_gen multi_shared_rand
                        in
                        let multi_shared_rand:Rand_chacha.Chacha.t_ChaCha20Rng = tmp0 in
                        Alloc.Vec.impl_1__push #bool #Alloc.Alloc.t_Global inner out,
                        multi_shared_rand
                        <:
                        (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
                          Rand_chacha.Chacha.t_ChaCha20Rng))
                in
                let r:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global =
                  Alloc.Vec.impl_1__push #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                    #Alloc.Alloc.t_Global
                    r
                    inner
                in
                multi_shared_rand, r
                <:
                (Rand_chacha.Chacha.t_ChaCha20Rng &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global))
        in
        let xj:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
          Alloc.Vec.impl__with_capacity #bool three_rho
        in
        let xj:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
          Core.Iter.Traits.Iterator.f_fold (Core.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec
                    (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                r
              <:
              Core.Slice.Iter.t_Iter (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
            xj
            (fun xj rbits ->
                let xj:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = xj in
                let rbits:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = rbits in
                let xm:bool = false in
                let xm:bool =
                  Core.Iter.Traits.Iterator.f_fold (Core.Iter.Traits.Collect.f_into_iter #(Core.Iter.Adapters.Zip.t_Zip
                            (Core.Slice.Iter.t_Iter bool) (Core.Slice.Iter.t_Iter bool))
                        #FStar.Tactics.Typeclasses.solve
                        (Core.Iter.Traits.Iterator.f_zip #(Core.Slice.Iter.t_Iter bool)
                            #FStar.Tactics.Typeclasses.solve
                            #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                            (Core.Slice.impl__iter #bool
                                (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                                    #FStar.Tactics.Typeclasses.solve
                                    x
                                  <:
                                  t_Slice bool)
                              <:
                              Core.Slice.Iter.t_Iter bool)
                            rbits
                          <:
                          Core.Iter.Adapters.Zip.t_Zip (Core.Slice.Iter.t_Iter bool)
                            (Core.Slice.Iter.t_Iter bool))
                      <:
                      Core.Iter.Adapters.Zip.t_Zip (Core.Slice.Iter.t_Iter bool)
                        (Core.Slice.Iter.t_Iter bool))
                    xm
                    (fun xm temp_1_ ->
                        let xm:bool = xm in
                        let xi, ri:(bool & bool) = temp_1_ in
                        Core.Ops.Bit.f_bitxor xm
                          (Core.Ops.Bit.f_bitand #bool #bool #FStar.Tactics.Typeclasses.solve xi ri
                            <:
                            bool)
                        <:
                        bool)
                in
                let xj:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
                  Alloc.Vec.impl_1__push #bool #Alloc.Alloc.t_Global xj xm
                in
                xj)
        in
        let xj_xjmac:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
          Alloc.Alloc.t_Global =
          Alloc.Vec.from_elem #(Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
            (Alloc.Vec.impl__new #(bool & u128) ()
              <:
              Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
            n
        in
        let xj_xjmac:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
          Alloc.Alloc.t_Global =
          Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
            n
            (fun xj_xjmac temp_1_ ->
                let xj_xjmac:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global =
                  xj_xjmac
                in
                let _:usize = temp_1_ in
                true)
            xj_xjmac
            (fun xj_xjmac k ->
                let xj_xjmac:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global =
                  xj_xjmac
                in
                let k:usize = k in
                if k =. i <: bool
                then xj_xjmac
                else
                  Core.Iter.Traits.Iterator.f_fold (Core.Iter.Traits.Collect.f_into_iter #(Core.Iter.Adapters.Zip.t_Zip
                            (Core.Slice.Iter.t_Iter (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                            (Core.Slice.Iter.t_Iter bool))
                        #FStar.Tactics.Typeclasses.solve
                        (Core.Iter.Traits.Iterator.f_zip #(Core.Slice.Iter.t_Iter
                              (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                            #FStar.Tactics.Typeclasses.solve
                            #(Core.Slice.Iter.t_Iter bool)
                            (Core.Slice.impl__iter #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                                (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                                        (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                                        Alloc.Alloc.t_Global)
                                    #FStar.Tactics.Typeclasses.solve
                                    r
                                  <:
                                  t_Slice (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                              <:
                              Core.Slice.Iter.t_Iter (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                            (Core.Slice.impl__iter #bool
                                (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                                    #FStar.Tactics.Typeclasses.solve
                                    xj
                                  <:
                                  t_Slice bool)
                              <:
                              Core.Slice.Iter.t_Iter bool)
                          <:
                          Core.Iter.Adapters.Zip.t_Zip
                            (Core.Slice.Iter.t_Iter (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                            (Core.Slice.Iter.t_Iter bool))
                      <:
                      Core.Iter.Adapters.Zip.t_Zip
                        (Core.Slice.Iter.t_Iter (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                        (Core.Slice.Iter.t_Iter bool))
                    xj_xjmac
                    (fun xj_xjmac temp_1_ ->
                        let xj_xjmac:Alloc.Vec.t_Vec
                          (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global
                        =
                          xj_xjmac
                        in
                        let rbits, xj:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global & bool) =
                          temp_1_
                        in
                        let xjmac:u128 = mk_u128 0 in
                        let xjmac:u128 =
                          Rust_primitives.Hax.Folds.fold_enumerated_slice (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                                    bool Alloc.Alloc.t_Global)
                                #FStar.Tactics.Typeclasses.solve
                                rbits
                              <:
                              t_Slice bool)
                            (fun xjmac temp_1_ ->
                                let xjmac:u128 = xjmac in
                                let _:usize = temp_1_ in
                                true)
                            xjmac
                            (fun xjmac temp_1_ ->
                                let xjmac:u128 = xjmac in
                                let j, rbit:(usize & bool) = temp_1_ in
                                if rbit
                                then
                                  let xjmac:u128 =
                                    xjmac ^.
                                    ((macs.[ k ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ j ]
                                      <:
                                      u128)
                                  in
                                  xjmac
                                else xjmac)
                        in
                        let xj_xjmac:Alloc.Vec.t_Vec
                          (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global
                        =
                          Rust_primitives.Hax.Monomorphized_update_at.update_at_usize xj_xjmac
                            k
                            (Alloc.Vec.impl_1__push #(bool & u128)
                                #Alloc.Alloc.t_Global
                                (xj_xjmac.[ k ]
                                  <:
                                  Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                                (xj, xjmac <: (bool & u128))
                              <:
                              Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                        in
                        xj_xjmac)
                  <:
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global)
        in
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
            "fabitn"
            (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                    (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                xj_xjmac
              <:
              t_Slice (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global))
            three_rho
        in
        let channel:iimpl_951670863_ = tmp0 in
        (match
            out
            <:
            Core.Result.t_Result
              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global) t_Error
          with
          | Core.Result.Result_Ok xj_xjmac_k ->
            (match
                Rust_primitives.Hax.Folds.fold_enumerated_slice_return (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                          (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                      #FStar.Tactics.Typeclasses.solve
                      r
                    <:
                    t_Slice (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
                  (fun temp_0_ temp_1_ ->
                      let _:Prims.unit = temp_0_ in
                      let _:usize = temp_1_ in
                      true)
                  ()
                  (fun temp_0_ temp_1_ ->
                      let _:Prims.unit = temp_0_ in
                      let j, rbits:(usize & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) = temp_1_ in
                      match
                        Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
                          n
                          (fun temp_0_ temp_1_ ->
                              let _:Prims.unit = temp_0_ in
                              let _:usize = temp_1_ in
                              true)
                          ()
                          (fun temp_0_ k ->
                              let _:Prims.unit = temp_0_ in
                              let k:usize = k in
                              if k =. i <: bool
                              then
                                Core.Ops.Control_flow.ControlFlow_Continue (() <: Prims.unit)
                                <:
                                Core.Ops.Control_flow.t_ControlFlow
                                  (Core.Ops.Control_flow.t_ControlFlow
                                      (iimpl_951670863_ &
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global &
                                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                      (Prims.unit & Prims.unit)) Prims.unit
                              else
                                let xj, xjmac:(bool & u128) =
                                  (xj_xjmac_k.[ k ]
                                    <:
                                    Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global).[ j ]
                                in
                                let xjkey:u128 = mk_u128 0 in
                                let xjkey:u128 =
                                  Rust_primitives.Hax.Folds.fold_enumerated_slice (Core.Ops.Deref.f_deref
                                        #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
                                        #FStar.Tactics.Typeclasses.solve
                                        rbits
                                      <:
                                      t_Slice bool)
                                    (fun xjkey temp_1_ ->
                                        let xjkey:u128 = xjkey in
                                        let _:usize = temp_1_ in
                                        true)
                                    xjkey
                                    (fun xjkey temp_1_ ->
                                        let xjkey:u128 = xjkey in
                                        let i, rbit:(usize & bool) = temp_1_ in
                                        if rbit
                                        then
                                          let xjkey:u128 =
                                            xjkey ^.
                                            ((keys.[ k ]
                                                <:
                                                Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ i ]
                                              <:
                                              u128)
                                          in
                                          xjkey
                                        else xjkey)
                                in
                                if
                                  xj && xjmac <>. (xjkey ^. delta.Polytune.Data_types._0 <: u128) ||
                                  ~.xj && xjmac <>. xjkey
                                then
                                  Core.Ops.Control_flow.ControlFlow_Break
                                  (Core.Ops.Control_flow.ControlFlow_Break
                                    (channel,
                                      (Core.Result.Result_Err (Error_ABitWrongMAC <: t_Error)
                                        <:
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global &
                                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                      <:
                                      (iimpl_951670863_ &
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global &
                                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error))
                                    <:
                                    Core.Ops.Control_flow.t_ControlFlow
                                      (iimpl_951670863_ &
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global &
                                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                      (Prims.unit & Prims.unit))
                                  <:
                                  Core.Ops.Control_flow.t_ControlFlow
                                    (Core.Ops.Control_flow.t_ControlFlow
                                        (iimpl_951670863_ &
                                          Core.Result.t_Result
                                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global &
                                              Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                        (Prims.unit & Prims.unit)) Prims.unit
                                else
                                  Core.Ops.Control_flow.ControlFlow_Continue ()
                                  <:
                                  Core.Ops.Control_flow.t_ControlFlow
                                    (Core.Ops.Control_flow.t_ControlFlow
                                        (iimpl_951670863_ &
                                          Core.Result.t_Result
                                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global &
                                              Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                        (Prims.unit & Prims.unit)) Prims.unit)
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (iimpl_951670863_ &
                            Core.Result.t_Result
                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                Rand_chacha.Chacha.t_ChaCha20Rng) t_Error) Prims.unit
                      with
                      | Core.Ops.Control_flow.ControlFlow_Break ret ->
                        Core.Ops.Control_flow.ControlFlow_Break
                        (Core.Ops.Control_flow.ControlFlow_Break ret
                          <:
                          Core.Ops.Control_flow.t_ControlFlow
                            (iimpl_951670863_ &
                              Core.Result.t_Result
                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                  Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                            (Prims.unit & Prims.unit))
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (Core.Ops.Control_flow.t_ControlFlow
                              (iimpl_951670863_ &
                                Core.Result.t_Result
                                  (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                    Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                              (Prims.unit & Prims.unit)) Prims.unit
                      | Core.Ops.Control_flow.ControlFlow_Continue loop_res ->
                        Core.Ops.Control_flow.ControlFlow_Continue loop_res
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (Core.Ops.Control_flow.t_ControlFlow
                              (iimpl_951670863_ &
                                Core.Result.t_Result
                                  (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                    Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                              (Prims.unit & Prims.unit)) Prims.unit)
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (iimpl_951670863_ &
                    Core.Result.t_Result
                      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                        Rand_chacha.Chacha.t_ChaCha20Rng) t_Error) Prims.unit
              with
              | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
              | Core.Ops.Control_flow.ControlFlow_Continue _ ->
                let _:Prims.unit = drop_func #(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) r in
                let x:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
                  Alloc.Vec.impl_1__truncate #bool #Alloc.Alloc.t_Global x l
                in
                let keys, macs:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                =
                  Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                    n
                    (fun temp_0_ temp_1_ ->
                        let keys, macs:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global) =
                          temp_0_
                        in
                        let _:usize = temp_1_ in
                        true)
                    (keys, macs
                      <:
                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global))
                    (fun temp_0_ k ->
                        let keys, macs:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global) =
                          temp_0_
                        in
                        let k:usize = k in
                        if k =. i <: bool
                        then
                          keys, macs
                          <:
                          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global)
                        else
                          let keys:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global =
                            Rust_primitives.Hax.Monomorphized_update_at.update_at_usize keys
                              k
                              (Alloc.Vec.impl_1__truncate #u128
                                  #Alloc.Alloc.t_Global
                                  (keys.[ k ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  l
                                <:
                                Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          in
                          let macs:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global =
                            Rust_primitives.Hax.Monomorphized_update_at.update_at_usize macs
                              k
                              (Alloc.Vec.impl_1__truncate #u128
                                  #Alloc.Alloc.t_Global
                                  (macs.[ k ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                  l
                                <:
                                Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          in
                          keys, macs
                          <:
                          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              Alloc.Alloc.t_Global))
                in
                let res:Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global =
                  Alloc.Vec.impl__with_capacity #Polytune.Data_types.t_Share l
                in
                let res:Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global =
                  Core.Iter.Traits.Iterator.f_fold (Core.Iter.Traits.Collect.f_into_iter #(Core.Iter.Adapters.Take.t_Take
                          (Core.Iter.Adapters.Enumerate.t_Enumerate (Core.Slice.Iter.t_Iter bool)))
                        #FStar.Tactics.Typeclasses.solve
                        (Core.Iter.Traits.Iterator.f_take #(Core.Iter.Adapters.Enumerate.t_Enumerate
                              (Core.Slice.Iter.t_Iter bool))
                            #FStar.Tactics.Typeclasses.solve
                            (Core.Iter.Traits.Iterator.f_enumerate #(Core.Slice.Iter.t_Iter bool)
                                #FStar.Tactics.Typeclasses.solve
                                (Core.Slice.impl__iter #bool
                                    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec bool
                                            Alloc.Alloc.t_Global)
                                        #FStar.Tactics.Typeclasses.solve
                                        x
                                      <:
                                      t_Slice bool)
                                  <:
                                  Core.Slice.Iter.t_Iter bool)
                              <:
                              Core.Iter.Adapters.Enumerate.t_Enumerate (Core.Slice.Iter.t_Iter bool)
                            )
                            l
                          <:
                          Core.Iter.Adapters.Take.t_Take
                          (Core.Iter.Adapters.Enumerate.t_Enumerate (Core.Slice.Iter.t_Iter bool)))
                      <:
                      Core.Iter.Adapters.Take.t_Take
                      (Core.Iter.Adapters.Enumerate.t_Enumerate (Core.Slice.Iter.t_Iter bool)))
                    res
                    (fun res temp_1_ ->
                        let res:Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global =
                          res
                        in
                        let l, xi:(usize & bool) = temp_1_ in
                        let authvec:Alloc.Vec.t_Vec
                          (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                          Alloc.Alloc.t_Global =
                          Alloc.Vec.from_elem #(Polytune.Data_types.t_Mac &
                              Polytune.Data_types.t_Key)
                            ((Polytune.Data_types.Mac (mk_u128 0) <: Polytune.Data_types.t_Mac),
                              (Polytune.Data_types.Key (mk_u128 0) <: Polytune.Data_types.t_Key)
                              <:
                              (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key))
                            n
                        in
                        let authvec:Alloc.Vec.t_Vec
                          (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                          Alloc.Alloc.t_Global =
                          Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                            n
                            (fun authvec temp_1_ ->
                                let authvec:Alloc.Vec.t_Vec
                                  (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                                  Alloc.Alloc.t_Global =
                                  authvec
                                in
                                let _:usize = temp_1_ in
                                true)
                            authvec
                            (fun authvec k ->
                                let authvec:Alloc.Vec.t_Vec
                                  (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                                  Alloc.Alloc.t_Global =
                                  authvec
                                in
                                let k:usize = k in
                                if k =. i <: bool
                                then authvec
                                else
                                  Rust_primitives.Hax.Monomorphized_update_at.update_at_usize authvec
                                    k
                                    ((Polytune.Data_types.Mac
                                        ((macs.[ k ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[
                                            l ]
                                          <:
                                          u128)
                                        <:
                                        Polytune.Data_types.t_Mac),
                                      (Polytune.Data_types.Key
                                        ((keys.[ k ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[
                                            l ]
                                          <:
                                          u128)
                                        <:
                                        Polytune.Data_types.t_Key)
                                      <:
                                      (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key))
                                  <:
                                  Alloc.Vec.t_Vec
                                    (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                                    Alloc.Alloc.t_Global)
                        in
                        Alloc.Vec.impl_1__push #Polytune.Data_types.t_Share
                          #Alloc.Alloc.t_Global
                          res
                          (Polytune.Data_types.Share xi
                              (Polytune.Data_types.Auth authvec <: Polytune.Data_types.t_Auth)
                            <:
                            Polytune.Data_types.t_Share))
                in
                let hax_temp_output:Core.Result.t_Result
                  (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                    Rand_chacha.Chacha.t_ChaCha20Rng) t_Error =
                  Core.Result.Result_Ok
                  (res, multi_shared_rand
                    <:
                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                      Rand_chacha.Chacha.t_ChaCha20Rng))
                  <:
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                      Rand_chacha.Chacha.t_ChaCha20Rng) t_Error
                in
                channel, hax_temp_output
                <:
                (iimpl_951670863_ &
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                      Rand_chacha.Chacha.t_ChaCha20Rng) t_Error))
          | Core.Result.Result_Err err ->
            channel,
            (Core.Result.Result_Err err
              <:
              Core.Result.t_Result
                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                  Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
            <:
            (iimpl_951670863_ &
              Core.Result.t_Result
                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                  Rand_chacha.Chacha.t_ChaCha20Rng) t_Error))
      | Core.Result.Result_Err err ->
        channel,
        (Core.Result.Result_Err err
          <:
          Core.Result.t_Result
            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
              Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
        <:
        (iimpl_951670863_ &
          Core.Result.t_Result
            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
              Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
