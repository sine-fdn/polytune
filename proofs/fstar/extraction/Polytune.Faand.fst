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
  | Error_OTError : Polytune.Swankyot.t_Error -> t_Error

/// Represents a cryptographic commitment as a fixed-size 32-byte array (a BLAKE3 hash).
type t_Commitment = | Commitment : t_Array u8 (mk_usize 32) -> t_Commitment

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Core.Fmt.t_Debug t_Commitment

let impl_3 = impl_3'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val e___impl': Serde.Ser.t_Serialize t_Commitment

let e___impl = e___impl'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val e_ee_1__impl': Serde.De.t_Deserialize t_Commitment

let e_ee_1__impl = e_ee_1__impl'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Core.Cmp.t_PartialEq t_Commitment t_Commitment

let impl_7 = impl_7'

/// Commits to a value using the BLAKE3 cryptographic hash function.
/// This is not a general-purpose commitment scheme, the input value is assumed to have high entropy.
assume
val commit': value: t_Slice u8 -> t_Commitment

let commit = commit'

/// Verifies if a given value matches a previously generated commitment.
/// This is not a general-purpose commitment scheme, the input value is assumed to have high entropy.
assume
val open_commitment': commitment: t_Commitment -> value: t_Slice u8 -> bool

let open_commitment = open_commitment'

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

let broadcast
      (#v_T #iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Serde.Ser.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Serde.De.t_DeserializeOwned v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: Core.Fmt.t_Debug v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i6: Core.Cmp.t_PartialEq v_T v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i7: Polytune.Channel.t_Channel iimpl_951670863_)
     = broadcast' #v_T #iimpl_951670863_ #i2 #i3 #i4 #i5 #i6 #i7

/// Protocol PI_aBit^n that performs F_aBit^n from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
/// This function implements a secure multi-party computation protocol to generate a random
/// bit-string and the corresponding keys and MACs (the latter are sent to the other parties),
/// i.e., shares of random authenticated bits.
/// The two main steps of the protocol are running two-party oblivious transfers (OTs) for
/// each pair of parties and then checking the validity of the MACs and keys by checking the XOR
/// of a linear combination of the bits, keys and the MACs and then removing 2 * RHO objects,
/// where RHO is the statistical security parameter.
assume
val fabitn':
    #iimpl_951670863_: Type0 ->
    {| i1: Polytune.Channel.t_Channel iimpl_951670863_ |} ->
    channel: iimpl_951670863_ ->
    delta: Polytune.Data_types.t_Delta ->
    i: usize ->
    n: usize ->
    l: usize ->
    shared_two_by_two: Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global
  -> (iimpl_951670863_ &
      Core.Result.t_Result
        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)

let fabitn
      (#iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Polytune.Channel.t_Channel iimpl_951670863_)
     = fabitn' #iimpl_951670863_ #i1

/// Protocol PI_aShare that performs F_aShare from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
/// This protocol allows parties to generate and distribute authenticated random shares securely.
/// It consists of the following steps:
/// 1. **Random Bit String Generation**: Each party picks a random bit string of a specified length.
/// 2. **Autenticated Bit Generation**: The parties generate random authenticated bit shares.
/// 3. **Commitment and Verification**:
///    - The parties compute commitments based on a subset of their shares and broadcast these to ensure consistency.
///    - They then verify these commitments by performing decommitments and checking the validity of the
///      MACs against the commitments.
/// 4. **Return Shares**: Finally, the function returns the first `l` authenticated bit shares.
let fashare
      (#iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Polytune.Channel.t_Channel iimpl_951670863_)
      (channel: iimpl_951670863_)
      (delta: Polytune.Data_types.t_Delta)
      (i n l: usize)
      (shared_two_by_two: Alloc.Vec.t_Vec Rand_chacha.Chacha.t_ChaCha20Rng Alloc.Alloc.t_Global)
    : (iimpl_951670863_ &
      Core.Result.t_Result
        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error) =
  let tmp0, out:(iimpl_951670863_ &
    Core.Result.t_Result
      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
        Rand_chacha.Chacha.t_ChaCha20Rng) t_Error) =
    fabitn #iimpl_951670863_ channel delta i n (l +! v_RHO <: usize) shared_two_by_two
  in
  let channel:iimpl_951670863_ = tmp0 in
  match
    out
    <:
    Core.Result.t_Result
      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
        Rand_chacha.Chacha.t_ChaCha20Rng) t_Error
  with
  | Core.Result.Result_Ok (xishares, multi_shared_rand) ->
    let d0:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
      Alloc.Vec.from_elem #u128 (mk_u128 0) v_RHO
    in
    let d1:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
      Alloc.Vec.from_elem #u128 (mk_u128 0) v_RHO
    in
    let c0_c1_cm:Alloc.Vec.t_Vec (t_Commitment & t_Commitment & t_Commitment) Alloc.Alloc.t_Global =
      Alloc.Vec.impl__with_capacity #(t_Commitment & t_Commitment & t_Commitment) v_RHO
    in
    let dmvec:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
      Alloc.Vec.impl__with_capacity #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) v_RHO
    in
    let c0_c1_cm, d0, d1, dmvec:(Alloc.Vec.t_Vec (t_Commitment & t_Commitment & t_Commitment)
        Alloc.Alloc.t_Global &
      Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
      Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
      Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
        v_RHO
        (fun temp_0_ temp_1_ ->
            let c0_c1_cm, d0, d1, dmvec:(Alloc.Vec.t_Vec
                (t_Commitment & t_Commitment & t_Commitment) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
              temp_0_
            in
            let _:usize = temp_1_ in
            true)
        (c0_c1_cm, d0, d1, dmvec
          <:
          (Alloc.Vec.t_Vec (t_Commitment & t_Commitment & t_Commitment) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global))
        (fun temp_0_ r ->
            let c0_c1_cm, d0, d1, dmvec:(Alloc.Vec.t_Vec
                (t_Commitment & t_Commitment & t_Commitment) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
              temp_0_
            in
            let r:usize = r in
            let xishare:Polytune.Data_types.t_Share = xishares.[ l +! r <: usize ] in
            let dm:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
              Alloc.Vec.impl__with_capacity #u8 (n *! mk_usize 16 <: usize)
            in
            let dm:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
              Alloc.Vec.impl_1__push #u8
                #Alloc.Alloc.t_Global
                dm
                (cast (xishare.Polytune.Data_types._0 <: bool) <: u8)
            in
            let d0, dm:(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
              Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                n
                (fun temp_0_ temp_1_ ->
                    let d0, dm:(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                      temp_0_
                    in
                    let _:usize = temp_1_ in
                    true)
                (d0, dm
                  <:
                  (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
                (fun temp_0_ k ->
                    let d0, dm:(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                      temp_0_
                    in
                    let k:usize = k in
                    if k =. i <: bool
                    then
                      d0, dm
                      <:
                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    else
                      let mac, key:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
                        xishare.Polytune.Data_types._1.Polytune.Data_types._0.[ k ]
                      in
                      let d0:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize d0
                          r
                          (key.Polytune.Data_types._0 ^. (d0.[ r ] <: u128) <: u128)
                      in
                      let dm:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                        Core.Iter.Traits.Collect.f_extend #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                          #u8
                          #FStar.Tactics.Typeclasses.solve
                          #(t_Array u8 (mk_usize 16))
                          dm
                          (Core.Num.impl_u128__to_be_bytes mac.Polytune.Data_types._0
                            <:
                            t_Array u8 (mk_usize 16))
                      in
                      d0, dm
                      <:
                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
            in
            let d1:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
              Rust_primitives.Hax.Monomorphized_update_at.update_at_usize d1
                r
                ((d0.[ r ] <: u128) ^. delta.Polytune.Data_types._0 <: u128)
            in
            let c0:t_Commitment =
              commit (Core.Num.impl_u128__to_be_bytes (d0.[ r ] <: u128) <: t_Slice u8)
            in
            let c1:t_Commitment =
              commit (Core.Num.impl_u128__to_be_bytes (d1.[ r ] <: u128) <: t_Slice u8)
            in
            let cm:t_Commitment =
              commit (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    #FStar.Tactics.Typeclasses.solve
                    dm
                  <:
                  t_Slice u8)
            in
            let c0_c1_cm:Alloc.Vec.t_Vec (t_Commitment & t_Commitment & t_Commitment)
              Alloc.Alloc.t_Global =
              Alloc.Vec.impl_1__push #(t_Commitment & t_Commitment & t_Commitment)
                #Alloc.Alloc.t_Global
                c0_c1_cm
                (c0, c1, cm <: (t_Commitment & t_Commitment & t_Commitment))
            in
            let dmvec:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global
            =
              Alloc.Vec.impl_1__push #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #Alloc.Alloc.t_Global
                dmvec
                dm
            in
            c0_c1_cm, d0, d1, dmvec
            <:
            (Alloc.Vec.t_Vec (t_Commitment & t_Commitment & t_Commitment) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global))
    in
    let tmp0, out:(iimpl_951670863_ &
      Core.Result.t_Result
        (Alloc.Vec.t_Vec
            (Alloc.Vec.t_Vec (t_Commitment & t_Commitment & t_Commitment) Alloc.Alloc.t_Global)
            Alloc.Alloc.t_Global) t_Error) =
      broadcast #(t_Commitment & t_Commitment & t_Commitment)
        #iimpl_951670863_
        channel
        i
        n
        "fashare comm"
        (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec (t_Commitment & t_Commitment & t_Commitment)
                Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            c0_c1_cm
          <:
          t_Slice (t_Commitment & t_Commitment & t_Commitment))
        v_RHO
    in
    let channel:iimpl_951670863_ = tmp0 in
    (match
        out
        <:
        Core.Result.t_Result
          (Alloc.Vec.t_Vec
              (Alloc.Vec.t_Vec (t_Commitment & t_Commitment & t_Commitment) Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global) t_Error
      with
      | Core.Result.Result_Ok c0_c1_cm_k ->
        let c0_c1_cm_k:Alloc.Vec.t_Vec
          (Alloc.Vec.t_Vec (t_Commitment & t_Commitment & t_Commitment) Alloc.Alloc.t_Global)
          Alloc.Alloc.t_Global =
          Rust_primitives.Hax.Monomorphized_update_at.update_at_usize c0_c1_cm_k i c0_c1_cm
        in
        let tmp0, out:(iimpl_951670863_ &
          Core.Result.t_Result
            (Alloc.Vec.t_Vec
                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global) t_Error) =
          broadcast #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #iimpl_951670863_
            channel
            i
            n
            "fashare ver"
            (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                dmvec
              <:
              t_Slice (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
            v_RHO
        in
        let channel:iimpl_951670863_ = tmp0 in
        (match
            out
            <:
            Core.Result.t_Result
              (Alloc.Vec.t_Vec
                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global) t_Error
          with
          | Core.Result.Result_Ok dm_k ->
            let dm_k:Alloc.Vec.t_Vec
              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global =
              Rust_primitives.Hax.Monomorphized_update_at.update_at_usize dm_k i dmvec
            in
            let (bi: t_Array bool (mk_usize 40)):t_Array bool (mk_usize 40) =
              Rust_primitives.Hax.repeat false (mk_usize 40)
            in
            let di_bi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
              Alloc.Vec.from_elem #u128 (mk_u128 0) v_RHO
            in
            (match
                Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
                  v_RHO
                  (fun di_bi temp_1_ ->
                      let di_bi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = di_bi in
                      let _:usize = temp_1_ in
                      true)
                  di_bi
                  (fun di_bi r ->
                      let di_bi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = di_bi in
                      let r:usize = r in
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
                                if
                                  (((dm_k.[ k ]
                                        <:
                                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                          Alloc.Alloc.t_Global).[ r ]
                                      <:
                                      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global).[ mk_usize 0 ]
                                    <:
                                    u8) >.
                                  mk_u8 1
                                  <:
                                  bool
                                then
                                  Core.Ops.Control_flow.ControlFlow_Break
                                  (Core.Ops.Control_flow.ControlFlow_Break
                                    (channel,
                                      (Core.Result.Result_Err (Error_InvalidBitValue <: t_Error)
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
                                  let cond:bool =
                                    (((dm_k.[ k ]
                                          <:
                                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                            Alloc.Alloc.t_Global).[ r ]
                                        <:
                                        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global).[ mk_usize 0 ]
                                      <:
                                      u8) <>.
                                    mk_u8 0
                                  in
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
                            (Prims.unit & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (Core.Ops.Control_flow.t_ControlFlow
                              (iimpl_951670863_ &
                                Core.Result.t_Result
                                  (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                    Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                              (Prims.unit & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                          (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                      | Core.Ops.Control_flow.ControlFlow_Continue _ ->
                        Core.Ops.Control_flow.ControlFlow_Continue
                        (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize di_bi
                            r
                            (if bi.[ r ] <: bool then d1.[ r ] <: u128 else d0.[ r ] <: u128)
                          <:
                          Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (Core.Ops.Control_flow.t_ControlFlow
                              (iimpl_951670863_ &
                                Core.Result.t_Result
                                  (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                                    Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                              (Prims.unit & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                          (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (iimpl_951670863_ &
                    Core.Result.t_Result
                      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                        Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                  (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
              with
              | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
              | Core.Ops.Control_flow.ControlFlow_Continue di_bi ->
                let tmp0, out:(iimpl_951670863_ &
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global) t_Error) =
                  broadcast #u128
                    #iimpl_951670863_
                    channel
                    i
                    n
                    "fashare di_bi"
                    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        #FStar.Tactics.Typeclasses.solve
                        di_bi
                      <:
                      t_Slice u128)
                    v_RHO
                in
                let channel:iimpl_951670863_ = tmp0 in
                match
                  out
                  <:
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global) t_Error
                with
                | Core.Result.Result_Ok di_bi_k ->
                  let xor_xk_macs:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global =
                    Alloc.Vec.from_elem #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                      (Alloc.Vec.from_elem #u128 (mk_u128 0) v_RHO
                        <:
                        Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                      n
                  in
                  (match
                      Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
                        v_RHO
                        (fun xor_xk_macs temp_1_ ->
                            let xor_xk_macs:Alloc.Vec.t_Vec
                              (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
                              xor_xk_macs
                            in
                            let _:usize = temp_1_ in
                            true)
                        xor_xk_macs
                        (fun xor_xk_macs r ->
                            let xor_xk_macs:Alloc.Vec.t_Vec
                              (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
                              xor_xk_macs
                            in
                            let r:usize = r in
                            match
                              Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter
                                    #(Core.Iter.Adapters.Take.t_Take
                                      (Core.Iter.Adapters.Enumerate.t_Enumerate
                                        (Core.Slice.Iter.t_Iter
                                          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                              Alloc.Alloc.t_Global))))
                                    #FStar.Tactics.Typeclasses.solve
                                    (Core.Iter.Traits.Iterator.f_take #(Core.Iter.Adapters.Enumerate.t_Enumerate
                                          (Core.Slice.Iter.t_Iter
                                            (Alloc.Vec.t_Vec
                                                (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                                Alloc.Alloc.t_Global)))
                                        #FStar.Tactics.Typeclasses.solve
                                        (Core.Iter.Traits.Iterator.f_enumerate #(Core.Slice.Iter.t_Iter
                                              (Alloc.Vec.t_Vec
                                                  (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                                  Alloc.Alloc.t_Global))
                                            #FStar.Tactics.Typeclasses.solve
                                            (Core.Slice.impl__iter #(Alloc.Vec.t_Vec
                                                    (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                                    Alloc.Alloc.t_Global)
                                                (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                                                        (Alloc.Vec.t_Vec
                                                            (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
                                                            ) Alloc.Alloc.t_Global)
                                                        Alloc.Alloc.t_Global)
                                                    #FStar.Tactics.Typeclasses.solve
                                                    dm_k
                                                  <:
                                                  t_Slice
                                                  (Alloc.Vec.t_Vec
                                                      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                                      Alloc.Alloc.t_Global))
                                              <:
                                              Core.Slice.Iter.t_Iter
                                              (Alloc.Vec.t_Vec
                                                  (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                                  Alloc.Alloc.t_Global))
                                          <:
                                          Core.Iter.Adapters.Enumerate.t_Enumerate
                                          (Core.Slice.Iter.t_Iter
                                            (Alloc.Vec.t_Vec
                                                (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                                Alloc.Alloc.t_Global)))
                                        n
                                      <:
                                      Core.Iter.Adapters.Take.t_Take
                                      (Core.Iter.Adapters.Enumerate.t_Enumerate
                                        (Core.Slice.Iter.t_Iter
                                          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                              Alloc.Alloc.t_Global))))
                                  <:
                                  Core.Iter.Adapters.Take.t_Take
                                  (Core.Iter.Adapters.Enumerate.t_Enumerate
                                    (Core.Slice.Iter.t_Iter
                                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                          Alloc.Alloc.t_Global))))
                                xor_xk_macs
                                (fun xor_xk_macs temp_1_ ->
                                    let xor_xk_macs:Alloc.Vec.t_Vec
                                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global =
                                      xor_xk_macs
                                    in
                                    let k, dmv:(usize &
                                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                                        Alloc.Alloc.t_Global) =
                                      temp_1_
                                    in
                                    match
                                      Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
                                        n
                                        (fun xor_xk_macs temp_1_ ->
                                            let xor_xk_macs:Alloc.Vec.t_Vec
                                              (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                              Alloc.Alloc.t_Global =
                                              xor_xk_macs
                                            in
                                            let _:usize = temp_1_ in
                                            true)
                                        xor_xk_macs
                                        (fun xor_xk_macs kk ->
                                            let xor_xk_macs:Alloc.Vec.t_Vec
                                              (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                              Alloc.Alloc.t_Global =
                                              xor_xk_macs
                                            in
                                            let kk:usize = kk in
                                            if kk =. k <: bool
                                            then
                                              Core.Ops.Control_flow.ControlFlow_Continue xor_xk_macs
                                              <:
                                              Core.Ops.Control_flow.t_ControlFlow
                                                (Core.Ops.Control_flow.t_ControlFlow
                                                    (iimpl_951670863_ &
                                                      Core.Result.t_Result
                                                        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                            Alloc.Alloc.t_Global &
                                                          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                                    (Prims.unit &
                                                      Alloc.Vec.t_Vec
                                                        (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                        Alloc.Alloc.t_Global))
                                                (Alloc.Vec.t_Vec
                                                    (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                    Alloc.Alloc.t_Global)
                                            else
                                              if
                                                Alloc.Vec.impl_1__is_empty #(Alloc.Vec.t_Vec u8
                                                      Alloc.Alloc.t_Global)
                                                  #Alloc.Alloc.t_Global
                                                  dmv
                                                <:
                                                bool
                                              then
                                                Core.Ops.Control_flow.ControlFlow_Break
                                                (Core.Ops.Control_flow.ControlFlow_Break
                                                  (channel,
                                                    (Core.Result.Result_Err
                                                      (Error_EmptyVector <: t_Error)
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
                                                          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                                  )
                                                  <:
                                                  Core.Ops.Control_flow.t_ControlFlow
                                                    (iimpl_951670863_ &
                                                      Core.Result.t_Result
                                                        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                            Alloc.Alloc.t_Global &
                                                          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                                    (Prims.unit &
                                                      Alloc.Vec.t_Vec
                                                        (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                        Alloc.Alloc.t_Global))
                                                <:
                                                Core.Ops.Control_flow.t_ControlFlow
                                                  (Core.Ops.Control_flow.t_ControlFlow
                                                      (iimpl_951670863_ &
                                                        Core.Result.t_Result
                                                          (Alloc.Vec.t_Vec
                                                              Polytune.Data_types.t_Share
                                                              Alloc.Alloc.t_Global &
                                                            Rand_chacha.Chacha.t_ChaCha20Rng)
                                                          t_Error)
                                                      (Prims.unit &
                                                        Alloc.Vec.t_Vec
                                                          (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global
                                                          ) Alloc.Alloc.t_Global))
                                                  (Alloc.Vec.t_Vec
                                                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                      Alloc.Alloc.t_Global)
                                              else
                                                let dm:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                                                  dmv.[ r ]
                                                in
                                                let start:usize =
                                                  if kk >. k
                                                  then
                                                    mk_usize 1 +!
                                                    ((kk -! mk_usize 1 <: usize) *! mk_usize 16
                                                      <:
                                                      usize)
                                                  else mk_usize 1 +! (kk *! mk_usize 16 <: usize)
                                                in
                                                let v_end:usize = start +! mk_usize 16 in
                                                match
                                                  Core.Result.impl__map #(t_Array u8 (mk_usize 16))
                                                    #Core.Array.t_TryFromSliceError
                                                    #u128
                                                    (Core.Convert.f_try_into #(t_Slice u8)
                                                        #(t_Array u8 (mk_usize 16))
                                                        #FStar.Tactics.Typeclasses.solve
                                                        (dm.[ {
                                                              Core.Ops.Range.f_start = start;
                                                              Core.Ops.Range.f_end = v_end
                                                            }
                                                            <:
                                                            Core.Ops.Range.t_Range usize ]
                                                          <:
                                                          t_Slice u8)
                                                      <:
                                                      Core.Result.t_Result
                                                        (t_Array u8 (mk_usize 16))
                                                        Core.Array.t_TryFromSliceError)
                                                    Core.Num.impl_u128__from_be_bytes
                                                  <:
                                                  Core.Result.t_Result u128
                                                    Core.Array.t_TryFromSliceError
                                                with
                                                | Core.Result.Result_Ok mac ->
                                                  let xor_xk_macs:Alloc.Vec.t_Vec
                                                    (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                    Alloc.Alloc.t_Global =
                                                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize
                                                      xor_xk_macs
                                                      kk
                                                      (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize
                                                          (xor_xk_macs.[ kk ]
                                                            <:
                                                            Alloc.Vec.t_Vec u128
                                                              Alloc.Alloc.t_Global)
                                                          r
                                                          (mac ^.
                                                            ((xor_xk_macs.[ kk ]
                                                                <:
                                                                Alloc.Vec.t_Vec u128
                                                                  Alloc.Alloc.t_Global).[ r ]
                                                              <:
                                                              u128)
                                                            <:
                                                            u128)
                                                        <:
                                                        Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                  in
                                                  Core.Ops.Control_flow.ControlFlow_Continue
                                                  xor_xk_macs
                                                  <:
                                                  Core.Ops.Control_flow.t_ControlFlow
                                                    (Core.Ops.Control_flow.t_ControlFlow
                                                        (iimpl_951670863_ &
                                                          Core.Result.t_Result
                                                            (Alloc.Vec.t_Vec
                                                                Polytune.Data_types.t_Share
                                                                Alloc.Alloc.t_Global &
                                                              Rand_chacha.Chacha.t_ChaCha20Rng)
                                                            t_Error)
                                                        (Prims.unit &
                                                          Alloc.Vec.t_Vec
                                                            (Alloc.Vec.t_Vec u128
                                                                Alloc.Alloc.t_Global)
                                                            Alloc.Alloc.t_Global))
                                                    (Alloc.Vec.t_Vec
                                                        (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                        Alloc.Alloc.t_Global)
                                                | _ ->
                                                  Core.Ops.Control_flow.ControlFlow_Break
                                                  (Core.Ops.Control_flow.ControlFlow_Break
                                                    (channel,
                                                      (Core.Result.Result_Err
                                                        (Error_ConversionErr <: t_Error)
                                                        <:
                                                        Core.Result.t_Result
                                                          (Alloc.Vec.t_Vec
                                                              Polytune.Data_types.t_Share
                                                              Alloc.Alloc.t_Global &
                                                            Rand_chacha.Chacha.t_ChaCha20Rng)
                                                          t_Error)
                                                      <:
                                                      (iimpl_951670863_ &
                                                        Core.Result.t_Result
                                                          (Alloc.Vec.t_Vec
                                                              Polytune.Data_types.t_Share
                                                              Alloc.Alloc.t_Global &
                                                            Rand_chacha.Chacha.t_ChaCha20Rng)
                                                          t_Error))
                                                    <:
                                                    Core.Ops.Control_flow.t_ControlFlow
                                                      (iimpl_951670863_ &
                                                        Core.Result.t_Result
                                                          (Alloc.Vec.t_Vec
                                                              Polytune.Data_types.t_Share
                                                              Alloc.Alloc.t_Global &
                                                            Rand_chacha.Chacha.t_ChaCha20Rng)
                                                          t_Error)
                                                      (Prims.unit &
                                                        Alloc.Vec.t_Vec
                                                          (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global
                                                          ) Alloc.Alloc.t_Global))
                                                  <:
                                                  Core.Ops.Control_flow.t_ControlFlow
                                                    (Core.Ops.Control_flow.t_ControlFlow
                                                        (iimpl_951670863_ &
                                                          Core.Result.t_Result
                                                            (Alloc.Vec.t_Vec
                                                                Polytune.Data_types.t_Share
                                                                Alloc.Alloc.t_Global &
                                                              Rand_chacha.Chacha.t_ChaCha20Rng)
                                                            t_Error)
                                                        (Prims.unit &
                                                          Alloc.Vec.t_Vec
                                                            (Alloc.Vec.t_Vec u128
                                                                Alloc.Alloc.t_Global)
                                                            Alloc.Alloc.t_Global))
                                                    (Alloc.Vec.t_Vec
                                                        (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                        Alloc.Alloc.t_Global))
                                      <:
                                      Core.Ops.Control_flow.t_ControlFlow
                                        (iimpl_951670863_ &
                                          Core.Result.t_Result
                                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                Alloc.Alloc.t_Global &
                                              Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                            Alloc.Alloc.t_Global)
                                    with
                                    | Core.Ops.Control_flow.ControlFlow_Break ret ->
                                      Core.Ops.Control_flow.ControlFlow_Break
                                      (Core.Ops.Control_flow.ControlFlow_Break ret
                                        <:
                                        Core.Ops.Control_flow.t_ControlFlow
                                          (iimpl_951670863_ &
                                            Core.Result.t_Result
                                              (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                  Alloc.Alloc.t_Global &
                                                Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                          (Prims.unit &
                                            Alloc.Vec.t_Vec
                                              (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                              Alloc.Alloc.t_Global))
                                      <:
                                      Core.Ops.Control_flow.t_ControlFlow
                                        (Core.Ops.Control_flow.t_ControlFlow
                                            (iimpl_951670863_ &
                                              Core.Result.t_Result
                                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                    Alloc.Alloc.t_Global &
                                                  Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                            (Prims.unit &
                                              Alloc.Vec.t_Vec
                                                (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                Alloc.Alloc.t_Global))
                                        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                            Alloc.Alloc.t_Global)
                                    | Core.Ops.Control_flow.ControlFlow_Continue loop_res ->
                                      Core.Ops.Control_flow.ControlFlow_Continue loop_res
                                      <:
                                      Core.Ops.Control_flow.t_ControlFlow
                                        (Core.Ops.Control_flow.t_ControlFlow
                                            (iimpl_951670863_ &
                                              Core.Result.t_Result
                                                (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                                    Alloc.Alloc.t_Global &
                                                  Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                            (Prims.unit &
                                              Alloc.Vec.t_Vec
                                                (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                                Alloc.Alloc.t_Global))
                                        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                            Alloc.Alloc.t_Global))
                              <:
                              Core.Ops.Control_flow.t_ControlFlow
                                (iimpl_951670863_ &
                                  Core.Result.t_Result
                                    (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                        Alloc.Alloc.t_Global &
                                      Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                    Alloc.Alloc.t_Global)
                            with
                            | Core.Ops.Control_flow.ControlFlow_Break ret ->
                              Core.Ops.Control_flow.ControlFlow_Break
                              (Core.Ops.Control_flow.ControlFlow_Break ret
                                <:
                                Core.Ops.Control_flow.t_ControlFlow
                                  (iimpl_951670863_ &
                                    Core.Result.t_Result
                                      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                          Alloc.Alloc.t_Global &
                                        Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                  (Prims.unit &
                                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global))
                              <:
                              Core.Ops.Control_flow.t_ControlFlow
                                (Core.Ops.Control_flow.t_ControlFlow
                                    (iimpl_951670863_ &
                                      Core.Result.t_Result
                                        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                            Alloc.Alloc.t_Global &
                                          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                    (Prims.unit &
                                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                        Alloc.Alloc.t_Global))
                                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                    Alloc.Alloc.t_Global)
                            | Core.Ops.Control_flow.ControlFlow_Continue xor_xk_macs ->
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
                                        Core.Ops.Control_flow.ControlFlow_Continue
                                        (() <: Prims.unit)
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
                                        let d_bj:t_Array u8 (mk_usize 16) =
                                          Core.Num.impl_u128__to_be_bytes ((di_bi_k.[ k ]
                                                <:
                                                Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ r ]
                                              <:
                                              u128)
                                        in
                                        let commitments:(t_Commitment & t_Commitment & t_Commitment)
                                        =
                                          (c0_c1_cm_k.[ k ]
                                            <:
                                            Alloc.Vec.t_Vec
                                              (t_Commitment & t_Commitment & t_Commitment)
                                              Alloc.Alloc.t_Global).[ r ]
                                        in
                                        if
                                          ~.(open_commitment commitments._1 (d_bj <: t_Slice u8)
                                            <:
                                            bool) &&
                                          ~.(open_commitment commitments._2 (d_bj <: t_Slice u8)
                                            <:
                                            bool)
                                        then
                                          Core.Ops.Control_flow.ControlFlow_Break
                                          (Core.Ops.Control_flow.ControlFlow_Break
                                            (channel,
                                              (Core.Result.Result_Err
                                                (Error_CommitmentCouldNotBeOpened <: t_Error)
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
                                          if
                                            ((xor_xk_macs.[ k ]
                                                <:
                                                Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ r ]
                                              <:
                                              u128) <>.
                                            ((di_bi_k.[ k ]
                                                <:
                                                Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ r ]
                                              <:
                                              u128)
                                          then
                                            Core.Ops.Control_flow.ControlFlow_Break
                                            (Core.Ops.Control_flow.ControlFlow_Break
                                              (channel,
                                                (Core.Result.Result_Err
                                                  (Error_AShareWrongMAC <: t_Error)
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
                                      (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                          Alloc.Alloc.t_Global &
                                        Rand_chacha.Chacha.t_ChaCha20Rng) t_Error) Prims.unit
                              with
                              | Core.Ops.Control_flow.ControlFlow_Break ret ->
                                Core.Ops.Control_flow.ControlFlow_Break
                                (Core.Ops.Control_flow.ControlFlow_Break ret
                                  <:
                                  Core.Ops.Control_flow.t_ControlFlow
                                    (iimpl_951670863_ &
                                      Core.Result.t_Result
                                        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                            Alloc.Alloc.t_Global &
                                          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                    (Prims.unit &
                                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                        Alloc.Alloc.t_Global))
                                <:
                                Core.Ops.Control_flow.t_ControlFlow
                                  (Core.Ops.Control_flow.t_ControlFlow
                                      (iimpl_951670863_ &
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global &
                                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                      (Prims.unit &
                                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                          Alloc.Alloc.t_Global))
                                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global)
                              | Core.Ops.Control_flow.ControlFlow_Continue () ->
                                Core.Ops.Control_flow.ControlFlow_Continue xor_xk_macs
                                <:
                                Core.Ops.Control_flow.t_ControlFlow
                                  (Core.Ops.Control_flow.t_ControlFlow
                                      (iimpl_951670863_ &
                                        Core.Result.t_Result
                                          (Alloc.Vec.t_Vec Polytune.Data_types.t_Share
                                              Alloc.Alloc.t_Global &
                                            Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                                      (Prims.unit &
                                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                          Alloc.Alloc.t_Global))
                                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                                      Alloc.Alloc.t_Global))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (iimpl_951670863_ &
                          Core.Result.t_Result
                            (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                              Rand_chacha.Chacha.t_ChaCha20Rng) t_Error)
                        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global)
                    with
                    | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
                    | Core.Ops.Control_flow.ControlFlow_Continue xor_xk_macs ->
                      let xishares:Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global
                      =
                        Alloc.Vec.impl_1__truncate #Polytune.Data_types.t_Share
                          #Alloc.Alloc.t_Global
                          xishares
                          l
                      in
                      let hax_temp_output:Core.Result.t_Result
                        (Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
                          Rand_chacha.Chacha.t_ChaCha20Rng) t_Error =
                        Core.Result.Result_Ok
                        (xishares, multi_shared_rand
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
