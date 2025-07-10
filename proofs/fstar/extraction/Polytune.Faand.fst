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

/// Represents a cryptographic commitment as a fixed-size 32-byte array (a BLAKE3 hash).
type t_Commitment = | Commitment : t_Array u8 (mk_usize 32) -> t_Commitment

/// Commits to a value using the BLAKE3 cryptographic hash function.
/// This is not a general-purpose commitment scheme, the input value is assumed to have high entropy.
assume
val commit': value: t_Slice u8 -> t_Commitment

unfold
let commit = commit'

/// Verifies if a given value matches a previously generated commitment.
/// This is not a general-purpose commitment scheme, the input value is assumed to have high entropy.
assume
val open_commitment': commitment: t_Commitment -> value: t_Slice u8 -> bool

unfold
let open_commitment = open_commitment'

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

/// This function takes a 128-bit unsigned integer (`u128`) as input and produces a 128-bit hash value.
/// We use the BLAKE3 cryptographic hash function to hash the input value and return the resulting hash.
/// The hash is truncated to 128 bits to match the input size. Due to the truncation, the security
/// guarantees of the hash function are reduced to 64-bit collision resistance and 128-bit preimage
/// resistance. This is sufficient for the purposes of the protocol if RHO <= 64, which we expect
/// to be the case in all real-world usages of our protocol.
assume
val hash128': input: u128 -> u128

unfold
let hash128 = hash128'

let flaand_1_
      (delta: Polytune.Data_types.t_Delta)
      (xshares yshares rshares zshares: t_Slice Polytune.Data_types.t_Share)
      (i n l: usize)
      (v: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
    : Prims.Pure
      (t_Slice Polytune.Data_types.t_Share &
        Core.Result.t_Result
          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) t_Error)
      (requires
        b2t ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global v <: usize) >=. l <: bool) /\
        b2t ((Core.Slice.impl__len #Polytune.Data_types.t_Share zshares <: usize) >=. l <: bool) /\
        (b2t ((Core.Slice.impl__len #Polytune.Data_types.t_Share rshares <: usize) >=. l <: bool) /\
        (b2t ((Core.Slice.impl__len #Polytune.Data_types.t_Share xshares <: usize) >=. l <: bool) /\
        (forall (ll: usize).
            b2t
            ((mk_usize 0 <=. ll <: bool) && (ll <. l <: bool) &&
              ((Core.Slice.impl__len #Polytune.Data_types.t_Share xshares <: usize) >=. l <: bool)) ==>
            b2t
            ((Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                  #Alloc.Alloc.t_Global
                  (xshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                    .Polytune.Data_types._0
                <:
                usize) >=.
              n
              <:
              bool)) /\
        (b2t ((Core.Slice.impl__len #Polytune.Data_types.t_Share yshares <: usize) >=. l <: bool) /\
        (forall (ll: usize).
            b2t
            ((mk_usize 0 <=. ll <: bool) && (ll <. l <: bool) &&
              ((Core.Slice.impl__len #Polytune.Data_types.t_Share yshares <: usize) >=. l <: bool)) ==>
            b2t
            ((Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                  #Alloc.Alloc.t_Global
                  (yshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                    .Polytune.Data_types._0
                <:
                usize) >=.
              n
              <:
              bool))))))
      (fun _ -> Prims.l_True) =
  let z:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = Alloc.Vec.from_elem #bool false l in
  let e:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = Alloc.Vec.from_elem #bool false l in
  let e, z, zshares:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
    Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
    t_Slice Polytune.Data_types.t_Share) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      l
      (fun temp_0_ temp_1_ ->
          let e, z, zshares:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
            t_Slice Polytune.Data_types.t_Share) =
            temp_0_
          in
          let _:usize = temp_1_ in
          ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global z <: usize) =. l <: bool) &&
          ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global e <: usize) =. l <: bool) &&
          ((Core.Slice.impl__len #Polytune.Data_types.t_Share zshares <: usize) >=. l <: bool))
      (e, z, zshares
        <:
        (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
          t_Slice Polytune.Data_types.t_Share))
      (fun temp_0_ ll ->
          let e, z, zshares:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
            t_Slice Polytune.Data_types.t_Share) =
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
          let zshares:t_Slice Polytune.Data_types.t_Share =
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
            t_Slice Polytune.Data_types.t_Share))
  in
  let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = Alloc.Vec.from_elem #u128 (mk_u128 0) l in
  let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      l
      (fun phi temp_1_ ->
          let phi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = phi in
          let _:usize = temp_1_ in
          (Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global phi <: usize) =. l <: bool)
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
                  (Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global phi <: usize) =. l <: bool)
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
  let ki_xj_phi:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
      (Alloc.Vec.from_elem #u128 (mk_u128 0) l <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
      n
  in
  let ei_uij:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
    Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #(Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
      (Alloc.Vec.impl__new #(bool & u128) () <: Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
      n
  in
  let ei_uij, ki_xj_phi:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
      Alloc.Alloc.t_Global &
    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      n
      (fun temp_0_ temp_1_ ->
          let ei_uij, ki_xj_phi:(Alloc.Vec.t_Vec
              (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
            temp_0_
          in
          let _:usize = temp_1_ in
          b2t
          (((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                  #Alloc.Alloc.t_Global
                  ki_xj_phi
                <:
                usize) =.
              n
              <:
              bool) &&
            ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                  #Alloc.Alloc.t_Global
                  ei_uij
                <:
                usize) =.
              n
              <:
              bool) &&
            ((Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global phi <: usize) =. l <: bool)) /\
          (forall (j: usize).
              b2t
              ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
                ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                      #Alloc.Alloc.t_Global
                      ki_xj_phi
                    <:
                    usize) =.
                  n
                  <:
                  bool)) ==>
              b2t
              ((Alloc.Vec.impl_1__len #u128
                    #Alloc.Alloc.t_Global
                    (ki_xj_phi.[ j ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                  <:
                  usize) =.
                l
                <:
                bool)))
      (ei_uij, ki_xj_phi
        <:
        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global))
      (fun temp_0_ j ->
          let ei_uij, ki_xj_phi:(Alloc.Vec.t_Vec
              (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
            temp_0_
          in
          let j:usize = j in
          if j =. i <: bool
          then
            ei_uij, ki_xj_phi
            <:
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
          else
            Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
              l
              (fun temp_0_ temp_1_ ->
                  let ei_uij, ki_xj_phi:(Alloc.Vec.t_Vec
                      (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global
                  ) =
                    temp_0_
                  in
                  let _:usize = temp_1_ in
                  b2t
                  (((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          #Alloc.Alloc.t_Global
                          ki_xj_phi
                        <:
                        usize) =.
                      n
                      <:
                      bool) &&
                    ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                          #Alloc.Alloc.t_Global
                          ei_uij
                        <:
                        usize) =.
                      n
                      <:
                      bool) &&
                    ((Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global phi <: usize) =. l <: bool)) /\
                  (forall (j: usize).
                      b2t
                      ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
                        ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              #Alloc.Alloc.t_Global
                              ki_xj_phi
                            <:
                            usize) =.
                          n
                          <:
                          bool)) ==>
                      b2t
                      ((Alloc.Vec.impl_1__len #u128
                            #Alloc.Alloc.t_Global
                            (ki_xj_phi.[ j ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          <:
                          usize) =.
                        l
                        <:
                        bool)))
              (ei_uij, ki_xj_phi
                <:
                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global))
              (fun temp_0_ ll ->
                  let ei_uij, ki_xj_phi:(Alloc.Vec.t_Vec
                      (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global
                  ) =
                    temp_0_
                  in
                  let ll:usize = ll in
                  let _, ki_xj:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
                    (xshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                      .Polytune.Data_types._0.[ j ]
                  in
                  let ki_xj_phi:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize ki_xj_phi
                      j
                      (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (ki_xj_phi.[ j ]
                            <:
                            Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          ll
                          (hash128 ki_xj.Polytune.Data_types._0 <: u128)
                        <:
                        Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                  in
                  let uij:u128 =
                    ((hash128 (ki_xj.Polytune.Data_types._0 ^. delta.Polytune.Data_types._0 <: u128)
                        <:
                        u128) ^.
                      ((ki_xj_phi.[ j ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ ll ] <: u128
                      )
                      <:
                      u128) ^.
                    (phi.[ ll ] <: u128)
                  in
                  let ei_uij:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize ei_uij
                      j
                      (Alloc.Vec.impl_1__push #(bool & u128)
                          #Alloc.Alloc.t_Global
                          (ei_uij.[ j ] <: Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                          ((e.[ ll ] <: bool), uij <: (bool & u128))
                        <:
                        Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                  in
                  ei_uij, ki_xj_phi
                  <:
                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global
                  ))
            <:
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global))
  in
  let hax_temp_output:Core.Result.t_Result
    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
      Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) t_Error =
    Core.Result.Result_Ok
    (ki_xj_phi, ei_uij, phi
      <:
      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
    <:
    Core.Result.t_Result
      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) t_Error
  in
  zshares, hax_temp_output
  <:
  (t_Slice Polytune.Data_types.t_Share &
    Core.Result.t_Result
      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) t_Error)

let flaand_2_
      (delta: Polytune.Data_types.t_Delta)
      (xshares rshares: t_Slice Polytune.Data_types.t_Share)
      (i n l: usize)
      (ki_xj_phi: Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
      (ei_uij_k:
          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
      (zshares: Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
      (phi: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
    : Prims.Pure
      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
        Core.Result.t_Result
          (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) t_Error)
      (requires
        b2t ((Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global phi <: usize) >=. l <: bool) /\
        b2t ((Core.Slice.impl__len #Polytune.Data_types.t_Share rshares <: usize) >=. l <: bool) /\
        (forall (ll: usize).
            b2t
            ((mk_usize 0 <=. ll <: bool) && (ll <. l <: bool) &&
              ((Core.Slice.impl__len #Polytune.Data_types.t_Share rshares <: usize) >=. l <: bool)) ==>
            b2t
            ((Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                  #Alloc.Alloc.t_Global
                  (rshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                    .Polytune.Data_types._0
                <:
                usize) >=.
              n
              <:
              bool)) /\
        (b2t
        ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Share #Alloc.Alloc.t_Global zshares <: usize) >=.
          l
          <:
          bool) /\
        (forall (ll: usize).
            b2t
            ((mk_usize 0 <=. ll <: bool) && (ll <. l <: bool) &&
              ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Share #Alloc.Alloc.t_Global zshares
                  <:
                  usize) >=.
                l
                <:
                bool)) ==>
            b2t
            ((Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                  #Alloc.Alloc.t_Global
                  (zshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                    .Polytune.Data_types._0
                <:
                usize) >=.
              n
              <:
              bool)) /\
        (b2t ((Core.Slice.impl__len #Polytune.Data_types.t_Share xshares <: usize) >=. l <: bool) /\
        (forall (ll: usize).
            b2t
            ((mk_usize 0 <=. ll <: bool) && (ll <. l <: bool) &&
              ((Core.Slice.impl__len #Polytune.Data_types.t_Share xshares <: usize) >=. l <: bool)) ==>
            b2t
            ((Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                  #Alloc.Alloc.t_Global
                  (xshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                    .Polytune.Data_types._0
                <:
                usize) >=.
              n
              <:
              bool)))) /\
        (b2t
        ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
              #Alloc.Alloc.t_Global
              ei_uij_k
            <:
            usize) >=.
          n
          <:
          bool) /\
        (forall (j: usize).
            b2t
            ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
              ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                    #Alloc.Alloc.t_Global
                    ei_uij_k
                  <:
                  usize) >=.
                n
                <:
                bool)) ==>
            b2t
            ((Alloc.Vec.impl_1__len #(bool & u128)
                  #Alloc.Alloc.t_Global
                  (ei_uij_k.[ j ] <: Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
                <:
                usize) >=.
              l
              <:
              bool)) /\
        (b2t
        ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
              #Alloc.Alloc.t_Global
              ki_xj_phi
            <:
            usize) >=.
          n
          <:
          bool) /\
        (forall (j: usize).
            b2t
            ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
              ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                    #Alloc.Alloc.t_Global
                    ki_xj_phi
                  <:
                  usize) >=.
                n
                <:
                bool)) ==>
            b2t
            ((Alloc.Vec.impl_1__len #u128
                  #Alloc.Alloc.t_Global
                  (ki_xj_phi.[ j ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                <:
                usize) >=.
              l
              <:
              bool)))))
      (fun _ -> Prims.l_True) =
  let ki_xj_phi, zshares:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
      Alloc.Alloc.t_Global &
    Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      n
      (fun temp_0_ temp_1_ ->
          let ki_xj_phi, zshares:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) =
            temp_0_
          in
          let _:usize = temp_1_ in
          b2t
          ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                #Alloc.Alloc.t_Global
                ki_xj_phi
              <:
              usize) >=.
            n
            <:
            bool) /\
          (forall (j: usize).
              b2t
              ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
                ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                      #Alloc.Alloc.t_Global
                      ki_xj_phi
                    <:
                    usize) >=.
                  n
                  <:
                  bool)) ==>
              b2t
              ((Alloc.Vec.impl_1__len #u128
                    #Alloc.Alloc.t_Global
                    (ki_xj_phi.[ j ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                  <:
                  usize) >=.
                l
                <:
                bool)) /\
          b2t
          ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Share #Alloc.Alloc.t_Global zshares
              <:
              usize) >=.
            l
            <:
            bool) /\
          (forall (ll: usize).
              b2t
              ((mk_usize 0 <=. ll <: bool) && (ll <. l <: bool) &&
                ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Share #Alloc.Alloc.t_Global zshares
                    <:
                    usize) >=.
                  l
                  <:
                  bool)) ==>
              b2t
              ((Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                    #Alloc.Alloc.t_Global
                    (zshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                      .Polytune.Data_types._0
                  <:
                  usize) >=.
                n
                <:
                bool)))
      (ki_xj_phi, zshares
        <:
        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
      (fun temp_0_ j ->
          let ki_xj_phi, zshares:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) =
            temp_0_
          in
          let j:usize = j in
          if j =. i <: bool
          then
            ki_xj_phi, zshares
            <:
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
          else
            Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
              l
              (fun temp_0_ temp_1_ ->
                  let ki_xj_phi, zshares:(Alloc.Vec.t_Vec
                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) =
                    temp_0_
                  in
                  let _:usize = temp_1_ in
                  b2t
                  ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        #Alloc.Alloc.t_Global
                        ki_xj_phi
                      <:
                      usize) >=.
                    n
                    <:
                    bool) /\
                  (forall (j: usize).
                      b2t
                      ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
                        ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                              #Alloc.Alloc.t_Global
                              ki_xj_phi
                            <:
                            usize) >=.
                          n
                          <:
                          bool)) ==>
                      b2t
                      ((Alloc.Vec.impl_1__len #u128
                            #Alloc.Alloc.t_Global
                            (ki_xj_phi.[ j ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          <:
                          usize) >=.
                        l
                        <:
                        bool)) /\
                  b2t
                  ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Share #Alloc.Alloc.t_Global zshares
                      <:
                      usize) >=.
                    l
                    <:
                    bool) /\
                  (forall (ll: usize).
                      b2t
                      ((mk_usize 0 <=. ll <: bool) && (ll <. l <: bool) &&
                        ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Share
                              #Alloc.Alloc.t_Global
                              zshares
                            <:
                            usize) >=.
                          l
                          <:
                          bool)) ==>
                      b2t
                      ((Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac &
                              Polytune.Data_types.t_Key)
                            #Alloc.Alloc.t_Global
                            (zshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                              .Polytune.Data_types._0
                          <:
                          usize) >=.
                        n
                        <:
                        bool)))
              (ki_xj_phi, zshares
                <:
                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
              (fun temp_0_ ll ->
                  let ki_xj_phi, zshares:(Alloc.Vec.t_Vec
                      (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global) =
                    temp_0_
                  in
                  let ll:usize = ll in
                  let mi_xj, _:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
                    (xshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                      .Polytune.Data_types._0.[ j ]
                  in
                  let ki_xj_phi:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize ki_xj_phi
                      j
                      (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (ki_xj_phi.[ j ]
                            <:
                            Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                          ll
                          ((((ki_xj_phi.[ j ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ ll ]
                                <:
                                u128) ^.
                              (hash128 mi_xj.Polytune.Data_types._0 <: u128)
                              <:
                              u128) ^.
                            ((cast ((xshares.[ ll ] <: Polytune.Data_types.t_Share)
                                      .Polytune.Data_types._0
                                    <:
                                    bool)
                                <:
                                u128) *!
                              ((ei_uij_k.[ j ] <: Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global
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
                  let mac, key:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
                    (rshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                      .Polytune.Data_types._0.[ j ]
                  in
                  if
                    ((ei_uij_k.[ j ] <: Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global).[ ll ] <: (bool & u128))
                      ._1
                  then
                    let zshares:Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global =
                      Rust_primitives.Hax.Monomorphized_update_at.update_at_usize zshares
                        ll
                        ({
                            (zshares.[ ll ] <: Polytune.Data_types.t_Share) with
                            Polytune.Data_types._1
                            =
                            {
                              (zshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1 with
                              Polytune.Data_types._0
                              =
                              Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (zshares.[
                                    ll ]
                                  <:
                                  Polytune.Data_types.t_Share)
                                  .Polytune.Data_types._1
                                  .Polytune.Data_types._0
                                j
                                (mac,
                                  (Polytune.Data_types.Key
                                    (key.Polytune.Data_types._0 ^. delta.Polytune.Data_types._0
                                      <:
                                      u128)
                                    <:
                                    Polytune.Data_types.t_Key)
                                  <:
                                  (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key))
                              <:
                              Alloc.Vec.t_Vec
                                (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                                Alloc.Alloc.t_Global
                            }
                            <:
                            Polytune.Data_types.t_Auth
                          }
                          <:
                          Polytune.Data_types.t_Share)
                    in
                    ki_xj_phi, zshares
                    <:
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global)
                  else
                    let zshares:Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global =
                      Rust_primitives.Hax.Monomorphized_update_at.update_at_usize zshares
                        ll
                        ({
                            (zshares.[ ll ] <: Polytune.Data_types.t_Share) with
                            Polytune.Data_types._1
                            =
                            {
                              (zshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1 with
                              Polytune.Data_types._0
                              =
                              Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (zshares.[
                                    ll ]
                                  <:
                                  Polytune.Data_types.t_Share)
                                  .Polytune.Data_types._1
                                  .Polytune.Data_types._0
                                j
                                (mac, key <: (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                                )
                              <:
                              Alloc.Vec.t_Vec
                                (Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                                Alloc.Alloc.t_Global
                            }
                            <:
                            Polytune.Data_types.t_Auth
                          }
                          <:
                          Polytune.Data_types.t_Share)
                    in
                    ki_xj_phi, zshares
                    <:
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                        Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
            <:
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global))
  in
  let hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = Alloc.Vec.from_elem #u128 (mk_u128 0) l in
  let commhi:Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #t_Commitment l
  in
  let commhi, hi:(Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global &
    Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      l
      (fun temp_0_ ll ->
          let commhi, hi:(Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) =
            temp_0_
          in
          let ll:usize = ll in
          b2t
          (((Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global hi <: usize) =. l <: bool) &&
            ((Alloc.Vec.impl_1__len #t_Commitment #Alloc.Alloc.t_Global commhi <: usize) =. ll
              <:
              bool)) /\
          b2t
          ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Share #Alloc.Alloc.t_Global zshares
              <:
              usize) >=.
            l
            <:
            bool) /\
          (forall (ll: usize).
              b2t
              ((mk_usize 0 <=. ll <: bool) && (ll <. l <: bool) &&
                ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Share #Alloc.Alloc.t_Global zshares
                    <:
                    usize) >=.
                  l
                  <:
                  bool)) ==>
              b2t
              ((Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key)
                    #Alloc.Alloc.t_Global
                    (zshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                      .Polytune.Data_types._0
                  <:
                  usize) >=.
                n
                <:
                bool)))
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
                  b2t
                  (((Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global hi <: usize) =. l <: bool) &&
                    ((Alloc.Vec.impl_1__len #t_Commitment #Alloc.Alloc.t_Global commhi <: usize) =.
                      ll
                      <:
                      bool)) /\
                  b2t
                  ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Share #Alloc.Alloc.t_Global zshares
                      <:
                      usize) >=.
                    l
                    <:
                    bool) /\
                  (forall (ll: usize).
                      b2t
                      ((mk_usize 0 <=. ll <: bool) && (ll <. l <: bool) &&
                        ((Alloc.Vec.impl_1__len #Polytune.Data_types.t_Share
                              #Alloc.Alloc.t_Global
                              zshares
                            <:
                            usize) >=.
                          l
                          <:
                          bool)) ==>
                      b2t
                      ((Alloc.Vec.impl_1__len #(Polytune.Data_types.t_Mac &
                              Polytune.Data_types.t_Key)
                            #Alloc.Alloc.t_Global
                            (zshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                              .Polytune.Data_types._0
                          <:
                          usize) >=.
                        n
                        <:
                        bool)))
              hi
              (fun hi k ->
                  let hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global = hi in
                  let k:usize = k in
                  if k =. i <: bool
                  then hi
                  else
                    let mk_zi, ki_zk:(Polytune.Data_types.t_Mac & Polytune.Data_types.t_Key) =
                      (zshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._1
                        .Polytune.Data_types._0.[ k ]
                    in
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize hi
                      ll
                      ((((hi.[ ll ] <: u128) ^. mk_zi.Polytune.Data_types._0 <: u128) ^.
                          ki_zk.Polytune.Data_types._0
                          <:
                          u128) ^.
                        ((ki_xj_phi.[ k ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ ll ]
                          <:
                          u128)
                        <:
                        u128))
          in
          let hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
            Rust_primitives.Hax.Monomorphized_update_at.update_at_usize hi
              ll
              (((hi.[ ll ] <: u128) ^.
                  ((cast ((xshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._0
                          <:
                          bool)
                      <:
                      u128) *!
                    (phi.[ ll ] <: u128)
                    <:
                    u128)
                  <:
                  u128) ^.
                ((cast ((zshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._0
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
              (commit (Core.Num.impl_u128__to_be_bytes (hi.[ ll ] <: u128) <: t_Slice u8)
                <:
                t_Commitment)
          in
          commhi, hi
          <:
          (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
  in
  let hax_temp_output:Core.Result.t_Result
    (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
    t_Error =
    Core.Result.Result_Ok
    (commhi, hi
      <:
      (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global
      ))
    <:
    Core.Result.t_Result
      (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global
      ) t_Error
  in
  ki_xj_phi, zshares, hax_temp_output
  <:
  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
    Alloc.Vec.t_Vec Polytune.Data_types.t_Share Alloc.Alloc.t_Global &
    Core.Result.t_Result
      (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global
      ) t_Error)

let flaand_3_
      (i n l: usize)
      (xor_all_hi: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
      (commhi_k:
          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
      (hi_k_outer: Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
    : Prims.Pure (Core.Result.t_Result Prims.unit t_Error)
      (requires
        b2t ((Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global xor_all_hi <: usize) =. l <: bool) /\
        b2t
        ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global)
              #Alloc.Alloc.t_Global
              commhi_k
            <:
            usize) >=.
          n
          <:
          bool) /\
        (forall (k: usize).
            b2t
            ((mk_usize 0 <=. k <: bool) && (k <. n <: bool) &&
              ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global)
                    #Alloc.Alloc.t_Global
                    commhi_k
                  <:
                  usize) >=.
                n
                <:
                bool)) ==>
            b2t
            ((Alloc.Vec.impl_1__len #t_Commitment
                  #Alloc.Alloc.t_Global
                  (commhi_k.[ k ] <: Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global)
                <:
                usize) >=.
              l
              <:
              bool)) /\
        (b2t
        ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
              #Alloc.Alloc.t_Global
              hi_k_outer
            <:
            usize) >=.
          n
          <:
          bool) /\
        (forall (k: usize).
            b2t
            ((mk_usize 0 <=. k <: bool) && (k <. n <: bool) &&
              ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                    #Alloc.Alloc.t_Global
                    hi_k_outer
                  <:
                  usize) >=.
                n
                <:
                bool)) ==>
            b2t
            ((Alloc.Vec.impl_1__len #u128
                  #Alloc.Alloc.t_Global
                  (hi_k_outer.[ k ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
                <:
                usize) >=.
              l
              <:
              bool))))
      (fun _ -> Prims.l_True) =
  let commitment_error:bool = false in
  let xor_not_zero_error:bool = false in
  let commitment_error, xor_all_hi:(bool & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      n
      (fun temp_0_ temp_1_ ->
          let commitment_error, xor_all_hi:(bool & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) =
            temp_0_
          in
          let _:usize = temp_1_ in
          (Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global xor_all_hi <: usize) =. l <: bool)
      (commitment_error, xor_all_hi <: (bool & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
      (fun temp_0_ k ->
          let commitment_error, xor_all_hi:(bool & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) =
            temp_0_
          in
          let k:usize = k in
          if k =. i <: bool
          then commitment_error, xor_all_hi <: (bool & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
          else
            Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
              l
              (fun temp_0_ temp_1_ ->
                  let commitment_error, xor_all_hi:(bool & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global
                  ) =
                    temp_0_
                  in
                  let _:usize = temp_1_ in
                  (Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global xor_all_hi <: usize) =. l
                  <:
                  bool)
              (commitment_error, xor_all_hi <: (bool & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
              (fun temp_0_ ll ->
                  let commitment_error, xor_all_hi:(bool & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global
                  ) =
                    temp_0_
                  in
                  let ll:usize = ll in
                  let commitment_error:bool =
                    if
                      ~.(open_commitment ((commhi_k.[ k ]
                              <:
                              Alloc.Vec.t_Vec t_Commitment Alloc.Alloc.t_Global).[ ll ]
                            <:
                            t_Commitment)
                          (Core.Num.impl_u128__to_be_bytes ((hi_k_outer.[ k ]
                                  <:
                                  Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ ll ]
                                <:
                                u128)
                            <:
                            t_Slice u8)
                        <:
                        bool)
                    then
                      let commitment_error:bool = true in
                      commitment_error
                    else commitment_error
                  in
                  let xor_all_hi:Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize xor_all_hi
                      ll
                      ((xor_all_hi.[ ll ] <: u128) ^.
                        ((hi_k_outer.[ k ] <: Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global).[ ll ]
                          <:
                          u128)
                        <:
                        u128)
                  in
                  commitment_error, xor_all_hi <: (bool & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global)
              )
            <:
            (bool & Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global))
  in
  let xor_not_zero_error:bool =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      l
      (fun xor_not_zero_error temp_1_ ->
          let xor_not_zero_error:bool = xor_not_zero_error in
          let _:usize = temp_1_ in
          (Alloc.Vec.impl_1__len #u128 #Alloc.Alloc.t_Global xor_all_hi <: usize) =. l <: bool)
      xor_not_zero_error
      (fun xor_not_zero_error i ->
          let xor_not_zero_error:bool = xor_not_zero_error in
          let i:usize = i in
          if (xor_all_hi.[ i ] <: u128) <>. mk_u128 0 <: bool
          then
            let xor_not_zero_error:bool = true in
            xor_not_zero_error
          else xor_not_zero_error)
  in
  if commitment_error
  then
    Core.Result.Result_Err (Error_CommitmentCouldNotBeOpened <: t_Error)
    <:
    Core.Result.t_Result Prims.unit t_Error
  else
    if xor_not_zero_error
    then
      Core.Result.Result_Err (Error_LaANDXorNotZero <: t_Error)
      <:
      Core.Result.t_Result Prims.unit t_Error
    else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit t_Error

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
