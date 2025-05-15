module Polytune.Faand
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

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
let open_commitment (commitment: t_Commitment) (value: t_Slice u8) : bool =
  (Blake3.impl_Hash__as_bytes (Blake3.hash value <: Blake3.t_Hash) <: t_Array u8 (mk_usize 32)) =.
  commitment._0

assume
val random_bool': Prims.unit -> bool

unfold
let random_bool = random_bool'

val fhaand 
      (deltas: Seq.seq Polytune.Data_types.t_Delta)
      (n l: usize)
      (xshares: Seq.seq (t_Slice Polytune.Data_types.t_Share))
      (yi: Seq.seq (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
    : Prims.Pure (Seq.seq (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))

let fhaand_1_
      (delta: Polytune.Data_types.t_Delta)
      (i n l: usize)
      (xshares: t_Slice Polytune.Data_types.t_Share)
      (yi: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
    : Prims.Pure
      (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
      (requires
        b2t ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global yi <: usize) >=. l <: bool) /\
        b2t ((Core.Slice.impl__len #Polytune.Data_types.t_Share xshares <: usize) >=. l <: bool) /\
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
              bool)))
      (fun _ -> Prims.l_True) =
  let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = Alloc.Vec.from_elem #bool false l in
  let h0h1:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global
  =
    Alloc.Vec.from_elem #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
      (Alloc.Vec.from_elem #(bool & bool) (false, false <: (bool & bool)) l
        <:
        Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
      n
  in
  let h0h1, vi:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
      Alloc.Alloc.t_Global &
    Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      n
      (fun temp_0_ temp_1_ ->
          let h0h1, vi:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
            temp_0_
          in
          let _:usize = temp_1_ in
          b2t ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global vi <: usize) =. l <: bool) /\
          b2t
          ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                #Alloc.Alloc.t_Global
                h0h1
              <:
              usize) =.
            n
            <:
            bool) /\
          (forall (j: usize).
              b2t
              ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
                ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                      #Alloc.Alloc.t_Global
                      h0h1
                    <:
                    usize) =.
                  n
                  <:
                  bool)) ==>
              b2t
              ((Alloc.Vec.impl_1__len #(bool & bool)
                    #Alloc.Alloc.t_Global
                    (h0h1.[ j ] <: Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                  <:
                  usize) =.
                l
                <:
                bool)))
      (h0h1, vi
        <:
        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
      (fun temp_0_ j ->
          let h0h1, vi:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
            temp_0_
          in
          let j:usize = j in
          if j =. i <: bool
          then
            h0h1, vi
            <:
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
          else
            Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
              l
              (fun temp_0_ temp_1_ ->
                  let h0h1, vi:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
                    temp_0_
                  in
                  let _:usize = temp_1_ in
                  b2t ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global vi <: usize) =. l <: bool) /\
                  b2t
                  ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                        #Alloc.Alloc.t_Global
                        h0h1
                      <:
                      usize) =.
                    n
                    <:
                    bool) /\
                  (forall (j: usize).
                      b2t
                      ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
                        ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global
                              )
                              #Alloc.Alloc.t_Global
                              h0h1
                            <:
                            usize) =.
                          n
                          <:
                          bool)) ==>
                      b2t
                      ((Alloc.Vec.impl_1__len #(bool & bool)
                            #Alloc.Alloc.t_Global
                            (h0h1.[ j ] <: Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                          <:
                          usize) =.
                        l
                        <:
                        bool)))
              (h0h1, vi
                <:
                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
              (fun temp_0_ ll ->
                  let h0h1, vi:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global &
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
                  let h0h1:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize h0h1
                      j
                      (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (h0h1.[ j ]
                            <:
                            Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                          ll
                          ({
                              ((h0h1.[ j ] <: Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global).[ ll
                                ]
                                <:
                                (bool & bool)) with
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
                        <:
                        Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                  in
                  let h0h1:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                    Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize h0h1
                      j
                      (Rust_primitives.Hax.Monomorphized_update_at.update_at_usize (h0h1.[ j ]
                            <:
                            Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                          ll
                          ({
                              ((h0h1.[ j ] <: Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global).[ ll
                                ]
                                <:
                                (bool & bool)) with
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
                        <:
                        Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                  in
                  let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
                    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize vi
                      ll
                      (Core.Ops.Bit.f_bitxor (vi.[ ll ] <: bool) sj <: bool)
                  in
                  h0h1, vi
                  <:
                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
            <:
            (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global &
              Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
  in
  vi, h0h1
  <:
  (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)

let fhaand_2_
      (i n l: usize)
      (xshares: t_Slice Polytune.Data_types.t_Share)
      (vi: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
      (h0h1_j:
          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
    : Prims.Pure (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
      (requires
        b2t ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global vi <: usize) =. l <: bool) /\
        b2t ((Core.Slice.impl__len #Polytune.Data_types.t_Share xshares <: usize) >=. l <: bool) /\
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
        (b2t
        ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
              #Alloc.Alloc.t_Global
              h0h1_j
            <:
            usize) >=.
          n
          <:
          bool) /\
        (forall (j: usize).
            b2t
            ((mk_usize 0 <=. j <: bool) && (j <. n <: bool) &&
              ((Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                    #Alloc.Alloc.t_Global
                    h0h1_j
                  <:
                  usize) >=.
                n
                <:
                bool)) ==>
            b2t
            ((Alloc.Vec.impl_1__len #(bool & bool)
                  #Alloc.Alloc.t_Global
                  (h0h1_j.[ j ] <: Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global)
                <:
                usize) >=.
              l
              <:
              bool))))
      (fun _ -> Prims.l_True) =
  Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
    n
    (fun vi temp_1_ ->
        let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = vi in
        let _:usize = temp_1_ in
        (Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global vi <: usize) =. l <: bool)
    vi
    (fun vi j ->
        let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = vi in
        let j:usize = j in
        if j =. i <: bool
        then vi
        else
          Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
            l
            (fun vi temp_1_ ->
                let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = vi in
                let _:usize = temp_1_ in
                (Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global vi <: usize) =. l <: bool)
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
                  (((Blake3.impl_Hash__as_bytes hash_mixj <: t_Array u8 (mk_usize 32)).[ mk_usize 31
                      ]
                      <:
                      u8) &.
                    mk_u8 1
                    <:
                    u8) <>.
                  mk_u8 0
                in
                let t:bool =
                  Core.Ops.Bit.f_bitxor t
                    (if (xshares.[ ll ] <: Polytune.Data_types.t_Share).Polytune.Data_types._0
                      then
                        ((h0h1_j.[ j ] <: Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global).[ ll ]
                          <:
                          (bool & bool))
                          ._2
                      else
                        ((h0h1_j.[ j ] <: Alloc.Vec.t_Vec (bool & bool) Alloc.Alloc.t_Global).[ ll ]
                          <:
                          (bool & bool))
                          ._1)
                in
                let vi:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global =
                  Rust_primitives.Hax.Monomorphized_update_at.update_at_usize vi
                    ll
                    (Core.Ops.Bit.f_bitxor (vi.[ ll ] <: bool) t <: bool)
                in
                vi)
          <:
          Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)

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
      (xshares yshares rshares: t_Slice Polytune.Data_types.t_Share)
      (i n l: usize)
      (v: Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global)
    : Prims.Pure
      (Core.Result.t_Result
          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec u128 Alloc.Alloc.t_Global) t_Error)
      (requires
        b2t ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global v <: usize) >=. l <: bool) /\
        b2t ((Core.Slice.impl__len #Polytune.Data_types.t_Share rshares <: usize) >=. l <: bool) /\
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
              bool)))))
      (fun _ -> Prims.l_True) =
  let z:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = Alloc.Vec.from_elem #bool false l in
  let e:Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global = Alloc.Vec.from_elem #bool false l in
  let e, z:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      l
      (fun temp_0_ temp_1_ ->
          let e, z:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
            temp_0_
          in
          let _:usize = temp_1_ in
          ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global z <: usize) =. l <: bool) &&
          ((Alloc.Vec.impl_1__len #bool #Alloc.Alloc.t_Global e <: usize) =. l <: bool))
      (e, z
        <:
        (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
      (fun temp_0_ ll ->
          let e, z:(Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global) =
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
          e, z
          <:
          (Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global & Alloc.Vec.t_Vec bool Alloc.Alloc.t_Global))
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
                    ((ei_uij_k.[ j ] <: Alloc.Vec.t_Vec (bool & u128) Alloc.Alloc.t_Global).[ ll ])
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
