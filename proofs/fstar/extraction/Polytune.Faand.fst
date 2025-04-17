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
  | Error_KOSConsistencyCheckFailed : t_Error
  | Error_ABitWrongMAC : t_Error
  | Error_AShareWrongMAC : t_Error
  | Error_LaANDXorNotZero : t_Error
  | Error_AANDWrongMAC : t_Error
  | Error_BeaverWrongMAC : t_Error
  | Error_InvalidHashLength : t_Error

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
