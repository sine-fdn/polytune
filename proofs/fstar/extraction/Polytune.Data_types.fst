module Polytune.Data_types
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

/// The global key known only to a single party that is used to authenticate bits.
type t_Delta = | Delta : u128 -> t_Delta

/// A message authentication code held by a party together with an authenticated bit.
type t_Mac = | Mac : u128 -> t_Mac

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3: Core.Ops.Bit.t_BitXor t_Mac t_Mac =
  {
    f_Output = t_Mac;
    f_bitxor_pre = (fun (self: t_Mac) (rhs: t_Mac) -> true);
    f_bitxor_post = (fun (self: t_Mac) (rhs: t_Mac) (out: t_Mac) -> true);
    f_bitxor = fun (self: t_Mac) (rhs: t_Mac) -> Mac (self._0 ^. rhs._0) <: t_Mac
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_4: Core.Convert.t_From u128 t_Mac =
  {
    f_from_pre = (fun (value: t_Mac) -> true);
    f_from_post = (fun (value: t_Mac) (out: u128) -> true);
    f_from = fun (value: t_Mac) -> value._0
  }

/// A key used to authenticate (together with the [Delta] global key) a bit for the other party.
type t_Key = | Key : u128 -> t_Key

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_5: Core.Convert.t_From u128 t_Key =
  {
    f_from_pre = (fun (value: t_Key) -> true);
    f_from_post = (fun (value: t_Key) (out: u128) -> true);
    f_from = fun (value: t_Key) -> value._0
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_6: Core.Ops.Bit.t_BitXor t_Key t_Delta =
  {
    f_Output = t_Mac;
    f_bitxor_pre = (fun (self: t_Key) (rhs: t_Delta) -> true);
    f_bitxor_post = (fun (self: t_Key) (rhs: t_Delta) (out: t_Mac) -> true);
    f_bitxor = fun (self: t_Key) (rhs: t_Delta) -> Mac (self._0 ^. rhs._0) <: t_Mac
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_7: Core.Ops.Bit.t_BitXor t_Key t_Key =
  {
    f_Output = t_Key;
    f_bitxor_pre = (fun (self: t_Key) (rhs: t_Key) -> true);
    f_bitxor_post = (fun (self: t_Key) (rhs: t_Key) (out: t_Key) -> true);
    f_bitxor = fun (self: t_Key) (rhs: t_Key) -> Key (self._0 ^. rhs._0) <: t_Key
  }

type t_Auth = | Auth : Alloc.Vec.t_Vec (t_Mac & t_Key) Alloc.Alloc.t_Global -> t_Auth

/// One half of a shared secret consisting of 2 XORed bits `r` and `s`.
/// Party A holds (`r`, [Mac]_r, [Key]_s) and party B holds (`s`, [Mac]_s, [Key]_r), so that each
/// party holds bit + MAC, with the other holding key + global key for the corresponding half of the
/// bit.
type t_Share = | Share : bool -> t_Auth -> t_Share

let impl_Share__bit (self: t_Share) : bool = self._0

let impl_Auth__macs (self: t_Auth) : Alloc.Vec.t_Vec t_Mac Alloc.Alloc.t_Global =
  Core.Iter.Traits.Iterator.f_collect #(Core.Iter.Adapters.Map.t_Map
        (Core.Slice.Iter.t_Iter (t_Mac & t_Key)) ((t_Mac & t_Key) -> t_Mac))
    #FStar.Tactics.Typeclasses.solve
    #(Alloc.Vec.t_Vec t_Mac Alloc.Alloc.t_Global)
    (Core.Iter.Traits.Iterator.f_map #(Core.Slice.Iter.t_Iter (t_Mac & t_Key))
        #FStar.Tactics.Typeclasses.solve
        #t_Mac
        (Core.Slice.impl__iter #(t_Mac & t_Key)
            (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec (t_Mac & t_Key) Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                self._0
              <:
              t_Slice (t_Mac & t_Key))
          <:
          Core.Slice.Iter.t_Iter (t_Mac & t_Key))
        (fun temp_0_ ->
            let mac, _:(t_Mac & t_Key) = temp_0_ in
            mac)
      <:
      Core.Iter.Adapters.Map.t_Map (Core.Slice.Iter.t_Iter (t_Mac & t_Key))
        ((t_Mac & t_Key) -> t_Mac))

let mac_by (share: t_Share) (party: usize)
    : Prims.Pure t_Mac
      (requires
        (Alloc.Vec.impl_1__len #t_Mac
            #Alloc.Alloc.t_Global
            (impl_Auth__macs share._1 <: Alloc.Vec.t_Vec t_Mac Alloc.Alloc.t_Global)
          <:
          usize) >.
        party)
      (fun _ -> Prims.l_True) =
  (impl_Auth__macs share._1 <: Alloc.Vec.t_Vec t_Mac Alloc.Alloc.t_Global).[ party ]

let impl_Auth__keys (self: t_Auth) : Alloc.Vec.t_Vec t_Key Alloc.Alloc.t_Global =
  Core.Iter.Traits.Iterator.f_collect #(Core.Iter.Adapters.Map.t_Map
        (Core.Slice.Iter.t_Iter (t_Mac & t_Key)) ((t_Mac & t_Key) -> t_Key))
    #FStar.Tactics.Typeclasses.solve
    #(Alloc.Vec.t_Vec t_Key Alloc.Alloc.t_Global)
    (Core.Iter.Traits.Iterator.f_map #(Core.Slice.Iter.t_Iter (t_Mac & t_Key))
        #FStar.Tactics.Typeclasses.solve
        #t_Key
        (Core.Slice.impl__iter #(t_Mac & t_Key)
            (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec (t_Mac & t_Key) Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                self._0
              <:
              t_Slice (t_Mac & t_Key))
          <:
          Core.Slice.Iter.t_Iter (t_Mac & t_Key))
        (fun temp_0_ ->
            let _, key:(t_Mac & t_Key) = temp_0_ in
            key)
      <:
      Core.Iter.Adapters.Map.t_Map (Core.Slice.Iter.t_Iter (t_Mac & t_Key))
        ((t_Mac & t_Key) -> t_Key))

let key_for (share: t_Share) (party: usize)
    : Prims.Pure t_Key
      (requires
        (Alloc.Vec.impl_1__len #t_Key
            #Alloc.Alloc.t_Global
            (impl_Auth__keys share._1 <: Alloc.Vec.t_Vec t_Key Alloc.Alloc.t_Global)
          <:
          usize) >.
        party)
      (fun _ -> Prims.l_True) =
  (impl_Auth__keys share._1 <: Alloc.Vec.t_Vec t_Key Alloc.Alloc.t_Global).[ party ]
