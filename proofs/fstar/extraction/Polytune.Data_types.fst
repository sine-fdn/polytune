module Polytune.Data_types
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

/// A message authentication code held by a party together with an authenticated bit.
type t_Mac = | Mac : u128 -> t_Mac

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2: Core.Ops.Bit.t_BitXor t_Mac t_Mac =
  {
    f_Output = t_Mac;
    f_bitxor_pre = (fun (self: t_Mac) (rhs: t_Mac) -> true);
    f_bitxor_post = (fun (self: t_Mac) (rhs: t_Mac) (out: t_Mac) -> true);
    f_bitxor = fun (self: t_Mac) (rhs: t_Mac) -> Mac (self._0 ^. rhs._0) <: t_Mac
  }

/// A key used to authenticate (together with the [Delta] global key) a bit for the other party.
type t_Key = | Key : u128 -> t_Key

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_4: Core.Ops.Bit.t_BitXor t_Key t_Key =
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
