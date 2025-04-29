module Polytune.Data_types
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

/// The global key known only to a single party that is used to authenticate bits.
type t_Delta = | Delta : u128 -> t_Delta

/// A message authentication code held by a party together with an authenticated bit.
type t_Mac = | Mac : u128 -> t_Mac

/// A key used to authenticate (together with the [Delta] global key) a bit for the other party.
type t_Key = | Key : u128 -> t_Key

type t_Auth = | Auth : Smallvec.t_SmallVec (t_Array (t_Mac & t_Key) (mk_usize 2)) -> t_Auth

/// One half of a shared secret consisting of 2 XORed bits `r` and `s`.
/// Party A holds (`r`, [Mac]_r, [Key]_s) and party B holds (`s`, [Mac]_s, [Key]_r), so that each
/// party holds bit + MAC, with the other holding key + global key for the corresponding half of the
/// bit.
type t_Share = | Share : bool -> t_Auth -> t_Share
