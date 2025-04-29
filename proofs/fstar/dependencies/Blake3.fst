module Blake3
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

/// An output of the default size, 32 bytes, which provides constant-time
/// equality checking.
/// `Hash` implements [`From`] and [`Into`] for `[u8; 32]`, and it provides
/// [`from_bytes`] and [`as_bytes`] for explicit conversions between itself and
/// `[u8; 32]`. However, byte arrays and slices don't provide constant-time
/// equality checking, which is often a security requirement in software that
/// handles private data. `Hash` doesn't implement [`Deref`] or [`AsRef`], to
/// avoid situations where a type conversion happens implicitly and the
/// constant-time property is accidentally lost.
/// `Hash` provides the [`to_hex`] and [`from_hex`] methods for converting to
/// and from hexadecimal. It also implements [`Display`] and [`FromStr`].
/// [`From`]: https://doc.rust-lang.org/std/convert/trait.From.html
/// [`Into`]: https://doc.rust-lang.org/std/convert/trait.Into.html
/// [`as_bytes`]: #method.as_bytes
/// [`from_bytes`]: #method.from_bytes
/// [`Deref`]: https://doc.rust-lang.org/stable/std/ops/trait.Deref.html
/// [`AsRef`]: https://doc.rust-lang.org/std/convert/trait.AsRef.html
/// [`to_hex`]: #method.to_hex
/// [`from_hex`]: #method.from_hex
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
type t_Hash = | Hash : t_Array u8 (mk_usize 32) -> t_Hash

/// The raw bytes of the `Hash`. Note that byte arrays don't provide
/// constant-time equality checking, so if  you need to compare hashes,
/// prefer the `Hash` type.
let impl_Hash__as_bytes (self: t_Hash) : t_Array u8 (mk_usize 32) = self._0

let extract_me (_: Prims.unit) : Prims.unit =
  let h:t_Hash = Hash (Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)) <: t_Hash in
  let _:t_Array u8 (mk_usize 32) = impl_Hash__as_bytes h in
  ()

/// The default hash function.
/// For an incremental version that accepts multiple writes, see
/// [`Hasher::update`].
/// For output sizes other than 32 bytes, see [`Hasher::finalize_xof`] and
/// [`OutputReader`].
/// This function is always single-threaded. For multithreading support, see
/// [`Hasher::update_rayon`](struct.Hasher.html#method.update_rayon).
assume
val hash': input: t_Slice u8 -> t_Hash

unfold
let hash = hash'
