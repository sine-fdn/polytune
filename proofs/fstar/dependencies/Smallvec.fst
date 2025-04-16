module Smallvec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

/// Types that can be used as the backing store for a [`SmallVec`].
class t_SmallVecArray (v_Self: Type0) = {
  f_Item:Type0;
  f_size_pre:Prims.unit -> Type0;
  f_size_post:Prims.unit -> usize -> Type0;
  f_size:x0: Prims.unit -> Prims.Pure usize (f_size_pre x0) (fun result -> f_size_post x0 result)
}

assume
val t_SmallVecData': v_A: Type0 -> {| i1: t_SmallVecArray v_A |} -> eqtype

let t_SmallVecData (v_A: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_SmallVecArray v_A) =
  t_SmallVecData' v_A #i1

/// A `Vec`-like container that can store a small number of elements inline.
/// `SmallVec` acts like a vector, but can store a limited amount of data inline within the
/// `SmallVec` struct rather than in a separate allocation.  If the data exceeds this limit, the
/// `SmallVec` will "spill" its data onto the heap, allocating a new buffer to hold it.
/// The amount of data that a `SmallVec` can store inline depends on its backing store. The backing
/// store can be any type that implements the `Array` trait; usually it is a small fixed-sized
/// array.  For example a `SmallVec<[u64; 8]>` can hold up to eight 64-bit integers inline.
/// ## Example
/// ```rust
/// use smallvec::SmallVec;
/// let mut v = SmallVec::<[u8; 4]>::new(); // initialize an empty vector
/// // The vector can hold up to 4 items without spilling onto the heap.
/// v.extend(0..4);
/// assert_eq!(v.len(), 4);
/// assert!(!v.spilled());
/// // Pushing another element will force the buffer to spill:
/// v.push(4);
/// assert_eq!(v.len(), 5);
/// assert!(v.spilled());
/// ```
type t_SmallVec (v_A: Type0) {| i1: t_SmallVecArray v_A |} = {
  f_capacity:usize;
  f_data:t_SmallVecData v_A
}

/// Creates a `SmallVec` with `n` copies of `elem`.
/// ```
/// use smallvec::SmallVec;
/// let v = SmallVec::<[char; 128]>::from_elem(\'d\', 2);
/// assert_eq!(v, SmallVec::from_buf([\'d\', \'d\']));
/// ```
assume
val impl_17__from_elem':
    #v_A: Type0 ->
    {| i1: t_SmallVecArray v_A |} ->
    {| i2: Core.Clone.t_Clone i1.f_Item |} ->
    elem: i1.f_Item ->
    n: usize
  -> t_SmallVec v_A

let impl_17__from_elem
      (#v_A: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_SmallVecArray v_A)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone i1.f_Item)
     = impl_17__from_elem' #v_A #i1 #i2

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_61 (#v_T: Type0) : t_SmallVecArray (t_Array v_T (mk_usize 2)) =
  {
    f_Item = v_T;
    f_size_pre = (fun (_: Prims.unit) -> true);
    f_size_post = (fun (_: Prims.unit) (out: usize) -> true);
    f_size = fun (_: Prims.unit) -> mk_usize 2
  }
