module Polytune.Faand.Spec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let share_is_authenticated
      (share_at_i share_at_j: Polytune.Data_types.t_Share)
      (i j: usize)
      (delta_j: Polytune.Data_types.t_Delta)
    : Lemma
    (requires (
             (Alloc.Vec.impl_1__len (Polytune.Data_types.impl_Auth__macs share_at_i._1) >. j)
           /\ (Alloc.Vec.impl_1__len (Polytune.Data_types.impl_Auth__keys share_at_j._1) >. i)
          ))
    (ensures
      (let bit:bool = Polytune.Data_types.impl_Share__bit share_at_i in
        let mac:Polytune.Data_types.t_Mac = Polytune.Data_types.mac_by share_at_i j in
        let key:Polytune.Data_types.t_Key = Polytune.Data_types.key_for share_at_j i in
        if bit
        then
          mac.Polytune.Data_types._0 =.
          (key.Polytune.Data_types._0 ^. delta_j.Polytune.Data_types._0 <: u128)
        else mac.Polytune.Data_types._0 =. key.Polytune.Data_types._0)) =
  let _:Prims.unit = admit () in
  ()
