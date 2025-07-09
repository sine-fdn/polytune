module Serde.Ser.Impls
open Serde.Ser

instance impl_serialize (#a:Type): t_Serialize a =
 {
 serialize = (fun (self: a) -> self);
 }
