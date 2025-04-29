module Serde.De.Impls

open Serde.De

instance impl_deserialize_owned (#a:Type): t_DeserializeOwned a =
 {
 deserialize_owned = (fun (self: a) -> self);
 }

instance impl_deserialize (#a:Type): t_Deserialize a =
 {
 deserialize = (fun (self: a) -> self);
 }
