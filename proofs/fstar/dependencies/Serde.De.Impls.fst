module Serde.De.Impls

open Serde.De

instance impl_deserialize_owned (#a:Type): t_DeserializeOwned a =
 {
 deserialize = (fun (self: a) -> self);
 }
