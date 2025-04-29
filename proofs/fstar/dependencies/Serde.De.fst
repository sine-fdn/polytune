module Serde.De
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"

class t_DeserializeOwned (t_Self:Type) = {
  deserialize: unit -> t_Self
}
