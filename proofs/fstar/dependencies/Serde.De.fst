module Serde.De
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"

class t_DeserializeOwned (t_Self:Type) = {
  deserialize_owned: t_Self -> t_Self
}

class t_Deserialize (t_Self:Type) = {
  deserialize: t_Self -> t_Self
}
