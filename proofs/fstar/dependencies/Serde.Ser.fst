module Serde.Ser
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"

class t_Serialize (t_Self:Type) = {
  serialize: t_Self -> unit
  }
