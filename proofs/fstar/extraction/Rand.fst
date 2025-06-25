module Rand
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"

class t_Rand (t_Self:Type) = {
  random: unit -> t_Self
}
