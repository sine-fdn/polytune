module Rand.Rng
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"

class t_Rng (t_Self:Type) = {
  f_gen: t_Self -> t_Self
}
