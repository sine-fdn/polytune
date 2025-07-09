module Polytune.Swankyot
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

/// Errors occurring during preprocessing.
type t_Error =
  | Error_ChannelErr : Polytune.Channel.t_Error -> t_Error
  | Error_KOSConsistencyCheckFailed : t_Error
  | Error_EmptyMsg : t_Error
  | Error_InvalidLength : t_Error
