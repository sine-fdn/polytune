module Polytune.Channel
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

/// The specific error that occurred when trying to send / receive a message.
type t_ErrorKind =
  | ErrorKind_RecvError : Alloc.String.t_String -> t_ErrorKind
  | ErrorKind_SendError : Alloc.String.t_String -> t_ErrorKind
  | ErrorKind_SerdeError : Alloc.String.t_String -> t_ErrorKind
  | ErrorKind_InvalidLength : t_ErrorKind

/// Errors related to sending / receiving / (de-)serializing messages.
type t_Error = {
  f_phase:Alloc.String.t_String;
  f_reason:t_ErrorKind
}
