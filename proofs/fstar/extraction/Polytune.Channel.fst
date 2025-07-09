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

/// Information about a sent message that can be useful for logging.
type t_SendInfo = {
  f_phase:Alloc.String.t_String;
  f_current_msg:usize;
  f_remaining_msgs:usize
}

/// Information about a received message that can be useful for logging.
type t_RecvInfo = {
  f_phase:Alloc.String.t_String;
  f_current_msg:usize;
  f_remaining_msgs:Core.Option.t_Option usize
}

/// A communication channel used to send/receive messages to/from another party.
/// This trait defines the core interface for message transport in the protocol.
/// Implementations of this trait determine how messages are physically sent and received,
/// which can vary based on the environment (network, in-process, etc.).
/// The trait supports both asynchronous and synchronous implementations through
/// the `maybe_async` crate. By default, methods are asynchronous, but synchronous
/// implementations can be created by enabling the `is_sync` feature.
class t_Channel (v_Self: Type0) = {
  f_SendError:Type0;
  f_SendError_4200989935222668608:Core.Fmt.t_Debug f_SendError;
  f_RecvError:Type0;
  f_RecvError_9730327992082288296:Core.Fmt.t_Debug f_RecvError;
  f_send_bytes_to_pre:v_Self -> usize -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global -> t_SendInfo
    -> Type0;
  f_send_bytes_to_post:
      v_Self ->
      usize ->
      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global ->
      t_SendInfo ->
      (v_Self & Core.Result.t_Result Prims.unit f_SendError)
    -> Type0;
  f_send_bytes_to:
      x0: v_Self ->
      x1: usize ->
      x2: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global ->
      x3: t_SendInfo
    -> Prims.Pure (v_Self & Core.Result.t_Result Prims.unit f_SendError)
        (f_send_bytes_to_pre x0 x1 x2 x3)
        (fun result -> f_send_bytes_to_post x0 x1 x2 x3 result);
  f_recv_bytes_from_pre:v_Self -> usize -> t_RecvInfo -> Type0;
  f_recv_bytes_from_post:
      v_Self ->
      usize ->
      t_RecvInfo ->
      (v_Self & Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) f_RecvError)
    -> Type0;
  f_recv_bytes_from:x0: v_Self -> x1: usize -> x2: t_RecvInfo
    -> Prims.Pure
        (v_Self & Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) f_RecvError)
        (f_recv_bytes_from_pre x0 x1 x2)
        (fun result -> f_recv_bytes_from_post x0 x1 x2 result)
}
