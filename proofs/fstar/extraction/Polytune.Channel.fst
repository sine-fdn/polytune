module Polytune.Channel
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Serde.De in
  let open Serde.Ser in
  ()

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

/// Serializes and sends an MPC message to the other party.
assume
val send_to':
    #v_S: Type0 ->
    #iimpl_951670863_: Type0 ->
    {| i2: Serde.Ser.t_Serialize v_S |} ->
    {| i3: Core.Fmt.t_Debug v_S |} ->
    {| i4: t_Channel iimpl_951670863_ |} ->
    channel: iimpl_951670863_ ->
    party: usize ->
    phase: string ->
    msg: t_Slice v_S
  -> (iimpl_951670863_ & Core.Result.t_Result Prims.unit t_Error)

let send_to
      (#v_S #iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Serde.Ser.t_Serialize v_S)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Fmt.t_Debug v_S)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: t_Channel iimpl_951670863_)
     = send_to' #v_S #iimpl_951670863_ #i2 #i3 #i4

/// Receives and deserializes an MPC message from the other party.
assume
val recv_from':
    #v_T: Type0 ->
    #iimpl_951670863_: Type0 ->
    {| i2: Serde.De.t_DeserializeOwned v_T |} ->
    {| i3: Core.Fmt.t_Debug v_T |} ->
    {| i4: t_Channel iimpl_951670863_ |} ->
    channel: iimpl_951670863_ ->
    party: usize ->
    phase: string
  -> (iimpl_951670863_ & Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) t_Error)

let recv_from
      (#v_T #iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Serde.De.t_DeserializeOwned v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Fmt.t_Debug v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: t_Channel iimpl_951670863_)
     = recv_from' #v_T #iimpl_951670863_ #i2 #i3 #i4

/// Receives and deserializes a Vec from the other party (while checking the length).
let recv_vec_from
      (#v_T #iimpl_951670863_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Serde.De.t_DeserializeOwned v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Fmt.t_Debug v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: t_Channel iimpl_951670863_)
      (channel: iimpl_951670863_)
      (party: usize)
      (phase: string)
      (len: usize)
    : (iimpl_951670863_ & Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) t_Error) =
  let tmp0, out:(iimpl_951670863_ &
    Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) t_Error) =
    recv_from #v_T #iimpl_951670863_ channel party phase
  in
  let channel:iimpl_951670863_ = tmp0 in
  match out <: Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) t_Error with
  | Core.Result.Result_Ok (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) ->
    let hax_temp_output:Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) t_Error =
      if (Alloc.Vec.impl_1__len #v_T #Alloc.Alloc.t_Global v <: usize) =. len
      then
        Core.Result.Result_Ok v
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) t_Error
      else
        Core.Result.Result_Err
        ({
            f_phase = Alloc.String.f_to_string #string #FStar.Tactics.Typeclasses.solve phase;
            f_reason = ErrorKind_InvalidLength <: t_ErrorKind
          }
          <:
          t_Error)
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) t_Error
    in
    channel, hax_temp_output
    <:
    (iimpl_951670863_ & Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) t_Error)
  | Core.Result.Result_Err err ->
    channel,
    (Core.Result.Result_Err err
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) t_Error)
    <:
    (iimpl_951670863_ & Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) t_Error)
