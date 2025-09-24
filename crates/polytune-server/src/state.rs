use std::{collections::HashMap, sync::{mpsc::Sender, Arc, Mutex}};

use uuid::Uuid;

use crate::{api::Policy, channel::{HttpChannel, MsgState}, consts::ConstState};

pub(crate) enum PolicyState {
    Launched(Policy),
    // Todo, we need to parse the garble program at some point to get the number of consts
    // before compiling it, we could store the parsed program to avoid reparsing it (although 
    // this cost is probably negligible)
    Validated(Policy),
    Running(Policy),
    SendingOutput(Policy)
}

// TODO if we want to be able to schedule computations we need to also maintain a queue of 
// scheduled policies. I think for now it makes sense to assume that we only have one fixed
// set of polytune instances on which computation are scheduled. That is, we don't have a case
// where something is schedule for P1 and P2, and for P2 and P3. This would complicate scheduling 
// the computations a lot and should probably be reserved for the future.
// Oooor, we just require for now that whoever calls /schedule on the polytune instances needs
// to do it in the same order for all instances

pub(crate) struct PolytuneStateInner {
    pub(crate) computations: Mutex<HashMap<Uuid, PolicyState>>,
    pub(crate) msg_state: MsgState,
    /// channels are stored here when created during /validate and removed when /run is called
    pub(crate) channels: Mutex<HashMap<Uuid, HttpChannel>>,
    // this will also contain state related to constants and tokio Notifys or channels to coordinate
    // between /launch and the different routes, so that when e.b. an error occurs during validate
    // we can return it from /launch
    pub(crate) const_state: ConstState
}

pub(crate) type PolytuneState = Arc<PolytuneStateInner>;

