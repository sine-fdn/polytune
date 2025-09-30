use std::{collections::HashMap, mem, ops::Deref, sync::Arc};

use axum::extract::FromRef;
use garble_lang::GarbleConsts;
use parking_lot::Mutex;
use tokio::sync::{
    Notify,
    mpsc::{self, Sender},
    oneshot,
};
use uuid::Uuid;

use crate::{
    api::{Policy, ValidateError, ValidatePolicyRequest},
    channel::{HttpChannel, MsgState},
    consts::{ConstState, Consts},
    mpc::ScheduledPolicy,
};

#[derive(Default)]
pub(crate) enum PolicyState {
    #[default]
    Empty,
    // TODO Add a validate requested state with a sender where /schedule can send a
    // policy if /schedule is called after /validate ?
    ValidateRequested(
        Arc<Notify>,
        oneshot::Receiver<Result<(), ValidateError>>,
    ),
    Scheduled(Policy, oneshot::Sender<Result<(), ValidateError>>),
    // Todo, we need to parse the garble program at some point to get the number of consts
    // before compiling it, we could store the parsed program to avoid reparsing it (although
    // this cost is probably negligible)
    Validated(Policy, oneshot::Receiver<GarbleConsts>),
    Running(Policy),
    SendingOutput(Policy),
}

pub(crate) enum PolicyCompatError {}

impl PolicyState {
    pub(crate) fn compatible_with(
        &self,
        req: &ValidatePolicyRequest,
    ) -> Result<(), PolicyCompatError> {
        // TODO
        Ok(())
    }

    pub(crate) fn to_validated(
        &mut self,
        const_receiver: oneshot::Receiver<GarbleConsts>,
    ) -> oneshot::Sender<Result<(), ValidateError>> {
        match mem::take(self) {
            PolicyState::Scheduled(policy, sender) => {
                *self = PolicyState::Validated(policy, const_receiver);
                return sender;
            }
            _ => panic!("invalid state transition"),
        }
    }
}

// TODO if we want to be able to schedule computations we need to also maintain a queue of
// scheduled policies. I think for now it makes sense to assume that we only have one fixed
// set of polytune instances on which computation are scheduled. That is, we don't have a case
// where something is schedule for P1 and P2, and for P2 and P3. This would complicate scheduling
// the computations a lot and should probably be reserved for the future.
// Oooor, we just require for now that whoever calls /schedule on the polytune instances needs
// to do it in the same order for all instances

pub(crate) struct PolytuneStateInner {
    pub(crate) client: reqwest_middleware::ClientWithMiddleware,
    pub(crate) computations: Mutex<HashMap<Uuid, PolicyState>>,
    pub(crate) msg_state: MsgState,
    pub(crate) schedule_sender: mpsc::Sender<ScheduledPolicy>,
    /// channels are stored here when created during /validate and removed when /run is called
    pub(crate) channels: Mutex<HashMap<Uuid, HttpChannel>>,
    // this will also contain state related to constants and tokio Notifys or channels to coordinate
    // between /launch and the different routes, so that when e.b. an error occurs during validate
    // we can return it from /launch
    pub(crate) const_state: ConstState,
}

#[derive(Clone)]
pub(crate) struct PolytuneState(pub(crate) Arc<PolytuneStateInner>);

impl PolytuneState {
    pub(crate) fn new(
        concurrency: usize,
        client: reqwest_middleware::ClientWithMiddleware,
    ) -> (Self, mpsc::Receiver<ScheduledPolicy>) {
        let (schedule_sender, schedule_receiver) = mpsc::channel(concurrency);
        let state = Arc::new(PolytuneStateInner {
            client,
            computations: Default::default(),
            msg_state: Default::default(),
            schedule_sender,
            channels: Default::default(),
            const_state: Default::default(),
        });
        (PolytuneState(state), schedule_receiver)
    }
}

impl Deref for PolytuneState {
    type Target = PolytuneStateInner;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl FromRef<PolytuneState> for ConstState {
    fn from_ref(input: &PolytuneState) -> Self {
        Arc::clone(&input.0.const_state)
    }
}

impl FromRef<PolytuneState> for MsgState {
    fn from_ref(input: &PolytuneState) -> Self {
        Arc::clone(&input.0.msg_state)
    }
}
