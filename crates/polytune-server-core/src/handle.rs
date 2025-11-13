use tokio::sync::{mpsc, oneshot};
use tracing::error;

use crate::{
    policy::Policy,
    state::{
        CancelError, ConstsError, ConstsRequest, MpcMsg, MpcMsgError, PolicyCmd, RunError,
        RunRequest, ScheduleError, ValidateError, ValidateRequest,
    },
};

/// A handle for an executing [`PolicyState`] state-machine.
///
/// This cheaply clonable handle to an executing [`PolicyState`] is used
/// to control the state-machine.
///
/// [`PolicyState`]: crate::PolicyState
#[derive(Clone)]
pub struct PolicyStateHandle(pub(crate) mpsc::Sender<PolicyCmd>);

/// Errors when controlling [`PolicyState`] state-machine.
///  
/// [`PolicyState`]: crate::PolicyState
#[derive(thiserror::Error, Debug)]
pub enum HandleError<E> {
    /// The state-machine for this handle is stopped.
    #[error("state machine for this handle is stopped")]
    StateMachineStopped,
    /// An error returned by the state-machine.
    ///
    /// The `E` parameter depends on the method called on [`PolicyStateHandle`].
    #[error("policy state error")]
    PolicyStateError(E),
}

impl PolicyStateHandle {
    /// Schedule the [`Policy`] for execution.
    ///
    /// This returns once [`PolicyStateHandle::schedule`] has been called on all parties and
    /// they have validated their provided policies (i.e. [`PolicyStateHandle::validate`] has been called).
    /// Therefore, calling `schedule` sequentially will result in a deadlock. Instead,`schedule`
    /// needs to be called concurrently for all parties, e.g.:
    /// ```rust, ignore
    /// join!(
    ///   handle_p1.schedule(policy1),
    ///   handle_p2.schedule(policy1)
    /// )
    /// ```
    pub async fn schedule(&self, req: Policy) -> Result<(), HandleError<ScheduleError>> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.0.send(PolicyCmd::Schedule(req, ret_tx)).await?;
        ret_rx.await?.map_err(HandleError::PolicyStateError)
    }

    /// Handle the [`ValidateRequest`].
    ///
    /// This can be called either before or during [`PolicyStateHandle::schedule`]. Note that a previous
    /// `schedule` call for a non-leader will only return once `validate` has been called.
    pub async fn validate(&self, req: ValidateRequest) -> Result<(), HandleError<ValidateError>> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.0.send(PolicyCmd::Validate(req, ret_tx)).await?;
        ret_rx.await?.map_err(HandleError::PolicyStateError)
    }

    /// Handle the [`RunRequest`].
    pub async fn run(&self, req: RunRequest) -> Result<(), HandleError<RunError>> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.0.send(PolicyCmd::Run(req, Some(ret_tx))).await?;
        ret_rx.await?.map_err(HandleError::PolicyStateError)
    }

    /// Handle the [`ConstsRequest`].
    pub async fn consts(&self, req: ConstsRequest) -> Result<(), HandleError<ConstsError>> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.0.send(PolicyCmd::Consts(req, ret_tx)).await?;
        ret_rx.await?.map_err(HandleError::PolicyStateError)
    }

    /// Handle the [`MpcMsg`].
    ///
    /// This message is passed on to the executing Polytune instance.
    pub async fn mpc_msg(&self, req: MpcMsg) -> Result<(), HandleError<MpcMsgError>> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.0.send(PolicyCmd::MpcMsg(req, ret_tx)).await?;
        ret_rx.await?.map_err(HandleError::PolicyStateError)
    }

    /// Cancel this [`Policy`] evaluation.
    ///
    /// If [`Policy.output`](`Policy`) is set, cancelling will try to notify the output
    /// destination.
    pub fn cancel(&self) -> impl Future<Output = Result<(), HandleError<CancelError>>> + use<> {
        let (ret_tx, ret_rx) = oneshot::channel();
        let cmd_tx = self.0.clone();
        async move {
            cmd_tx.send(PolicyCmd::Cancel(ret_tx)).await?;
            ret_rx.await?.map_err(HandleError::PolicyStateError)
        }
    }
}

impl<T, E> From<mpsc::error::SendError<T>> for HandleError<E> {
    fn from(_: mpsc::error::SendError<T>) -> Self {
        Self::StateMachineStopped
    }
}

impl<E> From<oneshot::error::RecvError> for HandleError<E> {
    fn from(_: oneshot::error::RecvError) -> Self {
        error!("ret sender dropped");
        Self::StateMachineStopped
    }
}
