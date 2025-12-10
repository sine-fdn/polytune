use garble_lang::literal::Literal as GarbleLiteral;
use url::Url;

use crate::{
    policy::Policy,
    state::{ConstsRequest, MpcMsg, OutputError, RunRequest, ValidateRequest},
};

/// Produces a [`PolicyClient`] for a [`Policy`].
pub trait PolicyClientBuilder {
    /// The associated [`PolicyClient`] type.
    type Client: PolicyClient;

    /// Returns a client suitable for the participants specified in the [`Policy`].
    fn new_client(&self, policy: &Policy) -> Self::Client;
}

/// Handles the communication between two executing [`PolicyStates`].
///
/// This is effectively a trait for a remote procedure call (RPC) client. Calling the
/// methods (except `output`) on this trait must result in the corresponding methods on
/// a [`PolicyStateHandle`] being called on the remote party.
///
/// [`PolicyStates`]: crate::PolicyState
/// [`PolicyStateHandle`]: crate::PolicyStateHandle
pub trait PolicyClient: Send + Sync + 'static {
    /// The error returned by the client's methods.
    type Error: std::error::Error + Send + Sync;

    /// Corresponds to [`PolicyStateHandle::validate()`] on a remote.
    ///
    /// [`PolicyStateHandle::validate()`]: crate::PolicyStateHandle::validate
    fn validate(
        &self,
        to: usize,
        req: ValidateRequest,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Corresponds to [`PolicyStateHandle::run()`] on a remote.
    ///
    /// [`PolicyStateHandle::run()`]: crate::PolicyStateHandle::run
    fn run(
        &self,
        to: usize,
        req: RunRequest,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Corresponds to [`PolicyStateHandle::consts()`] on a remote.
    ///
    /// [`PolicyStateHandle::consts()`]: crate::PolicyStateHandle::consts
    fn consts(
        &self,
        to: usize,
        req: ConstsRequest,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Corresponds to [`PolicyStateHandle::mpc_msg()`] on a remote.
    ///
    /// [`PolicyStateHandle::mpc_msg()`]: crate::PolicyStateHandle::mpc_msg
    fn msg(&self, to: usize, msg: MpcMsg) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Send the output to the specified Url.
    ///
    /// Implementations should log the result in case it is an error
    ///  with a [`tracing::Level::ERROR`] event. Implementations should
    /// emit an error event in case they return an error. This can be conveniently
    /// done by instrumenting the implementation with the `err` annotation.
    ///
    /// ```rust, ignore
    /// #[tracing::instrument(skip(self), err)]
    /// async fn output(
    ///     &self,
    ///     to: Url,
    ///     result: Result<Literal, OutputError>,
    /// ) -> Result<(), Self::Error>> {
    ///     if let Err(err) = result {
    ///         tracing::error!(%err);
    ///     }
    ///     todo!()
    /// }
    ///
    /// ```
    fn output(
        &self,
        to: Url,
        result: Result<GarbleLiteral, OutputError>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
