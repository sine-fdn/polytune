#![allow(missing_docs)] // Remove once module is improved
// TODO I think this module will require some changes once we actually implement
// a client using HTTP communication, specifically the error handling might need
// changes.
use std::convert::Infallible;

use garble_lang::literal::Literal as GarbleLiteral;
use url::Url;

use crate::{
    policy::Policy,
    state::{
        ConstsError, ConstsRequest, MpcMsg, MpcMsgError, OutputError, RunError, RunRequest,
        ValidateError, ValidateRequest,
    },
};

pub trait PolicyClientBuilder {
    type Client: PolicyClient;

    fn new_client(&self, policy: &Policy) -> Self::Client;
}

pub trait PolicyClient: Send + Sync + 'static {
    type ClientError<E>: std::error::Error + Send + Sync
    where
        E: std::error::Error + Send + Sync;

    fn validate(
        &self,
        to: usize,
        req: ValidateRequest,
    ) -> impl std::future::Future<Output = Result<(), Self::ClientError<ValidateError>>> + Send;

    fn run(
        &self,
        to: usize,
        req: RunRequest,
    ) -> impl std::future::Future<Output = Result<(), Self::ClientError<RunError>>> + Send;

    fn consts(
        &self,
        to: usize,
        req: ConstsRequest,
    ) -> impl Future<Output = Result<(), Self::ClientError<ConstsError>>> + Send;

    fn msg(
        &self,
        to: usize,
        msg: MpcMsg,
    ) -> impl Future<Output = Result<(), Self::ClientError<MpcMsgError>>> + Send;

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
    /// ) -> Result<(), Self::ClientError<Infallible>> {
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
    ) -> impl Future<Output = Result<(), Self::ClientError<Infallible>>> + Send;
}
