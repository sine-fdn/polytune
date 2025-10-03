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

    fn output(
        &self,
        to: Url,
        result: Result<GarbleLiteral, OutputError>,
    ) -> impl Future<Output = Result<(), Self::ClientError<Infallible>>> + Send;
}
