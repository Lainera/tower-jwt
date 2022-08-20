#![doc = include_str!("../Readme.md")]
//! # Examples
//!
//! With [`InPlace`][decoder::InPlace] decoder:
//!
//!```rust
//!# use serde::Deserialize;
//!# fn set_auth_token(req: &mut http::Request<()>) {}
//!# async fn example<S: tower::Service<http::Request<()>> + Clone + 'static>(
//!# key: jsonwebtoken::DecodingKey,
//!# validation: jsonwebtoken::Validation, service: S) {
//!use tower_jwt::{InPlace, Middleware};
//!use tower::Service;
//!
//!#[derive(Deserialize)]
//!struct Claim { jti: String }
//!
//!let decoder = InPlace::<Claim>::new(key, validation);
//!let mut middleware = Middleware::new(decoder, service);
//!
//!let mut req = http::Request::new(());
//!set_auth_token(&mut req);
//!
//!// use as tower service
//!middleware.call(req).await;
//!// inner services have `Claim` set on req.extensions()!
//!# }
//!```
//!
//!Slightly more involved with custom decoder:
//!
//!```rust
//!# use std::{sync::Arc, pin::Pin, task, future::Future};
//!# use tokio::sync::oneshot;
//!# use serde::Deserialize;
//!# use tower_jwt::Decoder;
//!# use jsonwebtoken::{errors::Error, Validation, DecodingKey, Algorithm::EdDSA};
//!# pub mod rayon {pub struct ThreadPool; impl ThreadPool {pub fn spawn<F: FnOnce()>(&self, func: F){}}}
//!# pub struct PoolFuture<T, E> {inner: oneshot::Receiver<Result<T, E>>}
//!# #[derive(Clone)] pub struct Context {issuer: String, decoding_key: DecodingKey};
//!# #[derive(Deserialize)] pub struct Claim {jti: String}
//!# pub struct DecoderFuture<F>(F);
//!# impl<F> DecoderFuture<F> { pub fn new(f: F) -> Self { Self(f) } }
//!# impl<F> Future for DecoderFuture<F> {
//!# type Output = Result<Claim, Error>;
//!# fn poll(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> task::Poll<Self::Output>{todo!()}}
//!// Say you have a separate worker pool for crypto tasks:
//!#[derive(Clone)]
//!pub struct Dispatcher {
//!    pool: Arc<rayon::ThreadPool>,
//!    context: Context,
//!}
//!// Which can spawn blocking work and return a future:
//!impl Dispatcher {
//!    pub fn spawn<F, T, E>(&self, op: F) -> PoolFuture<T, E>
//!    where
//!        F: Fn(Context) -> Result<T, E> + Send + 'static,
//!        T: Send + 'static,
//!        E: Send + 'static,
//!    {
//!        let (tx, rx) = oneshot::channel();
//!        let context = self.context.clone();
//!
//!        self.pool.spawn(move || {
//!            let outcome = op(context);
//!            let _ = tx.send(outcome);
//!        });
//!
//!        PoolFuture { inner: rx }
//!    }
//!}
//!
//!// Then you can implement Decoder for Dispatcher like so:
//!impl Decoder for Dispatcher {
//!    type Error = jsonwebtoken::errors::Error;
//!    type Claim = Claim;
//!    type Future = DecoderFuture<PoolFuture<Self::Claim, Self::Error>>;
//!
//!    fn decode(&self, token: &str) -> Self::Future {
//!        let token = token.to_owned();
//!        let future = self.spawn(move |context| {
//!            let mut validation = Validation::new(EdDSA);
//!            validation.set_issuer(&[&context.issuer]);
//!            jsonwebtoken::decode::<Claim>(&token, &context.decoding_key, &validation)
//!                .map(|token_data| token_data.claims)
//!        });
//!
//!        DecoderFuture::new(future)
//!    }
//!}
//!
//!```

use futures::future::Either;
use http::Request;
use serde::de::DeserializeOwned;
use std::future::Ready;
use std::task::{Context, Poll};
use thiserror::Error;
use tower::Service;
use typed_headers::{Authorization, HeaderMapExt};

mod decoder;
pub use decoder::{Decoder, InPlace, InPlaceBuilder};

mod future;
pub use future::MiddlewareFuture;

#[cfg(test)]
mod util;

#[derive(Debug, Clone)]
/// - Parses `Authorization` header off the incoming request
/// - Decodes the token or rejects the request
/// - Sets decoded claim in request extensions
pub struct Middleware<D, S> {
    service: S,
    decoder: D,
}

#[derive(Debug, Clone)]
pub struct Layer<D> {
    decoder: D,
}

impl<D> Layer<D> {
    pub fn new(decoder: D) -> Self {
        Self { decoder }
    }
}

impl<S, D> tower::Layer<S> for Layer<D>
where
    D: Decoder + Clone,
{
    type Service = Middleware<D, S>;

    fn layer(&self, inner: S) -> Self::Service {
        let decoder = self.decoder.clone();
        Middleware::new(decoder, inner)
    }
}

impl<D, S> Middleware<D, S> {
    pub fn new(decoder: D, service: S) -> Self {
        Middleware { service, decoder }
    }
}

impl<D, S, B> Service<Request<B>> for Middleware<D, S>
where
    S: Service<Request<B>> + Clone + 'static,
    D: Decoder,
    D::Claim: DeserializeOwned + Send + Sync + 'static,
    D::Future: Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = Error<S::Error, D::Error>;
    type Future = Either<MiddlewareFuture<B, S, D>, Ready<Result<S::Response, Self::Error>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(Error::Inner)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let token = match req
            .headers()
            .typed_get::<Authorization>()
            .ok()
            .flatten()
            .and_then(|header| header.as_bearer().map(|h| h.as_str().to_owned()))
        {
            Some(authorization_header) => authorization_header,
            _ => return Either::Right(std::future::ready(Err(Error::MissingAuthorizationHeader))),
        };

        let clone = self.service.clone();
        let service = core::mem::replace(&mut self.service, clone);
        let decoder_future = self.decoder.decode(&token);
        Either::Left(MiddlewareFuture::new(service, req, decoder_future))
    }
}

#[derive(Error, Debug)]
/// Combines underlying [service][tower::Service] errors
/// with [`Decoder`] errors
pub enum Error<E, D> {
    #[error("Authorization header must be set")]
    MissingAuthorizationHeader,

    #[error("Failed to decode token: {0}")]
    Decoder(D),

    #[error(transparent)]
    Inner(#[from] E),
}

#[cfg(test)]
mod tests {
    use super::Middleware;
    use crate::util;
    use core::future::Ready;
    use http::{HeaderValue, Request, Response, StatusCode};
    use std::{
        marker::PhantomData,
        task::{Context, Poll},
    };
    use tower::Service;

    #[derive(Debug, Clone)]
    struct S<B>(PhantomData<B>);

    impl<B> Service<Request<B>> for S<B> {
        type Response = Response<util::Claim>;
        type Error = ();
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<B>) -> Self::Future {
            match req.extensions().get::<util::Claim>() {
                Some(claim) => {
                    let claim = claim.clone();
                    let mut res = Response::new(claim);
                    *res.status_mut() = StatusCode::OK;
                    std::future::ready(Ok(res))
                }
                None => std::future::ready(Err(())),
            }
        }
    }

    #[tokio::test]
    async fn e2e() {
        let svc = S::<()>(PhantomData);
        let decoder = util::in_place_decoder();
        let mut middleware = Middleware::new(decoder, svc);

        let mut req = Request::new(());
        let claim = util::claim(Some(100));
        let token = util::token(&claim);

        req.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", token)
                .parse::<HeaderValue>()
                .expect("Failed to parse valid header"),
        );

        let outcome = middleware.call(req).await;
        assert!(outcome.is_ok());
        let response = outcome.unwrap().into_body();
        assert_eq!(response, claim);
    }
}
