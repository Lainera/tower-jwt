use crate::{Decoder, Error};
use core::future::Future;
use core::task::{Context, Poll};
use futures::ready;
use http::Request;
use pin_project::pin_project;
use std::marker::PhantomData;
use std::pin::Pin;
use tower::Service;

#[pin_project]
pub struct MiddlewareFuture<B, S, D>
where
    S: Service<Request<B>>,
    D: Decoder,
{
    service: S,
    request: Option<Request<B>>,
    #[pin]
    state: State<D::Future, S::Future>,
    _decoder: PhantomData<fn() -> D>,
}

impl<B, S, D> MiddlewareFuture<B, S, D>
where
    S: Service<Request<B>>,
    D: Decoder,
{
    /// Create new [`MiddlewareFuture`]
    ///
    /// ```rust
    /// # use tower_jwt::{MiddlewareFuture, Decoder, InPlace};
    /// # use serde::Deserialize;
    /// # #[derive(Deserialize)] pub struct Claim { jti: String };
    /// # fn example<B, S>(service: S, request: http::Request<B>, decoder: InPlace<Claim>, token: String )
    /// # where
    /// # S: tower::Service<http::Request<B>>
    /// # {
    /// let decoder_future = decoder.decode(&token);
    /// let fut: MiddlewareFuture<B, S, InPlace<Claim>> = MiddlewareFuture::new(service, request, decoder_future);
    /// # }
    /// ```
    pub fn new(service: S, request: Request<B>, decoder_future: D::Future) -> Self {
        MiddlewareFuture {
            service,
            request: Some(request),
            state: State::Decoding(decoder_future),
            _decoder: PhantomData,
        }
    }
}

#[pin_project(project = StateProject)]
enum State<D, S> {
    Decoding(#[pin] D),
    Responding(#[pin] S),
}

impl<B, S, D> Future for MiddlewareFuture<B, S, D>
where
    S: Service<Request<B>> + Clone + 'static,
    D: Decoder,
    D::Future: Send + Sync + 'static,
    D::Claim: Send + Sync + 'static,
{
    type Output = Result<S::Response, Error<S::Error, D::Error>>;

    #[tracing::instrument(skip_all)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        tracing::trace!("MiddlewareFuture::entered");
        let mut this = self.project();
        loop {
            match this.state.as_mut().project() {
                StateProject::Decoding(mut decoding) => {
                    let outcome = ready!(decoding.as_mut().poll(cx));
                    tracing::trace!("MiddlewareFuture::decoded");
                    match outcome {
                        Ok(claim) => {
                            let mut request = this
                                .request
                                .take()
                                // only way to construct future is via MiddlewareFuture::new(),
                                // which takes ownership of actual request struct
                                .expect("Request was missing on the future");
                            request.extensions_mut().insert::<D::Claim>(claim);
                            tracing::trace!("MiddlewareFuture::modified_request");
                            let fut = this.service.call(request);
                            this.state.set(State::Responding(fut));
                            tracing::trace!("MiddlewareFuture::state_switched");
                        }
                        Err(err) => return Poll::Ready(Err(Error::Decoder(err))),
                    }
                }
                StateProject::Responding(responding) => {
                    tracing::trace!("MiddlewareFuture::polling_inner");
                    return responding.poll(cx).map_err(Error::Inner)
                }
            }
        }
    }
}
