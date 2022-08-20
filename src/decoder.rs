use jsonwebtoken::{DecodingKey, Validation};
use serde::de::DeserializeOwned;
use std::{
    future::{self, Future, Ready},
    marker::PhantomData,
    sync::Arc,
};

/// Implementors are capable of decoding jwt tokens returning associated claim or error.
pub trait Decoder {
    type Error;
    type Claim: DeserializeOwned + 'static;
    type Future: Future<Output = Result<Self::Claim, Self::Error>>;

    fn decode(&self, token: &str) -> Self::Future;
}

impl<C> Decoder for InPlace<C>
where
    C: DeserializeOwned + 'static,
{
    type Error = jsonwebtoken::errors::Error;
    type Claim = C;
    type Future = Ready<Result<Self::Claim, Self::Error>>;

    fn decode(&self, token: &str) -> Self::Future {
        let decoded = jsonwebtoken::decode::<Self::Claim>(token, &self.key, &self.validation)
            .map(|token_data| token_data.claims);

        future::ready(decoded)
    }
}

/// Simplest implementer of [`Decoder`] trait which
/// decodes tokens in-place leveraging `jsonwebtoken` crate
pub struct InPlace<C> {
    validation: Validation,
    key: Arc<DecodingKey>,
    _claim: PhantomData<fn() -> C>,
}

impl<C> Clone for InPlace<C> {
    fn clone(&self) -> Self {
        Self {
            validation: self.validation.clone(),
            key: self.key.clone(),
            _claim: PhantomData,
        }
    }
}

impl<C> InPlace<C> {
    pub fn new(key: DecodingKey, validation: Validation) -> Self {
        Self {
            key: Arc::new(key),
            validation,
            _claim: PhantomData,
        }
    }

    pub fn builder() -> InPlaceBuilder<Empty, Empty> {
        Default::default()
    }
}

#[derive(Debug, Default)]
pub struct Empty;

pub struct InPlaceBuilder<K, V> {
    key: K,
    validation: V,
}

impl Default for InPlaceBuilder<Empty, Empty> {
    fn default() -> Self {
        Self {
            key: Default::default(),
            validation: Default::default(),
        }
    }
}

impl InPlaceBuilder<DecodingKey, Validation> {
    pub fn build<C>(self) -> InPlace<C> {
        let Self { key, validation } = self;
        InPlace {
            validation,
            key: Arc::new(key),
            _claim: PhantomData,
        }
    }
}

impl<K, V> InPlaceBuilder<K, V> {
    pub fn new(key: K, validation: V) -> Self {
        Self { key, validation }
    }

    pub fn set_key(self, key: DecodingKey) -> InPlaceBuilder<DecodingKey, V> {
        let Self { validation, .. } = self;
        InPlaceBuilder { validation, key }
    }

    pub fn set_validation(self, validation: Validation) -> InPlaceBuilder<K, Validation> {
        let Self { key, .. } = self;
        InPlaceBuilder { key, validation }
    }
}

#[cfg(test)]
mod test {
    use crate::{util, Decoder};

    #[tokio::test]
    async fn in_place_not_expired() {
        let decoder = util::in_place_decoder();
        let valid = util::claim(Some(100));
        let result = decoder.decode(&util::token(&valid)).await;

        assert!(
            result.is_ok(),
            "Failed to decode token with in-place decoder"
        );
        let decoded = result.unwrap();

        assert_eq!(decoded, valid);
    }

    #[tokio::test]
    async fn in_place_expired() {
        let decoder = util::in_place_decoder();
        let expired = util::claim(None);
        let result = decoder.decode(&util::token(&expired)).await;

        match result {
            Err(err) => {
                assert_eq!(
                    err.kind(),
                    &jsonwebtoken::errors::ErrorKind::ExpiredSignature
                );
            }
            _ => unreachable!("Decoded expired claim"),
        }
    }
}
