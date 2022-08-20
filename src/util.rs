//! Test helpers

use crate::{InPlace, InPlaceBuilder};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

// please don't use that keypair in your project. You can generate your own key with openssl:
// openssl genpkey -algorithm ed25519 -out secret_key
// openssl pkey -in secret_key -out public_key -pubout
pub(crate) const PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhlrQQ+GtqfopmxV4+o5H0oJ0QBsGRtgSSCO7e49vZI0=
-----END PUBLIC KEY-----
"#;

pub(crate) const PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINzPz89F+4jSACy7X//keAl7vvplC9gjqqB7GyfcKua0
-----END PRIVATE KEY-----
"#;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub(crate) struct Claim {
    sub: String,
    jti: String,
    role: String,
    iss: String,
    exp: i64,
    iat: i64,
}

pub(crate) fn claim(expiry: Option<i64>) -> Claim {
    let (iat, exp) = match expiry {
        Some(expiry) => {
            let iat = Utc::now();
            let exp = iat
                .checked_add_signed(Duration::seconds(expiry))
                .expect("Too far in the future");
            (iat, exp)
        }
        // Produce expired token
        None => {
            let iat = Utc::now()
                .checked_sub_signed(Duration::seconds(100))
                .expect("System clock is off");
            let exp = iat
                .checked_add_signed(Duration::seconds(10))
                .expect("Too far in the future");

            (iat, exp)
        }
    };

    Claim {
        sub: "sub".into(),
        jti: "jti".into(),
        role: "moderator".into(),
        iss: "issuer".into(),
        exp: exp.timestamp(),
        iat: iat.timestamp(),
    }
}

pub(crate) fn token(claim: &Claim) -> String {
    let header = Header::new(jsonwebtoken::Algorithm::EdDSA);
    let key = jsonwebtoken::EncodingKey::from_ed_pem(PRIVATE_KEY.as_bytes())
        .expect("Failed to create encoding key from valid bytes");
    encode(&header, claim, &key).expect("failed to encode valid claim")
}

pub(crate) fn in_place_decoder() -> InPlace<Claim> {
    InPlaceBuilder::new(
        DecodingKey::from_ed_pem(PUBLIC_KEY.as_bytes()).expect("Failed to parse valid key"),
        Validation::new(jsonwebtoken::Algorithm::EdDSA),
    )
    .build()
}
