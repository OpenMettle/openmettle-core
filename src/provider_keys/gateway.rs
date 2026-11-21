//! ADR 0037 gateway wrapping domain. Only the reconciliation login can reserve a nonce.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper::header::HeaderValue;
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::fmt;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection;
impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("gateway credential protection failed")
    }
}
impl std::error::Error for Protection {}

/// Owns sensitive scratch bytes until the header or ciphertext has been built.
pub struct Bearer(Vec<u8>);
impl Drop for Bearer {
    fn drop(&mut self) {
        // rustls' owning SharedSecret zeroizes both length and spare capacity on drop.
        drop(rustls::crypto::SharedSecret::from(std::mem::take(
            &mut self.0,
        )));
    }
}
impl fmt::Debug for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bearer(..)")
    }
}
impl Bearer {
    pub fn new(bytes: &[u8]) -> Result<Self, Protection> {
        if !(1..=crate::provider_http::MAX_REQUEST_HEADER_BYTES - 128).contains(&bytes.len())
            || !bytes.iter().all(u8::is_ascii_graphic)
        {
            return Err(Protection);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn generate() -> Result<Self, Protection> {
        let mut random = Bearer(vec![0; 32]);
        SystemRandom::new()
            .fill(&mut random.0)
            .map_err(|_| Protection)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(&random.0).into_bytes()))
    }

    pub fn authorization(&self) -> HeaderValue {
        let mut bytes = Self(Vec::with_capacity(7 + self.0.len()));
        bytes.0.extend_from_slice(b"Bearer ");
        bytes.0.extend_from_slice(&self.0);
        let mut value = HeaderValue::from_bytes(&bytes.0).expect("validated bearer");
        value.set_sensitive(true);
        value
    }
}

pub struct Context<'a> {
    pub installation: &'a str,
    pub user_id: &'a str,
    pub binding_id: &'a str,
    pub principal: &'a str,
    pub generation: i64,
}
impl Context<'_> {
    fn aad(&self, id: &str) -> Result<aead::Aad<Vec<u8>>, Protection> {
        if self.generation < 1
            || ![
                self.installation,
                self.user_id,
                self.binding_id,
                self.principal,
            ]
            .into_iter()
            .all(crate::runs::is_canonical_uuid)
        {
            return Err(Protection);
        }
        Ok(aead::Aad::from(crate::runs::identity(
            b"openmettle/gateway-inference-bearer/1\0",
            &[
                self.installation.as_bytes(),
                self.user_id.as_bytes(),
                self.binding_id.as_bytes(),
                self.principal.as_bytes(),
                &self.generation.to_be_bytes(),
                id.as_bytes(),
            ],
        )))
    }
}

pub struct Envelope {
    pub key_id: String,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}
struct Key {
    id: String,
    fingerprint: [u8; 32],
    key: aead::LessSafeKey,
}
/// The inference configuration exposes only decryption.
pub struct GatewayKeys(Vec<Key>);
impl fmt::Debug for GatewayKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayKeys(..)")
    }
}
impl GatewayKeys {
    pub fn new(material: &[(String, [u8; 32])]) -> Result<Self, Protection> {
        if !(1..=4).contains(&material.len()) {
            return Err(Protection);
        }
        let mut keys = Vec::new();
        for (n, (id, raw)) in material.iter().enumerate() {
            if !crate::auth_config::CursorKeys::valid_id(id)
                || material[..n]
                    .iter()
                    .any(|(prev, b)| prev == id || bool::from(b.ct_eq(raw)))
            {
                return Err(Protection);
            }
            keys.push(Key {
                id: id.clone(),
                fingerprint: Sha256::digest(raw).into(),
                key: aead::LessSafeKey::new(
                    aead::UnboundKey::new(&aead::AES_256_GCM, raw).map_err(|_| Protection)?,
                ),
            });
        }
        Ok(Self(keys))
    }
    pub fn open(&self, ctx: &Context<'_>, envelope: &Envelope) -> Result<Bearer, Protection> {
        if !(17..=4112).contains(&envelope.ciphertext.len()) {
            return Err(Protection);
        }
        let key = self
            .0
            .iter()
            .find(|k| k.id == envelope.key_id)
            .ok_or(Protection)?;
        let mut buffer = Bearer(envelope.ciphertext.clone());
        let plain = key
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(envelope.nonce),
                ctx.aad(&key.id)?,
                &mut buffer.0,
            )
            .map_err(|_| Protection)?;
        Bearer::new(plain)
    }
}

/// The gateway process constructs this with its own pool and dedicated mounted ring.
pub struct GatewaySealer {
    keys: GatewayKeys,
    primary: PgPool,
}
impl GatewaySealer {
    pub fn new(keys: GatewayKeys, primary: PgPool) -> Self {
        Self { keys, primary }
    }
    pub async fn seal(
        &self,
        ctx: &Context<'_>,
        bearer: &Bearer,
    ) -> Result<([u8; 32], Envelope), Protection> {
        let key = &self.keys.0[0];
        let aad = ctx.aad(&key.id)?;
        // A collision is retried with new entropy. A lost commit reply fails closed.
        for _ in 0..4 {
            let mut nonce = [0; 12];
            SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| Protection)?;
            let mut tx = crate::runs::WriteTransaction::begin_bounded_pool(&self.primary, false)
                .await
                .map_err(|_| Protection)?;
            let inserted = sqlx::query(
                "INSERT INTO openmettle.gateway_nonces (key_fingerprint,nonce)
                 VALUES ($1,$2) ON CONFLICT DO NOTHING",
            )
            .bind(key.fingerprint.as_slice())
            .bind(nonce.as_slice())
            .execute(tx.connection().map_err(|_| Protection)?)
            .await
            .map_err(|_| Protection)?
            .rows_affected();
            tx.commit().await.map_err(|_| Protection)?;
            if inserted == 0 {
                continue;
            }
            let mut buffer = Bearer(Vec::with_capacity(bearer.0.len() + 16));
            buffer.0.extend_from_slice(&bearer.0);
            key.key
                .seal_in_place_append_tag(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aad,
                    &mut buffer.0,
                )
                .map_err(|_| Protection)?;
            return Ok((
                key.fingerprint,
                Envelope {
                    key_id: key.id.clone(),
                    nonce,
                    ciphertext: std::mem::take(&mut buffer.0),
                },
            ));
        }
        Err(Protection)
    }
    pub fn keys(&self) -> &GatewayKeys {
        &self.keys
    }
}
