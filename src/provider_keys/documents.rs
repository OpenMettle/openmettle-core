//! Strict online document profile; offline verifier parsing is unchanged.
use super::{Error, ProviderConfig};
use crate::auth::{MAX_JWKS_BYTES, MAX_JWKS_KEYS};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{HttpResponse, core::CoreJsonWebKeySet};
use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::{
    collections::HashSet,
    fmt,
    time::{Duration, SystemTime},
};

// Reject duplicate members at every depth, including ignored extensions. serde_json retains its
// default recursion limit. The streaming transport and this entry point both cap document bytes.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded JSON")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut values = Map::new();
                while let Some((key, Unique(value))) = a.next_entry::<String, Unique>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate member"));
                    }
                }
                Ok(Unique(Value::Object(values)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(v)) = a.next_element()? {
                    values.push(v);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                Ok(Unique(
                    serde_json::Number::from_f64(v)
                        .ok_or_else(|| E::custom("number"))?
                        .into(),
                ))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(V)
    }
}
pub(crate) fn json(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.is_empty() || bytes.len() > MAX_JWKS_BYTES {
        return Err(Error::Document);
    }
    serde_json::from_slice::<Unique>(bytes)
        .map(|v| v.0)
        .map_err(|_| Error::Document)
}
#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    grant_types_supported: Option<Vec<String>>,
    response_modes_supported: Option<Vec<String>>,
    scopes_supported: Option<Vec<String>>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    code_challenge_methods_supported: Option<Vec<String>>,
    authorization_response_iss_parameter_supported: Option<bool>,
}
pub(super) fn metadata(bytes: &[u8], config: &ProviderConfig) -> Result<(), Error> {
    let value = json(bytes)?;
    for name in [
        "grant_types_supported",
        "response_modes_supported",
        "scopes_supported",
        "token_endpoint_auth_methods_supported",
        "code_challenge_methods_supported",
    ] {
        if value.get(name).is_some_and(|v| !v.is_array()) {
            return Err(Error::Document);
        }
    }
    if value
        .get("authorization_response_iss_parameter_supported")
        .is_some_and(|v| !v.is_boolean())
    {
        return Err(Error::Document);
    }
    let m: Metadata = serde_json::from_value(value).map_err(|_| Error::Document)?;
    if m.issuer != config.identity.binding().1
        || m.authorization_endpoint != config.authorization
        || m.token_endpoint != config.token_url
        || m.jwks_uri != config.jwks_url
    {
        return Err(Error::Mismatch);
    }
    let has = |v: &[String], s: &str| v.iter().any(|x| x == s);
    if !has(&m.response_types_supported, "code")
        || !m
            .subject_types_supported
            .iter()
            .any(|s| s == "public" || s == "pairwise")
        || !has(&m.id_token_signing_alg_values_supported, "RS256")
        || m.grant_types_supported
            .is_some_and(|v| !has(&v, "authorization_code"))
        || m.response_modes_supported
            .is_some_and(|v| !has(&v, "query"))
        || m.token_endpoint_auth_methods_supported
            .is_none_or(|v| !has(&v, "none"))
        || m.code_challenge_methods_supported
            .is_none_or(|v| !has(&v, "S256"))
        || m.authorization_response_iss_parameter_supported != Some(true)
    {
        return Err(Error::Mismatch);
    }
    // Scopes advertising is recommended, not exhaustive or required.
    let _ = m.scopes_supported;
    Ok(())
}
pub(super) struct Keys {
    pub keys: CoreJsonWebKeySet,
    pub kids: Vec<Option<String>>,
}
fn optional_string<'a>(key: &'a Map<String, Value>, name: &str) -> Result<Option<&'a str>, Error> {
    key.get(name)
        .map(|v| v.as_str().ok_or(Error::Document))
        .transpose()
}
fn integer(s: &str) -> Result<Vec<u8>, Error> {
    let value = URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::Document)?;
    if value.is_empty() {
        return Err(Error::Document);
    }
    Ok(value)
}
pub(super) fn keys(bytes: &[u8]) -> Result<Keys, Error> {
    let root = json(bytes)?;
    let raw = root
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(Error::Document)?;
    if raw.len() > MAX_JWKS_KEYS {
        return Err(Error::Document);
    }
    let mut selected = Vec::new();
    let mut kids = Vec::new();
    let mut seen = HashSet::new();
    for raw_key in raw {
        let key = raw_key.as_object().ok_or(Error::Document)?;
        let kty = optional_string(key, "kty")?.ok_or(Error::Document)?;
        if kty == "oct"
            || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|n| key.contains_key(*n))
        {
            return Err(Error::Document);
        }
        let kid = optional_string(key, "kid")?;
        if kid.is_some_and(|v| v.len() > 256 || v.contains('\0')) {
            return Err(Error::Document);
        }
        let alg = optional_string(key, "alg")?;
        let usage = optional_string(key, "use")?;
        for name in ["n", "e", "x", "y", "x5t", "x5t#S256"] {
            if let Some(s) = optional_string(key, name)? {
                integer(s)?;
            }
        }
        for name in ["crv", "x5u"] {
            optional_string(key, name)?;
        }
        if let Some(certs) = key.get("x5c") {
            for v in certs.as_array().ok_or(Error::Document)? {
                base64::engine::general_purpose::STANDARD
                    .decode(v.as_str().ok_or(Error::Document)?)
                    .map_err(|_| Error::Document)?;
            }
        }
        let ops = key
            .get("key_ops")
            .map(|v| -> Result<Vec<&str>, Error> {
                let ops = v
                    .as_array()
                    .ok_or(Error::Document)?
                    .iter()
                    .map(|v| v.as_str().ok_or(Error::Document))
                    .collect::<Result<Vec<_>, _>>()?;
                let unique: HashSet<_> = ops.iter().collect();
                if unique.len() != ops.len() {
                    return Err(Error::Document);
                }
                Ok(ops)
            })
            .transpose()?;
        if ops
            .as_ref()
            .is_some_and(|v| v.as_slice() != ["verify"] || usage.is_some_and(|u| u != "sig"))
        {
            return Err(Error::Document);
        }
        // Validate recognized public material before filtering by algorithm/use.
        let rsa_bits = match kty {
            "RSA" => {
                let n = integer(optional_string(key, "n")?.ok_or(Error::Document)?)?;
                let start = n.iter().position(|b| *b != 0).ok_or(Error::Document)?;
                let bits = (n.len() - start) * 8 - n[start].leading_zeros() as usize;
                if n.last().is_none_or(|b| b % 2 == 0) {
                    return Err(Error::Document);
                }
                let small_n = if bits <= 32 {
                    Some(
                        n[start..]
                            .iter()
                            .fold(0u64, |a, b| (a << 8) | u64::from(*b)),
                    )
                } else {
                    None
                };
                let e = integer(optional_string(key, "e")?.ok_or(Error::Document)?)?;
                let start = e.iter().position(|b| *b != 0).ok_or(Error::Document)?;
                if e.len() - start > 4 {
                    return Err(Error::Document);
                }
                let e = e[start..]
                    .iter()
                    .fold(0u64, |a, b| (a << 8) | u64::from(*b));
                if e < 3 || e % 2 == 0 || small_n.is_some_and(|n| e >= n) {
                    return Err(Error::Document);
                }
                Some(bits)
            }
            "EC" | "OKP" => {
                let curve = optional_string(key, "crv")?.ok_or(Error::Document)?;
                let size = match (kty, curve) {
                    ("EC", "P-256" | "secp256k1") => 32,
                    ("EC", "P-384") => 48,
                    ("EC", "P-521") => 66,
                    ("OKP", "Ed25519" | "X25519") => 32,
                    ("OKP", "Ed448") => 57,
                    ("OKP", "X448") => 56,
                    _ => return Err(Error::Document),
                };
                let x = integer(optional_string(key, "x")?.ok_or(Error::Document)?)?;
                if x.len() != size {
                    return Err(Error::Document);
                }
                if kty == "EC"
                    && integer(optional_string(key, "y")?.ok_or(Error::Document)?)?.len() != size
                {
                    return Err(Error::Document);
                }
                None
            }
            _ => return Err(Error::Document),
        };
        if kty != "RSA" || alg.is_some_and(|a| a != "RS256") || usage.is_some_and(|u| u != "sig") {
            continue;
        }
        if !rsa_bits.is_some_and(|bits| (2048..=8192).contains(&bits)) {
            return Err(Error::Document);
        }
        // openidconnect 4.1.0 calls rsa::RsaPublicKey::new, whose maximum is 4096 bits.
        // Keep the document ceiling separate from this maintained verifier's capability.
        if rsa_bits.is_some_and(|bits| bits > 4096) {
            continue;
        }
        if let Some(k) = kid
            && !seen.insert(k.to_owned())
        {
            return Err(Error::Document);
        }
        selected.push(serde_json::from_value(raw_key.clone()).map_err(|_| Error::Document)?);
        kids.push(kid.map(str::to_owned));
    }
    Ok(Keys {
        keys: CoreJsonWebKeySet::new(selected),
        kids,
    })
}
pub(super) fn media(response: &HttpResponse, jwks: bool) -> Result<(), Error> {
    if response.status() != 200 {
        return Err(Error::Fetch);
    }
    let h = response.headers();
    if h.get_all("content-type").iter().count() != 1 {
        return Err(Error::Document);
    }
    let s = h["content-type"].to_str().map_err(|_| Error::Document)?;
    let mut parts = s.split(';');
    let kind = parts.next().unwrap_or_default().trim();
    if !kind.eq_ignore_ascii_case("application/json")
        && !(jwks && kind.eq_ignore_ascii_case("application/jwk-set+json"))
    {
        return Err(Error::Document);
    }
    let params = parts.collect::<Vec<_>>();
    if params.len() > 1
        || params.first().is_some_and(|v| {
            !v.trim().eq_ignore_ascii_case("charset=utf-8")
                && !v.trim().eq_ignore_ascii_case("charset=\"utf-8\"")
        })
    {
        return Err(Error::Document);
    }
    Ok(())
}
// None means a valid representation cannot be reused. Callers must retire older keys.
pub(super) fn freshness(
    response: &HttpResponse,
    request: SystemTime,
    received: SystemTime,
    delay: Duration,
    cap: Duration,
) -> Option<Duration> {
    let h = response.headers();
    for n in ["cache-control", "date", "age"] {
        if h.get_all(n).iter().count() > 1 {
            return None;
        }
    }
    if received < request {
        return None;
    }
    let date = httpdate::parse_http_date(h.get("date")?.to_str().ok()?).ok()?;
    if date > received {
        return None;
    }
    let decimal = |s: &str| -> Option<u64> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            None
        } else {
            s.parse().ok()
        }
    };
    let age = h
        .get("age")
        .map(|v| decimal(v.to_str().ok()?))
        .unwrap_or(Some(0))?;
    let mut max_age = None;
    let mut seen = HashSet::new();
    for directive in h.get("cache-control")?.to_str().ok()?.split(',') {
        let (name, value) = directive
            .trim()
            .split_once('=')
            .map_or((directive.trim(), None), |(n, v)| {
                (n.trim(), Some(v.trim()))
            });
        let name = name.to_ascii_lowercase();
        if name.is_empty() || !seen.insert(name.clone()) {
            return None;
        }
        match name.as_str() {
            "no-store" | "no-cache" => return None,
            "max-age" => {
                let v = value?;
                let v = if v.starts_with('"') {
                    v.strip_prefix('"')?.strip_suffix('"')?
                } else {
                    v
                };
                max_age = Some(Duration::from_secs(decimal(v)?));
            }
            // Understood controls never authorize stale use. Unknown semantics fail closed.
            "public" | "private" | "must-revalidate" | "proxy-revalidate" | "no-transform"
                if value.is_none() => {}
            "stale-if-error" | "stale-while-revalidate" | "s-maxage" => {
                decimal(value?)?;
            }
            _ => return None,
        }
    }
    let age = Duration::from_secs(age)
        .checked_add(delay)?
        .max(received.duration_since(date).ok()?);
    max_age?.min(cap).checked_sub(age).filter(|v| !v.is_zero())
}
