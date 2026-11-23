//! Preserve duplicate-key evidence until every nested object has been visited. The worker
//! decoder and the gateway proxy's usage reader share this parser.
use super::Error;
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::fmt;

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(Json).map(Self)
    }
}
struct Json;
impl<'de> Visitor<'de> for Json {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON with unique object keys")
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut a = Vec::new();
        while let Some(Unique(v)) = seq.next_element()? {
            a.push(v);
        }
        Ok(Value::Array(a))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut obj = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if obj.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            obj.insert(key, map.next_value::<Unique>()?.0);
        }
        Ok(Value::Object(obj))
    }
}
pub(crate) fn parse(bytes: &[u8]) -> Result<Value, Error> {
    serde_json::from_slice::<Unique>(bytes)
        .map(|u| u.0)
        .map_err(|_| Error::Malformed)
}

pub(super) fn array<'a>(v: &'a Value, key: &str) -> Result<&'a [Value], Error> {
    v[key].as_array().map(Vec::as_slice).ok_or(Error::Malformed)
}
pub(super) fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    v[key].as_str().ok_or(Error::Malformed)
}
pub(super) fn optional<'a>(v: &'a Value, key: &str) -> Result<Option<&'a str>, Error> {
    if v[key].is_null() {
        Ok(None)
    } else {
        string(v, key).map(Some)
    }
}
pub(super) fn index(v: &Value, key: &str) -> Result<usize, Error> {
    v[key]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(Error::Malformed)
}
