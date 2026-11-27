//! The supported function-schema dialect. Every admitted keyword has matching instance validation.
use serde_json::Value as V;
use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SchemaSubset {
    /// One object with scalar properties.
    Flat,
    /// Objects and arrays may contain other declared schemas.
    Nested,
}

pub(crate) fn declared(s: &V, subset: SchemaSubset) -> bool {
    s["type"] == "object" && node(s, 0, subset)
}
fn node(s: &V, depth: usize, subset: SchemaSubset) -> bool {
    let Some(obj) = s.as_object() else {
        return false;
    };
    if depth > 32 {
        return false;
    }
    let kind = s["type"].as_str();
    if subset == SchemaSubset::Flat && depth > 0 && matches!(kind, Some("object" | "array")) {
        return false;
    }
    obj.keys().all(|k| match k.as_str() {
        "type" => true,
        "description" => s[k].is_string(),
        "properties" => {
            kind == Some("object")
                && s[k]
                    .as_object()
                    .is_some_and(|p| p.values().all(|v| node(v, depth + 1, subset)))
        }
        "required" => {
            kind == Some("object")
                && s[k].as_array().is_some_and(|a| {
                    let mut seen = HashSet::new();
                    a.iter().all(|v| {
                        v.as_str().is_some_and(|name| {
                            seen.insert(name) && s["properties"].get(name).is_some()
                        })
                    })
                })
        }
        "additionalProperties" => kind == Some("object") && s[k].is_boolean(),
        "items" => kind == Some("array") && node(&s[k], depth + 1, subset),
        _ => false,
    }) && matches!(
        kind,
        Some("object" | "string" | "number" | "integer" | "boolean" | "null" | "array")
    ) && (kind != Some("array") || s.get("items").is_some())
}
pub(super) fn accepts(s: &V, v: &V) -> bool {
    match s["type"].as_str() {
        Some("object") => v.as_object().is_some_and(|o| {
            s["required"]
                .as_array()
                .into_iter()
                .flatten()
                .all(|k| o.contains_key(k.as_str().unwrap()))
                && o.iter().all(|(k, v)| match s["properties"].get(k) {
                    Some(child) => accepts(child, v),
                    None => s["additionalProperties"] != false,
                })
        }),
        Some("array") => v
            .as_array()
            .is_some_and(|a| a.iter().all(|v| accepts(&s["items"], v))),
        Some("string") => v.is_string(),
        Some("boolean") => v.is_boolean(),
        Some("null") => v.is_null(),
        Some("integer") => v.as_f64().is_some_and(|n| n.fract() == 0.),
        Some("number") => v.is_number(),
        _ => false,
    }
}
