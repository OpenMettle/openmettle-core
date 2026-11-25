//! Gateway usage report payload shared by the inference proxy and settlement store (ADR 0044).
use crate::runs::is_canonical_uuid;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageReport {
    pub request: String,
    pub installation: String,
    pub principal: String,
    pub scope: String,
    pub source: String,
    pub report_id: String,
    pub revision: i64,
    pub r#final: bool,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub reasoning_tokens: Option<i64>,
    pub reasoning_included: Option<bool>,
    pub cost: Option<String>,
    pub unit: Option<String>,
}

impl UsageReport {
    pub fn valid(&self) -> bool {
        [
            &self.request,
            &self.installation,
            &self.principal,
            &self.scope,
            &self.source,
            &self.report_id,
        ]
        .iter()
        .all(|id| is_canonical_uuid(id))
            && self.revision >= 0
            && [
                self.prompt_tokens,
                self.completion_tokens,
                self.reasoning_tokens,
            ]
            .into_iter()
            .flatten()
            .all(|n| n >= 0)
            && (self.reasoning_tokens.is_none() || self.reasoning_included.is_some())
            && match (&self.cost, &self.unit) {
                (None, None) => true,
                (Some(c), Some(u)) => {
                    let (whole, fraction) = c
                        .split_once('.')
                        .map_or((c.as_str(), None), |(w, f)| (w, Some(f)));
                    (1..=18).contains(&whole.len())
                        && whole.bytes().all(|b| b.is_ascii_digit())
                        && fraction.is_none_or(|f| {
                            (1..=12).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit())
                        })
                        && (1..=32).contains(&u.len())
                        && u.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                }
                _ => false,
            }
    }

    pub fn measured(&self) -> Option<i128> {
        if [
            self.prompt_tokens,
            self.completion_tokens,
            self.reasoning_tokens,
        ]
        .iter()
        .all(Option::is_none)
        {
            return None;
        }
        let output = i128::from(self.completion_tokens.unwrap_or(0));
        let reasoning = i128::from(self.reasoning_tokens.unwrap_or(0));
        Some(
            i128::from(self.prompt_tokens.unwrap_or(0))
                + if self.reasoning_included == Some(true) {
                    output.max(reasoning)
                } else {
                    output + reasoning
                },
        )
    }
}
