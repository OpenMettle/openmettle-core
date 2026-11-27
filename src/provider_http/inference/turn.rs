use super::*;
use crate::model_config::{Profile, ReplaySource};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone)]
pub struct Reasoning {
    pub source: Box<ReplaySource>,
    /// The JSONB array to persist. The parent Option represents SQL NULL.
    pub blocks: Vec<Value>,
    pub storage_bytes: usize,
}
impl Reasoning {
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.blocks.is_empty() || self.blocks.len() > MAX_PARTS {
            return Err(Error::Validation);
        }
        let mut bytes = 0;
        for block in &self.blocks {
            if !block.is_object() {
                return Err(Error::Validation);
            }
            let cost = 2 + pg_bytes(block).map_err(|_| Error::Validation)?;
            if cost > MAX_TEXT - bytes {
                return Err(Error::Validation);
            }
            bytes += cost;
        }
        if bytes != self.storage_bytes {
            return Err(Error::Validation);
        }
        Ok(())
    }
    pub(super) fn texts(&self) -> Result<impl Iterator<Item = &str>, Error> {
        if !self.blocks.iter().all(|v| v["text"].is_string()) {
            return Err(Error::Validation);
        }
        Ok(self.blocks.iter().filter_map(|v| v["text"].as_str()))
    }
}
#[derive(Clone, PartialEq)]
pub struct Call {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

/// Model-visible recovery for a rejected group. No member of the group is executable.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolError {
    pub call_id: String,
    pub(crate) name: String,
    pub(crate) arguments: String,
}
impl ToolError {
    pub fn model_output(&self) -> Value {
        json!({"error":{"code":"invalid_tool_arguments"}})
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// Generation stopped because it reached the model's output token limit.
    Limit,
}
impl StopReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Limit => "limit",
        }
    }
}
pub enum CallGroup {
    Valid(Vec<Call>),
    InvalidArguments(Vec<ToolError>),
}
pub struct Answer {
    pub choice: usize,
    /// Index in this vector is the contiguous storage ordinal.
    pub parts: Vec<String>,
    pub reasoning: Option<Reasoning>,
    pub calls: CallGroup,
    pub stop_reason: Option<StopReason>,
}
pub struct Usage {
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub source: &'static str,
    pub semantics: String,
}
pub struct Turn {
    pub answers: Vec<Answer>,
    pub usage: Option<Usage>,
}
pub struct VisibleDelta {
    pub choice: usize,
    /// Responses output and content indices identify the lane even when items interleave.
    pub part: (usize, usize),
    pub text: String,
}

pub(super) fn identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic())
}
pub(super) fn append(s: &mut String, fragment: &str, limit: usize) -> Result<(), Error> {
    if fragment.len() > limit - s.len() {
        return Err(Error::Malformed);
    }
    s.push_str(fragment);
    Ok(())
}
#[derive(Default)]
pub(super) struct PendingCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
    depth: usize,
    quoted: bool,
    escaped: bool,
}
impl PendingCall {
    pub fn complete(id: &str, name: &str, arguments: &str) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arguments: arguments.into(),
            ..Default::default()
        }
    }
    /// Track only the open JSON container for the qualified parser's separator. The strict
    /// duplicate-rejecting decoder validates the complete argument independently at terminal.
    pub fn fragment(&mut self, s: &str) -> Result<(), Error> {
        append(&mut self.arguments, s, MAX_ARGUMENT)?;
        for b in s.bytes() {
            if self.escaped {
                self.escaped = false;
                continue;
            }
            if self.quoted && b == b'\\' {
                self.escaped = true;
                continue;
            }
            if b == b'"' {
                self.quoted = !self.quoted;
            } else if !self.quoted {
                match b {
                    b'{' | b'[' => self.depth += 1,
                    b'}' | b']' => self.depth = self.depth.saturating_sub(1),
                    _ => {}
                }
            }
        }
        Ok(())
    }
    pub fn open(&self) -> bool {
        self.depth > 0
    }
}
pub(super) fn bind(slot: &mut String, value: Option<&str>) -> Result<(), Error> {
    if let Some(s) = value {
        if !identifier(s) || !slot.is_empty() && s != slot {
            return Err(Error::Malformed);
        }
        if slot.is_empty() {
            slot.push_str(s);
        }
    }
    Ok(())
}
#[derive(Default)]
pub(super) struct Output {
    pub parts: BTreeMap<(usize, usize), String>,
    visible_bytes: usize,
    pub blocks: Vec<Value>,
    reasoning_bytes: usize,
    pub calls: BTreeMap<usize, PendingCall>,
    pub discarded_calls: usize,
    pub discarded_call_ids: Vec<String>,
    pub finished: bool,
    pub stop_reason: Option<StopReason>,
}
impl Output {
    pub fn discard_calls(&mut self) {
        let dropped = std::mem::take(&mut self.calls);
        self.discarded_calls += dropped.len();
        self.discarded_call_ids.extend(
            dropped
                .into_values()
                .map(|c| c.id)
                .filter(|id| !id.is_empty()),
        );
    }
    pub fn text(&mut self, key: (usize, usize), s: &str) -> Result<(), Error> {
        if s.is_empty() {
            return Ok(());
        }
        if s.contains('\0')
            || s.len() > MAX_TEXT - self.visible_bytes
            || self.parts.len() == MAX_PARTS && !self.parts.contains_key(&key)
        {
            return Err(Error::Malformed);
        }
        self.parts.entry(key).or_default().push_str(s);
        self.visible_bytes += s.len();
        Ok(())
    }
    pub fn call(&mut self, i: usize) -> Result<&mut PendingCall, Error> {
        if i >= MAX_CALLS {
            return Err(Error::Malformed);
        }
        Ok(self.calls.entry(i).or_default())
    }
    pub fn reasoning_delta(&mut self, s: &str) -> Result<(), Error> {
        if s.is_empty() {
            return Ok(());
        }
        if self.blocks.is_empty() {
            self.block(json!({"text":""}))?;
        }
        let cost = escaped_bytes(s)?;
        if cost > MAX_TEXT - self.reasoning_bytes {
            return Err(Error::Malformed);
        }
        let Value::String(text) = &mut self.blocks[0]["text"] else {
            return Err(Error::Malformed);
        };
        text.push_str(s);
        self.reasoning_bytes += cost;
        Ok(())
    }
    pub fn block(&mut self, block: Value) -> Result<(), Error> {
        // The empty array brackets cost two bytes; later blocks add comma-space.
        let cost = 2 + pg_bytes(&block)?;
        if self.blocks.len() == MAX_PARTS || cost > MAX_TEXT - self.reasoning_bytes {
            return Err(Error::Malformed);
        }
        self.blocks.push(block);
        self.reasoning_bytes += cost;
        Ok(())
    }
}
// PostgreSQL jsonb::text uses one space after each comma and colon. Stored reasoning has
// only string leaves, so PostgreSQL numeric normalization cannot change this count.
pub(super) fn pg_bytes(v: &Value) -> Result<usize, Error> {
    match v {
        Value::String(s) => Ok(2 + escaped_bytes(s)?),
        Value::Array(a) => a
            .iter()
            .try_fold(2 + 2 * a.len().saturating_sub(1), |n, v| {
                Ok(n + pg_bytes(v)?)
            }),
        Value::Object(o) => o
            .iter()
            .try_fold(2 + 2 * o.len().saturating_sub(1), |n, (k, v)| {
                Ok(n + escaped_bytes(k)? + 4 + pg_bytes(v)?)
            }),
        _ => Err(Error::Malformed),
    }
}
pub(super) fn escaped_bytes(s: &str) -> Result<usize, Error> {
    s.bytes().try_fold(0, |n, b| {
        Ok(n + match b {
            0 => return Err(Error::Malformed),
            b'"' | b'\\' | 8 | 9 | 10 | 12 | 13 => 2,
            1..32 => 6,
            _ => 1,
        })
    })
}

#[derive(Default)]
pub(super) struct Assembly {
    pub choices: BTreeMap<usize, Output>,
    pub terminal: bool,
    pub call_count: usize,
    pub counts: Option<(Option<u64>, Option<u64>)>,
}
impl Assembly {
    pub fn usage(&mut self, usage: &Value, input: &str, output: &str) -> Result<(), Error> {
        if usage.is_null() {
            return Ok(());
        }
        if !usage.is_object() {
            return Err(Error::Malformed);
        }
        let count = |key: &str| -> Result<Option<u64>, Error> {
            match usage.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(v) => v
                    .as_u64()
                    .filter(|n| *n <= i64::MAX as u64)
                    .map(Some)
                    .ok_or(Error::Malformed),
            }
        };
        let pair = (count(input)?, count(output)?);
        if pair != (None, None) {
            if self.counts.is_some_and(|old| old != pair) {
                return Err(Error::Malformed);
            }
            self.counts = Some(pair);
        }
        Ok(())
    }
    pub fn finish(
        self,
        q: &Qualification,
        p: &Profile,
        request: &Request,
        server: bool,
    ) -> Result<Turn, Error> {
        if !self.terminal {
            return Err(Error::Incomplete);
        }
        if self.choices.is_empty() {
            return Err(Error::Malformed);
        }
        let tools = request.tools.as_deref().unwrap_or_default();
        let mut used = HashSet::new();
        for history in &request.history {
            match history {
                History::Assistant { calls, .. } => {
                    used.extend(calls.iter().map(|c| c.id.as_str()))
                }
                History::RejectedGroup(errors) => {
                    used.extend(errors.iter().map(|e| e.call_id.as_str()))
                }
                _ => {}
            }
        }
        let mut count = 0;
        for out in self.choices.values() {
            let choice_calls = out.calls.len() + out.discarded_calls;
            count += choice_calls;
            if !out.finished
                || count > MAX_CALLS
                || choice_calls > 1 && (!q.parallel || request.parallel == Some(false))
            {
                return Err(Error::Malformed);
            }
            for id in &out.discarded_call_ids {
                if !identifier(id) || !used.insert(id.as_str()) {
                    return Err(Error::Malformed);
                }
            }
            for c in out.calls.values() {
                if !identifier(&c.id)
                    || !used.insert(&c.id)
                    || !tools.iter().any(|t| t.name == c.name)
                {
                    return Err(Error::Malformed);
                }
            }
        }
        let mut answers = Vec::new();
        for (choice, out) in self.choices {
            let mut valid = Vec::new();
            let mut ids = Vec::new();
            for (_, c) in out.calls {
                let schema = &tools
                    .iter()
                    .find(|t| t.name == c.name)
                    .expect("validated offered name")
                    .parameters;

                if let Ok(args) = json::parse(c.arguments.as_bytes())
                    && schema::accepts(schema, &args)
                {
                    valid.push(Call {
                        id: c.id.clone(),
                        name: c.name.clone(),
                        arguments: args,
                    });
                }
                ids.push(ToolError {
                    call_id: c.id,
                    name: c.name,
                    arguments: c.arguments,
                });
            }
            let calls = if valid.len() == ids.len() {
                CallGroup::Valid(valid)
            } else if server {
                CallGroup::InvalidArguments(ids)
            } else {
                return Err(Error::Malformed);
            };
            let reasoning = if out.blocks.is_empty() {
                None
            } else {
                Some(Reasoning {
                    source: Box::new(ReplaySource {
                        profile: p.pin.clone(),
                        format: p.reasoning_format.clone().ok_or(Error::Malformed)?,
                    }),
                    blocks: out.blocks,
                    storage_bytes: out.reasoning_bytes,
                })
            };
            answers.push(Answer {
                choice,
                parts: out.parts.into_values().collect(),
                reasoning,
                calls,
                stop_reason: out.stop_reason,
            });
        }
        let usage = self
            .counts
            .filter(|_| q.usage)
            .map(|(input, output)| Usage {
                input,
                output,
                source: "gateway",
                semantics: p.usage_semantics.clone(),
            });
        Ok(Turn { answers, usage })
    }
}
