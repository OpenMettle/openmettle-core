//! The terminal Responses object is authoritative. Bind streamed lanes by item identity and
//! output index, then reconcile observed deltas and done snapshots before releasing any calls.
use super::{
    json::{array, index, optional, string},
    turn::{Assembly, Output, PendingCall, append, escaped_bytes, identifier, pg_bytes},
    *,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

const ITEMS: usize = MAX_PARTS * 3;

struct Item {
    id: String,
    kind: String,
    call: Option<(String, String)>,
    arguments: Option<String>,
    arguments_done: bool,
    parts: BTreeMap<usize, Text>,
    done: Option<Value>,
}
#[derive(Default)]
struct Text {
    value: String,
    done: bool,
}
#[derive(Default)]
pub(super) struct Events {
    items: BTreeMap<usize, Item>,
    visible_bytes: usize,
    visible_parts: usize,
    reasoning_bytes: usize,
}

fn item_texts<'a>(item: &'a Value, key: &str, kind: &str) -> Result<Vec<&'a str>, Error> {
    let list = array(item, key)?;
    if list.len() > MAX_PARTS {
        return Err(Error::Malformed);
    }
    list.iter()
        .map(|c| {
            if c["type"] != kind {
                return Err(Error::Malformed);
            }
            string(c, "text")
        })
        .collect()
}
fn compatible_status(v: &Value) -> Result<(), Error> {
    match string(v, "status")? {
        "completed" => Ok(()),
        "incomplete" => Err(
            if v.pointer("/incomplete_details/reason")
                .and_then(Value::as_str)
                == Some("content_filter")
            {
                Error::Filtered
            } else {
                Error::Incomplete
            },
        ),
        "failed" | "cancelled" => Err(Error::Provider),
        _ => Err(Error::Malformed),
    }
}
impl Events {
    pub fn event(&mut self, state: &mut Assembly, v: &Value) -> Result<Vec<VisibleDelta>, Error> {
        if !v["error"].is_null() || !v["response"]["error"].is_null() {
            return Err(Error::Provider);
        }
        let kind = string(v, "type")?;
        match kind {
            "response.failed" | "response.cancelled" | "error" | "response.error" => {
                return Err(Error::Provider);
            }
            "response.incomplete" => {
                return Err(
                    if v.pointer("/response/incomplete_details/reason")
                        .and_then(Value::as_str)
                        == Some("content_filter")
                    {
                        Error::Filtered
                    } else {
                        Error::Incomplete
                    },
                );
            }
            "response.created" | "response.in_progress" | "response.queued" => return Ok(vec![]),
            "response.completed" => return self.complete(state, &v["response"]),
            _ => {}
        }
        let i = index(v, "output_index")?;
        if i >= ITEMS {
            return Err(Error::Malformed);
        }
        if kind == "response.output_item.added" {
            let item = &v["item"];
            let id = string(item, "id")?;
            let k = string(item, "type")?;
            if !identifier(id)
                || self.items.contains_key(&i)
                || self.items.values().any(|x| x.id == id)
                || !matches!(k, "message" | "function_call" | "reasoning")
            {
                return Err(Error::Malformed);
            }
            let call = if k == "function_call" {
                if self.items.values().filter(|x| x.call.is_some()).count() >= MAX_CALLS {
                    return Err(Error::Malformed);
                }
                let call_id = string(item, "call_id")?;
                let name = string(item, "name")?;
                if !identifier(call_id) || !identifier(name) {
                    return Err(Error::Malformed);
                }
                Some((call_id.into(), name.into()))
            } else {
                None
            };
            match k {
                "message" if item["role"] != "assistant" || !array(item, "content")?.is_empty() => {
                    return Err(Error::Malformed);
                }
                "reasoning" => {
                    if self
                        .items
                        .values()
                        .filter(|item| item.kind == "reasoning")
                        .count()
                        >= MAX_PARTS
                        || !array(item, "summary")?.is_empty()
                    {
                        return Err(Error::Malformed);
                    }
                    let cost = 2 + pg_bytes(&reasoning_block(item)?)?;
                    charge(&mut self.reasoning_bytes, cost)?;
                }
                _ => {}
            }
            let arguments = optional(item, "arguments")?.filter(|s| !s.is_empty());
            if arguments.is_some_and(|s| s.len() > MAX_ARGUMENT) {
                return Err(Error::Malformed);
            }
            self.items.insert(
                i,
                Item {
                    id: id.into(),
                    kind: k.into(),
                    call,
                    arguments: arguments.map(str::to_owned),
                    arguments_done: false,
                    parts: BTreeMap::new(),
                    done: None,
                },
            );
            return Ok(vec![]);
        }
        let item = self.items.get_mut(&i).ok_or(Error::Malformed)?;
        if item.done.is_some() {
            return Err(Error::Malformed);
        }
        if kind == "response.output_item.done" {
            let snapshot = &v["item"];
            item.verify(snapshot)?;
            item.done = Some(snapshot.clone());
            return Ok(vec![]);
        }
        if string(v, "item_id")? != item.id {
            return Err(Error::Malformed);
        }
        match kind {
            "response.function_call_arguments.delta" | "response.function_call_arguments.done"
                if item.call.is_some() =>
            {
                if item.arguments_done {
                    return Err(Error::Malformed);
                }
                let (call_id, name) = item.call.as_ref().expect("function call lane");
                if optional(v, "call_id")?.is_some_and(|id| id != call_id)
                    || optional(v, "name")?.is_some_and(|n| n != name)
                {
                    return Err(Error::Malformed);
                }
                if kind.ends_with(".delta") {
                    append(
                        item.arguments.get_or_insert_default(),
                        string(v, "delta")?,
                        MAX_ARGUMENT,
                    )?;
                } else {
                    let args = string(v, "arguments")?;
                    if args.len() > MAX_ARGUMENT
                        || item.arguments.as_ref().is_some_and(|s| s != args)
                    {
                        return Err(Error::Malformed);
                    }
                    item.arguments = Some(args.into());
                    item.arguments_done = true;
                }
            }
            "response.output_text.delta"
            | "response.output_text.done"
            | "response.content_part.added"
            | "response.content_part.done"
            | "response.reasoning_summary_text.delta"
            | "response.reasoning_summary_text.done"
            | "response.reasoning_summary_part.added"
            | "response.reasoning_summary_part.done" => {
                let reasoning = kind.starts_with("response.reasoning_");
                if item.kind != if reasoning { "reasoning" } else { "message" } {
                    return Err(Error::Malformed);
                }
                let n = index(
                    v,
                    if reasoning {
                        "summary_index"
                    } else {
                        "content_index"
                    },
                )?;
                if n >= MAX_PARTS {
                    return Err(Error::Malformed);
                }
                let is_delta = kind.ends_with(".delta");
                let text = if kind.contains("_part.") {
                    if v["part"]["type"]
                        != if reasoning {
                            "summary_text"
                        } else {
                            "output_text"
                        }
                    {
                        return Err(Error::Malformed);
                    }
                    string(&v["part"], "text")?
                } else {
                    string(v, if is_delta { "delta" } else { "text" })?
                };
                if !item.parts.contains_key(&n) {
                    if reasoning {
                        let cost = pg_bytes(&json!({"type":"summary_text","text":""}))?
                            + if item.parts.is_empty() { 0 } else { 2 };
                        charge(&mut self.reasoning_bytes, cost)?;
                    } else {
                        if self.visible_parts == MAX_PARTS {
                            return Err(Error::Malformed);
                        }
                        self.visible_parts += 1;
                    }
                }
                let part = item.parts.entry(n).or_default();
                if is_delta && part.done
                    || kind.ends_with(".added") && (!part.value.is_empty() || part.done)
                {
                    return Err(Error::Malformed);
                }
                let fragment = if is_delta || part.value.is_empty() && !part.done {
                    text
                } else if part.value == text {
                    ""
                } else {
                    return Err(Error::Malformed);
                };
                if reasoning {
                    charge(&mut self.reasoning_bytes, escaped_bytes(fragment)?)?;
                } else {
                    if fragment.contains('\0') {
                        return Err(Error::Malformed);
                    }
                    charge(&mut self.visible_bytes, fragment.len())?;
                }
                part.value.push_str(fragment);
                part.done |= kind.ends_with(".done");
                if !reasoning && !fragment.is_empty() {
                    return Ok(vec![VisibleDelta {
                        choice: 0,
                        part: (i, n),
                        text: fragment.into(),
                    }]);
                }
            }
            _ => return Err(Error::Malformed),
        }
        Ok(vec![])
    }

    pub fn complete(
        &self,
        state: &mut Assembly,
        response: &Value,
    ) -> Result<Vec<VisibleDelta>, Error> {
        if !response["error"].is_null() {
            return Err(Error::Provider);
        }
        compatible_status(response)?;
        let items = array(response, "output")?;
        if items.is_empty() || items.len() > ITEMS || self.items.keys().any(|i| *i >= items.len()) {
            return Err(Error::Malformed);
        }
        let mut ids = HashSet::new();
        let mut out = Output::default();
        let mut visible = Vec::new();
        for (i, item) in items.iter().enumerate() {
            if let Some(id) = optional(item, "id")?
                && (!identifier(id) || !ids.insert(id))
            {
                return Err(Error::Malformed);
            }
            let observed = self.items.get(&i);
            if let Some(lane) = observed {
                lane.verify(item)?;
            }
            if !item["status"].is_null() {
                compatible_status(item)?;
            }
            match string(item, "type")? {
                "message" if item["role"] == "assistant" => {
                    for (n, s) in item_texts(item, "content", "output_text")?
                        .into_iter()
                        .enumerate()
                    {
                        out.text((i, n), s)?;
                        if !s.is_empty()
                            && observed.is_none_or(|lane| {
                                lane.parts.get(&n).is_none_or(|part| part.value.is_empty())
                            })
                        {
                            visible.push(VisibleDelta {
                                choice: 0,
                                part: (i, n),
                                text: s.into(),
                            });
                        }
                    }
                }
                "function_call" => {
                    if !identifier(string(item, "id")?) {
                        return Err(Error::Malformed);
                    }
                    let args = string(item, "arguments")?;
                    if out.calls.len() >= MAX_CALLS || args.len() > MAX_ARGUMENT {
                        return Err(Error::Malformed);
                    }
                    out.calls.insert(
                        i,
                        PendingCall::complete(
                            string(item, "call_id")?,
                            string(item, "name")?,
                            args,
                        ),
                    );
                }
                "reasoning" => {
                    let block = reasoning_block(item)?;
                    out.block(block)?;
                }
                _ => return Err(Error::Malformed),
            }
        }
        out.finished = true;
        state.choices.insert(0, out);
        state.usage(&response["usage"], "input_tokens", "output_tokens")?;
        state.terminal = true;
        Ok(visible)
    }
}
impl Item {
    fn verify(&self, v: &Value) -> Result<(), Error> {
        if v["id"] != self.id
            || v["type"] != self.kind
            || self.done.as_ref().is_some_and(|s| s != v)
        {
            return Err(Error::Malformed);
        }
        if let Some((id, name)) = &self.call
            && (v["call_id"] != *id
                || v["name"] != *name
                || self
                    .arguments
                    .as_ref()
                    .is_some_and(|s| v["arguments"] != *s))
        {
            return Err(Error::Malformed);
        }
        let key = if self.kind == "message" {
            "content"
        } else {
            "summary"
        };
        for (n, part) in &self.parts {
            if v[key][*n]["text"] != part.value {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
}

pub(super) fn reasoning_block(item: &Value) -> Result<Value, Error> {
    let texts = item_texts(item, "summary", "summary_text")?;
    // Keep only the declared replay representation and bound the normalized jsonb::text size.
    let mut summary_bytes = 0;
    for text in &texts {
        charge(&mut summary_bytes, escaped_bytes(text)?)?;
    }
    let mut block = json!({
        "type": "reasoning",
        "summary": texts
            .into_iter()
            .map(|text| json!({"type": "summary_text", "text": text}))
            .collect::<Vec<_>>()
    });
    for key in ["id", "encrypted_content"] {
        if let Some(s) = optional(item, key)? {
            if escaped_bytes(s)? > MAX_TEXT {
                return Err(Error::Malformed);
            }
            block[key] = s.into();
        }
    }
    if 2 + pg_bytes(&block)? > MAX_TEXT {
        return Err(Error::Malformed);
    }
    Ok(block)
}
fn charge(total: &mut usize, n: usize) -> Result<(), Error> {
    if n > MAX_TEXT - *total {
        return Err(Error::Malformed);
    }
    *total += n;
    Ok(())
}
