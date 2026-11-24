use super::{
    json::{array, index, optional, string},
    turn::{Assembly, PendingCall, bind},
    *,
};
use serde_json::Value;

pub(super) fn accept(
    state: &mut Assembly,
    v: &Value,
    stream: bool,
    separators: bool,
) -> Result<Vec<VisibleDelta>, Error> {
    if state.terminal || !v["error"].is_null() {
        return Err(if v["error"].is_null() {
            Error::Malformed
        } else {
            Error::Provider
        });
    }
    state.usage(&v["usage"], "prompt_tokens", "completion_tokens")?;
    let choices = array(v, "choices")?;
    if choices.is_empty() && v["usage"].is_null() {
        return Err(Error::Malformed);
    }
    let mut visible = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for choice in choices {
        let i = index(choice, "index")?;
        if i >= MAX_PARTS || !seen.insert(i) {
            return Err(Error::Malformed);
        }
        let out = state.choices.entry(i).or_default();
        if out.finished {
            return Err(Error::Malformed);
        }
        let msg = &choice[if stream { "delta" } else { "message" }];
        if !msg.is_object()
            || optional(msg, "role")?.is_some_and(|role| role != "assistant")
            || !stream && msg["role"] != "assistant"
        {
            return Err(Error::Malformed);
        }
        // A parser separator can arrive on the content lane while parallel calls are open.
        // Keep real prose (including its spaces); only the all-whitespace separator is suppressed.
        if !stream && msg["content"].is_array() {
            let parts = array(msg, "content")?;
            if parts.len() > MAX_PARTS {
                return Err(Error::Malformed);
            }
            for (n, part) in parts.iter().enumerate() {
                if part["type"] != "text" {
                    return Err(Error::Malformed);
                }
                out.text((0, n), string(part, "text")?)?;
            }
        } else if let Some(s) = optional(msg, "content")?
            && !(s.is_empty()
                || stream
                    && separators
                    && s.trim().is_empty()
                    && out.calls.values().any(PendingCall::open))
        {
            out.text((0, 0), s)?;
            visible.push(VisibleDelta {
                choice: i,
                part: (0, 0),
                text: s.into(),
            });
        }
        if let Some(s) = optional(msg, "reasoning_content")? {
            out.reasoning_delta(s)?;
        }
        if !msg["tool_calls"].is_null() {
            for (ordinal, c) in array(msg, "tool_calls")?.iter().enumerate() {
                let n = if stream { index(c, "index")? } else { ordinal };
                if optional(c, "type")?.is_some_and(|s| s != "function")
                    || !stream && c["type"] != "function"
                {
                    return Err(Error::Malformed);
                }
                if !out.calls.contains_key(&n) {
                    if state.call_count == MAX_CALLS {
                        return Err(Error::Malformed);
                    }
                    state.call_count += 1;
                }
                let call = out.call(n)?;
                bind(&mut call.id, optional(c, "id")?)?;
                let f = &c["function"];
                if !f.is_object() {
                    return Err(Error::Malformed);
                }
                bind(&mut call.name, optional(f, "name")?)?;
                if stream {
                    if let Some(s) = optional(f, "arguments")? {
                        call.fragment(s)?;
                    }
                } else {
                    call.fragment(string(f, "arguments")?)?;
                }
            }
        }
        if !choice["finish_reason"].is_null() {
            match string(choice, "finish_reason")? {
                "stop" if out.calls.is_empty() => {}
                "tool_calls" if !out.calls.is_empty() => {}
                "length" => {
                    out.stop_reason = Some(StopReason::Limit);
                    out.calls.clear();
                }
                "content_filter" => return Err(Error::Filtered),
                _ => return Err(Error::Malformed),
            }
            out.finished = true;
        } else if !stream {
            return Err(Error::Malformed);
        }
    }
    state.terminal = !stream;
    Ok(visible)
}
