use super::{turn::identifier, *};
use crate::model_config::{Profile, Source};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::collections::HashSet;

#[derive(Clone, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}
#[derive(Clone, Copy)]
pub enum ImageType {
    Png,
    Jpeg,
}

#[derive(Clone)]
pub enum History {
    User(String),
    UserImage {
        text: String,
        media: ImageType,
        bytes: Vec<u8>,
    },
    Assistant {
        parts: Vec<String>,
        reasoning: Option<Reasoning>,
        calls: Vec<Call>,
    },
    ToolResult {
        id: String,
        output: String,
    },
    /// Atomic server-only follow-up. Replays what the model proposed and correlates a
    /// fixed error with every member, including valid siblings that were never dispatched.
    RejectedGroup(Vec<ToolError>),
}
pub struct Request {
    pub history: Vec<History>,
    pub tools: Option<Vec<Tool>>,
    pub parallel: Option<bool>,
    pub stream: bool,
}

impl Request {
    pub(super) fn encode(
        &self,
        q: &Qualification,
        p: &Profile,
        e: &Effective,
        server: bool,
    ) -> Result<Vec<u8>, Error> {
        let chat = q.protocol == Protocol::Chat;
        if (self.stream && !q.sse)
            || (!self.stream && !q.json)
            || self.parallel.is_some()
                && (!q.parallel || self.tools.as_ref().is_none_or(Vec::is_empty))
            || self.history.is_empty()
        {
            return Err(Error::Validation);
        }
        let mut wire = json!({"model":e.model,"stream":self.stream});
        if let Some(tools) = &self.tools {
            if tools.len() > MAX_CALLS || !tools.is_empty() && q.functions.is_none() {
                return Err(Error::Validation);
            }
            let mut names = HashSet::new();
            let mut list = Vec::new();
            for tool in tools {
                if !identifier(&tool.name)
                    || !names.insert(&tool.name)
                    || !q
                        .functions
                        .is_some_and(|subset| schema::declared(&tool.parameters, subset))
                {
                    return Err(Error::Validation);
                }
                let mut f = json!({"name":tool.name,"description":tool.description,"parameters":tool.parameters});
                if chat {
                    f = json!({"type":"function","function":f});
                } else {
                    f["type"] = "function".into();
                }
                list.push(f);
            }
            wire["tools"] = list.into();
        }
        if let Some(parallel) = self.parallel {
            wire["parallel_tool_calls"] = parallel.into();
        }
        if let Some(level) = &e.reasoning_effort.value {
            if !p.efforts.contains(level) || e.reasoning_effort.source == Source::GatewayDefault {
                return Err(Error::Validation);
            }
            if chat {
                wire["reasoning_effort"] = level.as_str().into()
            } else {
                wire["reasoning"] = json!({"effort":level});
            }
        }
        if !p.joint_sampling && e.temperature.value.is_some() && e.top_p.value.is_some() {
            return Err(Error::Validation);
        }
        for (key, value, range) in [
            ("temperature", e.temperature.value, p.temperature),
            ("top_p", e.top_p.value, p.top_p),
        ] {
            if let Some(n) = value {
                if !range.is_some_and(|r| n >= r.min && n <= r.max) {
                    return Err(Error::Validation);
                }
                wire[key] = n.into();
            }
        }
        if let Some(n) = e.output_reserve.value {
            if n == 0 || !p.output_limit.is_some_and(|limit| n <= limit) {
                return Err(Error::Validation);
            }
            wire[if chat {
                "max_completion_tokens"
            } else {
                "max_output_tokens"
            }] = n.into();
        }
        if chat && self.stream && q.usage {
            wire["stream_options"] = json!({"include_usage":true});
        }
        let mut items = e
            .instructions
            .iter()
            .map(|i| json!({"role":"system","content":i.text}))
            .collect::<Vec<_>>();
        let mut pending = HashSet::new();
        let mut seen = HashSet::new();
        let instructions = items.len();
        for turn in &self.history {
            if !pending.is_empty() && !matches!(turn, History::ToolResult { .. }) {
                return Err(Error::Validation);
            }
            match turn {
                History::User(s) => items.push(json!({"role":"user","content":s})),
                History::UserImage { text, media, bytes } => {
                    if !q.images || bytes.is_empty() || bytes.len() > BODY / 4 * 3 {
                        return Err(Error::Validation);
                    }
                    let mime = match media {
                        ImageType::Png => "image/png",
                        ImageType::Jpeg => "image/jpeg",
                    };
                    let data = format!("data:{mime};base64,{}", STANDARD.encode(bytes));
                    let content = if chat {
                        json!([{"type":"text","text":text},{"type":"image_url","image_url":{"url":data}}])
                    } else {
                        json!([{"type":"input_text","text":text},{"type":"input_image","image_url":data}])
                    };
                    items.push(json!({"role":"user","content":content}));
                }
                History::ToolResult { id, output } => {
                    if !pending.remove(id.as_str()) {
                        return Err(Error::Validation);
                    }
                    items.push(result_item(chat, id, output));
                }
                History::RejectedGroup(errors) => {
                    if !server || errors.is_empty() || errors.len() > MAX_CALLS {
                        return Err(Error::Validation);
                    }
                    let mut calls = Vec::new();
                    for error in errors {
                        if !identifier(&error.call_id) || !seen.insert(error.call_id.as_str()) {
                            return Err(Error::Validation);
                        }
                        calls.push(call_item(
                            chat,
                            &error.call_id,
                            &error.name,
                            &error.arguments,
                        ));
                    }
                    if chat {
                        items.push(json!({"role":"assistant","tool_calls":calls}));
                    } else {
                        items.extend(calls);
                    }
                    items.extend(errors.iter().map(|err| {
                        result_item(chat, &err.call_id, &err.model_output().to_string())
                    }));
                }
                History::Assistant {
                    parts,
                    reasoning,
                    calls,
                } => {
                    if parts.is_empty() && calls.is_empty() && reasoning.is_none() {
                        return Err(Error::Validation);
                    }
                    if calls.len() > MAX_CALLS
                        || !calls.is_empty() && q.functions.is_none()
                        || calls.len() > 1 && !q.parallel
                        || parts.len() > MAX_PARTS
                        || parts.iter().map(String::len).sum::<usize>() > MAX_TEXT
                        || parts.iter().any(|s| s.contains('\0'))
                    {
                        return Err(Error::Validation);
                    }
                    if let Some(r) = reasoning {
                        r.validate()?;
                    }
                    let mut msg = json!({"role":"assistant"});
                    let replay = reasoning
                        .as_ref()
                        .filter(|r| p.replay_rule(Some(&r.source)).is_some());
                    if let Some(r) = replay {
                        if chat && r.source.format == "reasoning_content" {
                            msg["reasoning_content"] = r.texts()?.collect::<String>().into();
                        } else if !chat && r.source.format == "responses.reasoning" {
                            for block in &r.blocks {
                                if block["type"] != "reasoning" {
                                    return Err(Error::Validation);
                                }
                                items.push(
                                    responses::reasoning_block(block)
                                        .map_err(|_| Error::Validation)?,
                                );
                            }
                        }
                    }
                    match parts.as_slice() {
                        [] => {}
                        [text] => msg["content"] = text.as_str().into(),
                        _ => {
                            let kind = if chat { "text" } else { "output_text" };
                            msg["content"] = parts
                                .iter()
                                .map(|text| json!({"type":kind,"text":text}))
                                .collect();
                        }
                    }
                    let mut functions = Vec::new();
                    for call in calls {
                        if !identifier(&call.id)
                            || !identifier(&call.name)
                            || !call.arguments.is_object()
                            || !seen.insert(call.id.as_str())
                        {
                            return Err(Error::Validation);
                        }
                        pending.insert(call.id.as_str());
                        let args = call.arguments.to_string();
                        functions.push(call_item(chat, &call.id, &call.name, &args));
                    }
                    if chat && !functions.is_empty() {
                        msg["tool_calls"] = std::mem::take(&mut functions).into();
                    }
                    if msg.as_object().unwrap().len() > 1 {
                        items.push(msg);
                    }
                    items.extend(functions);
                }
            }
        }
        if !pending.is_empty() || items.len() == instructions {
            return Err(Error::Validation);
        }
        wire[if chat { "messages" } else { "input" }] = items.into();
        let bytes = serde_json::to_vec(&wire).map_err(|_| Error::Validation)?;
        if bytes.len() > BODY {
            return Err(Error::Validation);
        }
        Ok(bytes)
    }
}

fn call_item(chat: bool, id: &str, name: &str, args: &str) -> Value {
    if chat {
        json!({"id":id,"type":"function","function":{"name":name,"arguments":args}})
    } else {
        json!({"type":"function_call","call_id":id,"name":name,"arguments":args})
    }
}
fn result_item(chat: bool, id: &str, output: &str) -> Value {
    if chat {
        json!({"role":"tool","tool_call_id":id,"content":output})
    } else {
        json!({"type":"function_call_output","call_id":id,"output":output})
    }
}
