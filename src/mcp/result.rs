//! Model-visible envelopes are bounded after JSON escaping and provenance serialization.
use super::*;
use sha2::{Digest, Sha256};

pub(crate) struct Output<'a> {
    pub text: &'a str,
    pub digest: [u8; 32],
    lines: usize,
}
impl<'a> Output<'a> {
    pub fn new(text: &'a str) -> Result<Self, ToolFault> {
        if text.len() > 4 * 1024 * 1024 {
            return Err(ToolFault::TerminalRefusal);
        }
        Ok(Self {
            text,
            digest: Sha256::digest(text.as_bytes()).into(),
            lines: text.lines().count(),
        })
    }
    pub fn inline(&self) -> Option<String> {
        if self.lines > 200 || self.text.len() > INLINE_BYTES {
            return None;
        }
        let encoded=json!({"status":"ok","storage":"inline","truncated":false,"text":self.text,"size_bytes":self.text.len(),
            "line_count":self.lines,"content_sha256":crate::authz::projects::hex(&self.digest)}).to_string();
        (encoded.len() <= INLINE_BYTES).then_some(encoded)
    }
    pub fn preview(
        &self,
        p: &Proposal,
        op: &str,
        location: Result<(&str, &str), &'static str>,
    ) -> String {
        let head_end = self
            .text
            .match_indices('\n')
            .nth(59)
            .map_or(self.text.len(), |(i, _)| i + 1)
            .min(4096);
        let head = &self.text[..self.text.floor_char_boundary(head_end)];
        let rest = &self.text[head.len()..];
        let tail_start = rest
            .strip_suffix('\n')
            .unwrap_or(rest)
            .rmatch_indices('\n')
            .nth(59)
            .map_or(0, |(i, _)| i + 1);
        let tail =
            &rest[rest.ceil_char_boundary(tail_start.max(rest.len().saturating_sub(4096)))..];
        let (artifact, revision) = location.ok().unzip();
        let encode = |limit: usize| {
            let head = &head[..head.floor_char_boundary(limit.min(head.len()))];
            let tail = &tail[tail.ceil_char_boundary(tail.len().saturating_sub(limit))..];
            let mut result = json!({"status":"ok","storage":if location.is_ok(){"spilled"}else{"truncated_no_spill"},"truncated":true,
                "head":head,"tail":tail,"provenance":{"source":"tool_spill","tool_id":p.tool,"tool_version":p.version,
                "operation_id":op,"artifact_id":artifact,"revision_id":revision,"size_bytes":self.text.len(),"line_count":self.lines,
                "content_sha256":crate::authz::projects::hex(&self.digest),"inline_head_bytes":head.len(),"inline_tail_bytes":tail.len(),
                "omitted_bytes":self.text.len()-head.len()-tail.len()}});
            if let Err(error) = location {
                result["spill_error"] = json!(error);
                result["artifact_id"] = Value::Null;
                result["revision_id"] = Value::Null;
            }
            result.to_string()
        };
        let mut low = 0usize;
        let mut high = 4096;
        while low < high {
            let mid = (low + high).div_ceil(2);
            if encode(mid).len() <= INLINE_BYTES {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        encode(low)
    }
}
