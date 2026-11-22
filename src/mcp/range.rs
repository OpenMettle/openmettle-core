use super::*;
use crate::storage::{self, Revision};
use http_body_util::BodyExt;

pub(super) async fn read(
    pool: &PgPool,
    store: &Store,
    args: &Value,
    scope: &str,
) -> Result<String, ToolFault> {
    let mut c = pool.acquire().await.map_err(|_| ToolFault::Transient)?;
    let rev = storage::read_revision(
        &mut c,
        canonical_id(&args["artifact_id"])?,
        canonical_id(&args["revision_id"])?,
    )
    .await
    .map_err(|_| ToolFault::Transient)?
    .filter(|r| r.scope_id == scope && r.state == "active")
    .ok_or(ToolFault::TerminalRefusal)?;
    drop(c);
    let mut fields = rev.media_type.split(';').map(str::trim);
    let media = fields.next().unwrap_or_default().to_ascii_lowercase();
    let textual = media.split_once('/').is_some_and(|(kind, subtype)| {
        !subtype.is_empty()
            && (kind == "text" || media == "application/json" || subtype.ends_with("+json"))
    });
    let utf8 = fields.all(|field| {
        field.split_once('=').is_some_and(|(name, value)| {
            !name.trim().eq_ignore_ascii_case("charset")
                || value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
        })
    });
    if !textual || !utf8 {
        return Err(ToolFault::Semantic);
    }
    let start = args["offset"].as_u64().ok_or(ToolFault::Semantic)?;
    let max = args["max_bytes"]
        .as_u64()
        .filter(|n| (4..=INLINE_BYTES as u64).contains(n))
        .ok_or(ToolFault::Semantic)?;
    let remaining = (rev.size_bytes as u64)
        .checked_sub(start)
        .ok_or(ToolFault::Semantic)?;
    let bytes = store
        .read(
            &rev.reservation_id,
            rev.size_bytes,
            start,
            remaining.min(max),
        )
        .await
        .map_err(|_| ToolFault::Transient)?
        .collect()
        .await
        .map_err(|_| ToolFault::Transient)?
        .to_bytes();
    page(&rev, start, &bytes)
}

fn page(rev: &Revision, start: u64, bytes: &[u8]) -> Result<String, ToolFault> {
    let size = rev.size_bytes as u64;
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e)
            if e.error_len().is_none()
                && start + (bytes.len() as u64) < size
                && e.valid_up_to() > 0 =>
        {
            std::str::from_utf8(&bytes[..e.valid_up_to()]).map_err(|_| ToolFault::Semantic)?
        }
        Err(_) => return Err(ToolFault::Semantic),
    };
    let limit = text
        .match_indices('\n')
        .nth(199)
        .map_or(text.len(), |(i, _)| i + 1);
    let encode = |n| {
        let next = start + n as u64;
        json!({"status":"ok","storage":"inline","text":&text[..n],"next_offset":next,
            "size_bytes":size,"media_type":rev.media_type,"content_digest":crate::authz::projects::hex(&rev.content_digest),
            "eof":next==size}).to_string()
    };
    let end = text[..limit]
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(limit))
        .collect::<Vec<_>>();
    let fits = end.partition_point(|&n| encode(n).len() <= INLINE_BYTES);
    let n = *end
        .get(fits.checked_sub(1).ok_or(ToolFault::Semantic)?)
        .ok_or(ToolFault::Semantic)?;
    if n == 0 && start < size {
        return Err(ToolFault::Semantic);
    }
    Ok(encode(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn revision(size: i64) -> Revision {
        Revision {
            id: String::new(),
            artifact_id: String::new(),
            revision: 1,
            scope_id: String::new(),
            project_id: None,
            reservation_id: String::new(),
            size_bytes: size,
            content_digest: vec![0; 32],
            media_type: "text/plain".into(),
            display_name: None,
            state: "active".into(),
            created_us: 0,
        }
    }
    #[test]
    fn page_progresses_across_utf8_and_limits_the_serialized_result() {
        let bytes = "雪🙂".as_bytes();
        let rev = revision(bytes.len() as i64);
        let first: Value = serde_json::from_str(&page(&rev, 0, &bytes[..4]).unwrap()).unwrap();
        assert_eq!(first["text"], "雪");
        assert_eq!(first["next_offset"], 3);
        assert_eq!(page(&rev, 1, &bytes[1..]), Err(ToolFault::Semantic));
        assert_eq!(
            page(&revision(2), 0, &[0xe2, 0x81]),
            Err(ToolFault::Semantic)
        );
        assert_eq!(page(&rev, 0, &[0xff]), Err(ToolFault::Semantic));
        for s in ["\x1b".repeat(INLINE_BYTES), "雪\n".repeat(201)] {
            let json = page(&revision(s.len() as i64), 0, s.as_bytes()).unwrap();
            assert!(json.len() <= INLINE_BYTES);
            let result: Value = serde_json::from_str(&json).unwrap();
            let text = result["text"].as_str().unwrap();
            assert!(s.starts_with(text));
            assert!(text.lines().count() <= 200);
            assert_eq!(result["next_offset"], text.len());
            assert_eq!(result["eof"], false);
        }
    }
}
