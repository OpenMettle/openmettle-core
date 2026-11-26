//! Authenticated keyset positions. Only the position is carried on the wire.
use super::*;
use crate::auth_config::CursorKeys;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde::Serialize;

pub(super) const INVALID_CURSOR: Problem = problem(
    StatusCode::BAD_REQUEST,
    "invalid_cursor",
    "Discard the cursor and restart the list.",
);
pub(super) struct Page<'a> {
    pub limit: usize,
    pub scope: Option<&'a str>,
    cursor: Option<&'a str>,
    keys: Option<&'a CursorKeys>,
    op: Op,
    user: &'a str,
    path: &'a str,
}

impl<'a> Page<'a> {
    pub fn new(parts: &'a Parts, user: &'a str, op: Op) -> Result<Self, Problem> {
        let mut limit = None;
        let mut scope = None;
        let mut cursor = None;
        for pair in parts.uri.query().into_iter().flat_map(|s| s.split('&')) {
            match pair.split_once('=') {
                Some(("limit", n)) if limit.is_none() && n.bytes().all(|c| c.is_ascii_digit()) => {
                    limit = Some(
                        n.parse::<usize>()
                            .ok()
                            .filter(|n| (1..=100).contains(n))
                            .ok_or(INVALID)?,
                    );
                }
                Some(("scope_id", s))
                    if matches!(op, Op::ListConversations | Op::ListConnections)
                        && scope.is_none()
                        && crate::runs::uuid(s).is_ok() =>
                {
                    scope = Some(s)
                }
                Some(("cursor", s)) if cursor.is_none() => cursor = Some(s),
                _ => return Err(INVALID),
            }
        }
        Ok(Self {
            limit: limit.unwrap_or(50),
            scope,
            cursor,
            op,
            user,
            path: parts.uri.path(),
            keys: parts.extensions.get::<Arc<CursorKeys>>().map(Arc::as_ref),
        })
    }
    fn identity(&self, kid: &str, binding: &str, position: &[u8]) -> Vec<u8> {
        crate::runs::identity(
            b"openmettle/v1-page-cursor/1\0",
            &[
                kid.as_bytes(),
                self.user.as_bytes(),
                self.op.id().as_bytes(),
                self.path.as_bytes(),
                match self.op {
                    Op::ListBranches | Op::ListConversations | Op::ListConnections => {
                        b"created_at,id"
                    }
                    Op::ListMessages => b"head-to-root",
                    _ => b"id",
                },
                binding.as_bytes(),
                &(self.limit as u32).to_be_bytes(),
                position,
            ],
        )
    }
    pub fn position<T: DeserializeOwned>(&self, binding: &str) -> Result<Option<T>, Problem> {
        let Some(cursor) = self.cursor else {
            return Ok(None);
        };
        if cursor.len() > 512 {
            return Err(INVALID_CURSOR);
        }
        let keys = self.keys.ok_or(PROVISIONING)?;
        let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| INVALID_CURSOR)?;
        let (&n, rest) = bytes.split_first().ok_or(INVALID_CURSOR)?;
        let (kid, rest) = rest.split_at_checked(n as usize).ok_or(INVALID_CURSOR)?;
        let kid = std::str::from_utf8(kid).map_err(|_| INVALID_CURSOR)?;
        let (tag, pos) = rest.split_at_checked(32).ok_or(INVALID_CURSOR)?;
        let (_, key) = std::iter::once(&keys.active)
            .chain(&keys.verify_only)
            .find(|(id, _)| id == kid)
            .ok_or(INVALID_CURSOR)?;
        hmac::verify(key, &self.identity(kid, binding, pos), tag).map_err(|_| INVALID_CURSOR)?;
        serde_json::from_slice(pos)
            .map(Some)
            .map_err(|_| INVALID_CURSOR)
    }
    pub fn finish<T: Serialize>(
        &self,
        items: Vec<Value>,
        binding: &str,
        next: Option<T>,
    ) -> Result<Response, Problem> {
        let cursor = next
            .map(|pos| {
                let (kid, key) = &self.keys.ok_or(PROVISIONING)?.active;
                let pos = serde_json::to_vec(&pos).map_err(|_| INTERNAL)?;
                let mut token = vec![kid.len() as u8];
                token.extend(kid.as_bytes());
                token.extend(hmac::sign(key, &self.identity(kid, binding, &pos)).as_ref());
                token.extend(pos);
                let encoded = URL_SAFE_NO_PAD.encode(token);
                if encoded.len() > 512 {
                    return Err(INTERNAL);
                }
                Ok(encoded)
            })
            .transpose()?;
        Ok(reply(
            StatusCode::OK,
            json!({"items":items,"page_info":{"next_cursor":cursor}}),
        ))
    }
}
