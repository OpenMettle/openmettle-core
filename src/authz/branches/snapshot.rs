//! The v1 storage encoding for a managed submission. Compare only normalized client intent
//! on replay. The original snapshot bytes remain the input to the durable run identity.
use super::{History, Operation, Part, PartContent};
use crate::{
    authz::runs::RunReplay,
    model_config::{Catalog, ConfigSnapshot, Error, SNAPSHOT_FORMAT, SNAPSHOT_VERSION, Selection},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize)]
pub struct Intent<'a> {
    pub source_branch_id: &'a str,
    pub expected_head_message_id: Option<&'a str>,
    pub operation: Operation<'a>,
    pub selection: &'a Selection,
    pub requested_rounds: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Attachment {
    pub ordinal: i32,
    /// An unavailable historical attachment is pinned as an omission.
    pub revision_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PinnedTurn {
    pub message_id: String,
    pub replay_reasoning: bool,
    pub attachments: Vec<Attachment>,
}

#[derive(Serialize, Deserialize)]
pub struct InputSnapshot {
    intent: Value,
    pub path: Vec<PinnedTurn>,
}

impl InputSnapshot {
    pub fn matches(&self, intent: &Intent<'_>) -> bool {
        serde_json::to_value(intent).is_ok_and(|value| value == self.intent)
    }
}

pub struct Snapshots {
    pub input: Vec<u8>,
    pub config: Vec<u8>,
}

impl Snapshots {
    /// Pin the prepared destination's path, including the selected input. Only immutable IDs,
    /// ordinals and the target's replay decision are needed to recover historical content.
    pub fn encode(
        intent: &Intent<'_>,
        history: &History,
        catalog: &Catalog,
        config: &ConfigSnapshot,
    ) -> Result<Self, Error> {
        let target = catalog.target(&config.effective)?;
        let mut path = Vec::with_capacity(history.turns.len());
        for (depth, turn) in history.turns.iter().enumerate() {
            let mut attachments = Vec::new();
            for part in &turn.parts {
                let revision_id = match &part.value {
                    PartContent::Available(Part::Text(_)) => continue,
                    PartContent::Available(Part::Attachment(id)) => Some(id.clone()),
                    PartContent::RetainedAttachment(_) | PartContent::UnavailableAttachment => {
                        if depth == 0 {
                            return Err(Error::Invalid("input attachment"));
                        }
                        None
                    }
                };
                attachments.push(Attachment {
                    ordinal: part.ordinal,
                    revision_id,
                });
            }
            path.push(PinnedTurn {
                message_id: turn.metadata.message_id.clone(),
                replay_reasoning: turn.metadata.reasoning_bytes > 0
                    && turn.metadata.replay_rule(target).is_some(),
                attachments,
            });
        }
        let input = InputSnapshot {
            intent: serde_json::to_value(intent)
                .map_err(|_| Error::Invalid("submission intent"))?,
            path,
        };
        let input = serde_json::to_vec(&input).map_err(|_| Error::Invalid("input snapshot"))?;
        let config =
            serde_json::to_vec(config).map_err(|_| Error::Invalid("configuration snapshot"))?;
        if input.len().saturating_add(config.len()) > crate::runs::MAX_SNAPSHOT_BYTES {
            return Err(Error::Invalid("snapshot size"));
        }
        Ok(Self { input, config })
    }

    pub fn decode(run: &RunReplay) -> Result<(InputSnapshot, ConfigSnapshot), Error> {
        if run.snapshot_format != SNAPSHOT_FORMAT || run.snapshot_version != SNAPSHOT_VERSION {
            return Err(Error::Invalid("snapshot version"));
        }
        let input = serde_json::from_slice(&run.input_snapshot)
            .map_err(|_| Error::Invalid("input snapshot"))?;
        let config = serde_json::from_slice(&run.config_snapshot)
            .map_err(|_| Error::Invalid("configuration snapshot"))?;
        Ok((input, config))
    }
}
