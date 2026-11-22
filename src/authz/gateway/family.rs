//! Wall-clock schedules on the gateway's pinned family revision. Convert an instant
//! to local time: missing spring minutes never occur and both autumn occurrences agree.
use super::Error;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hours {
    pub start_minute: u16,
    pub end_minute: u16,
}
impl Hours {
    fn contains(&self, m: u16) -> bool {
        if self.start_minute < self.end_minute {
            (self.start_minute..self.end_minute).contains(&m)
        } else {
            m >= self.start_minute || m < self.end_minute
        }
    }
}
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FamilyPolicy {
    pub revision: i64,
    pub zone: String,
    pub quiet: Option<Hours>,
    pub study: Option<Hours>,
    pub study_models: BTreeSet<String>,
    pub disabled_models: BTreeSet<String>,
}
impl FamilyPolicy {
    pub(super) async fn local_minute(
        &self,
        c: &mut PgConnection,
        instant_ms: Option<i64>,
    ) -> Result<u16, Error> {
        if self.revision < 1
            || self.zone.len() > 128
            || [self.quiet.as_ref(), self.study.as_ref()]
                .into_iter()
                .flatten()
                .any(|h| {
                    h.start_minute >= 1440 || h.end_minute >= 1440 || h.start_minute == h.end_minute
                })
        {
            return Err(Error::Refused);
        }
        let minute: i32 = sqlx::query_scalar("SELECT extract(hour FROM local_time)::int*60+extract(minute FROM local_time)::int
            FROM (SELECT coalesce(to_timestamp($2::bigint/1000.0),clock_timestamp()) AT TIME ZONE name AS local_time
            FROM pg_catalog.pg_timezone_names WHERE name=$1) z")
            .bind(&self.zone).bind(instant_ms).fetch_optional(c).await?.ok_or(Error::Refused)?;
        Ok(minute as u16)
    }
    pub async fn permits(
        &self,
        c: &mut PgConnection,
        model: &str,
        instant_ms: Option<i64>,
    ) -> Result<bool, Error> {
        let minute = self.local_minute(c, instant_ms).await?;
        Ok(self.permits_minute(model, minute))
    }
    pub(super) fn permits_minute(&self, model: &str, minute: u16) -> bool {
        !self.disabled_models.contains(model)
            && !self.quiet.as_ref().is_some_and(|h| h.contains(minute))
            && (!self.study.as_ref().is_some_and(|h| h.contains(minute))
                || self.study_models.contains(model))
    }
}
