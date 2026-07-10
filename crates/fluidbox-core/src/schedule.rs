//! Cron schedule domain (design doc §6.2). Pure: parsing, validation, and
//! DST-correct next-fire computation — no clock, no I/O; the scheduler
//! worker supplies `now`. §17 #5 (settled 2026-07-10): overlap default
//! `allow`, missed-run default `skip`; catch_up fires exactly ONE run —
//! fire-all-missed is a thundering herd and is not representable here.

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use std::str::FromStr;

/// What happens when a firing (or API invoke) comes due while a previous
/// run of the same subscription is still active. Enforced for ALL
/// invocations inside `run_service::create_run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConcurrencyPolicy {
    #[default]
    Allow,
    SkipIfRunning,
    Replace,
}

impl ConcurrencyPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "skip_if_running" => Some(Self::SkipIfRunning),
            "replace" => Some(Self::Replace),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::SkipIfRunning => "skip_if_running",
            Self::Replace => "replace",
        }
    }
}

/// What happens when the scheduler discovers fire times in the past
/// (control plane down, or the subscription was disabled across them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MissedRunPolicy {
    #[default]
    Skip,
    CatchUp,
}

impl MissedRunPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "skip" => Some(Self::Skip),
            "catch_up" => Some(Self::CatchUp),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::CatchUp => "catch_up",
        }
    }
}

/// A parsed cron expression bound to an explicit IANA timezone. The `cron`
/// crate wants a seconds field, so a standard 5-field expression gets
/// second 0 prepended; 6/7-field expressions pass through — the seconds
/// field doubles as the e2e fire-fast seam (sub-minute cadence).
pub struct CronSchedule {
    schedule: cron::Schedule,
    tz: Tz,
}

impl CronSchedule {
    pub fn parse(cron_expr: &str, timezone: &str) -> Result<Self, String> {
        let tz = Tz::from_str(timezone).map_err(|_| {
            format!(
                "unknown timezone '{timezone}' (use an IANA name like 'America/New_York' or 'UTC')"
            )
        })?;
        let expr = cron_expr.trim();
        let normalized = match expr.split_whitespace().count() {
            5 => format!("0 {expr}"),
            6 | 7 => expr.to_string(),
            n => {
                return Err(format!(
                    "cron expression has {n} fields; want 5 (min hour dom mon dow) or 6-7 (with seconds)"
                ))
            }
        };
        let schedule = cron::Schedule::from_str(&normalized)
            .map_err(|e| format!("invalid cron expression: {e}"))?;
        Ok(Self { schedule, tz })
    }

    /// Next fire time strictly after `after`, computed in the schedule's
    /// timezone (DST-correct), returned in UTC. None = no future firing.
    pub fn next_fire_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.schedule
            .after(&after.with_timezone(&self.tz))
            .next()
            .map(|t| t.with_timezone(&Utc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn policies_parse_and_roundtrip() {
        assert_eq!(
            ConcurrencyPolicy::parse("allow"),
            Some(ConcurrencyPolicy::Allow)
        );
        assert_eq!(
            ConcurrencyPolicy::parse("skip_if_running"),
            Some(ConcurrencyPolicy::SkipIfRunning)
        );
        assert_eq!(
            ConcurrencyPolicy::parse("replace"),
            Some(ConcurrencyPolicy::Replace)
        );
        assert_eq!(ConcurrencyPolicy::parse("sometimes"), None);
        assert_eq!(ConcurrencyPolicy::default().as_str(), "allow"); // §17 #5
        assert_eq!(MissedRunPolicy::parse("skip"), Some(MissedRunPolicy::Skip));
        assert_eq!(
            MissedRunPolicy::parse("catch_up"),
            Some(MissedRunPolicy::CatchUp)
        );
        assert_eq!(MissedRunPolicy::parse("fire_all"), None);
        assert_eq!(MissedRunPolicy::default().as_str(), "skip"); // §17 #5
    }

    #[test]
    fn five_field_cron_is_normalized_and_six_field_passes_through() {
        // Standard cron (no seconds) — fires at second 0.
        let s = CronSchedule::parse("*/5 * * * *", "UTC").unwrap();
        let n = s.next_fire_after(utc("2026-07-10T00:01:00Z")).unwrap();
        assert_eq!(n, utc("2026-07-10T00:05:00Z"));
        // Seconds field (the e2e fire-fast seam).
        let s = CronSchedule::parse("*/5 * * * * *", "UTC").unwrap();
        let n = s.next_fire_after(utc("2026-07-10T00:00:01Z")).unwrap();
        assert_eq!(n, utc("2026-07-10T00:00:05Z"));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(CronSchedule::parse("*/5 * * * *", "Mars/Olympus").is_err());
        assert!(CronSchedule::parse("not a cron", "UTC").is_err());
        assert!(CronSchedule::parse("* * * *", "UTC").is_err()); // 4 fields
        assert!(CronSchedule::parse("99 * * * * *", "UTC").is_err()); // bad seconds
    }

    #[test]
    fn next_fire_is_dst_correct() {
        // America/New_York springs forward 2026-03-08 (EST -5 → EDT -4).
        // Daily 09:30 local must be 14:30Z before and 13:30Z after.
        let s = CronSchedule::parse("0 30 9 * * *", "America/New_York").unwrap();
        assert_eq!(
            s.next_fire_after(utc("2026-03-06T00:00:00Z")).unwrap(),
            utc("2026-03-06T14:30:00Z")
        );
        assert_eq!(
            s.next_fire_after(utc("2026-03-09T00:00:00Z")).unwrap(),
            utc("2026-03-09T13:30:00Z")
        );
        // Fixed +05:30 offset (no DST): 09:00 Kolkata = 03:30Z.
        let s = CronSchedule::parse("0 0 9 * * *", "Asia/Kolkata").unwrap();
        assert_eq!(
            s.next_fire_after(utc("2026-07-10T00:00:00Z")).unwrap(),
            utc("2026-07-10T03:30:00Z")
        );
    }

    #[test]
    fn next_fire_is_strictly_after() {
        let s = CronSchedule::parse("*/5 * * * * *", "UTC").unwrap();
        // `after` exactly on a fire boundary → the NEXT slot, never the same.
        let n = s.next_fire_after(utc("2026-07-10T00:00:05Z")).unwrap();
        assert_eq!(n, utc("2026-07-10T00:00:10Z"));
    }
}
