use crate::audit::event::{finalize_event, AuditEvent, ZERO_HASH_64};
use crate::error::{CoreError, CoreResult};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

const AUDIT_EVENT_KEYS: [&str; 8] = [
    "ts_utc",
    "event_type",
    "run_id",
    "vault_id",
    "actor",
    "details",
    "prev_event_hash",
    "event_hash",
];

#[derive(Debug)]
pub struct AuditLog {
    path: std::path::PathBuf,
    last_hash: String,
}

impl AuditLog {
    pub fn open_or_create(path: impl AsRef<Path>) -> CoreResult<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            File::create(&path)?;
            return Ok(Self {
                path,
                last_hash: ZERO_HASH_64.to_string(),
            });
        }

        let contents = fs::read_to_string(&path)?;
        let last_hash = verify_ndjson(&contents)?;
        Ok(Self { path, last_hash })
    }

    pub fn append(&mut self, mut event: AuditEvent) -> CoreResult<AuditEvent> {
        // Revalidate the persisted chain before appending. This detects a log that
        // changed after open_or_create (including edits by another writer) instead
        // of extending an already-invalid or stale chain.
        let persisted_last_hash = verify_ndjson(&fs::read_to_string(&self.path)?)?;
        if persisted_last_hash != self.last_hash {
            return Err(CoreError::InvalidInput(
                "audit log changed since it was opened".to_string(),
            ));
        }
        event.prev_event_hash = self.last_hash.clone();
        let event = finalize_event(event)?;
        let line = serde_json::to_string(&event)?; // already canonical rules for hashing; log bytes can be compact JSON
        let mut f = OpenOptions::new().append(true).open(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        self.last_hash = event.event_hash.clone();
        Ok(event)
    }

    pub fn read_all_ndjson(&self) -> CoreResult<String> {
        Ok(fs::read_to_string(&self.path)?)
    }
}

/// Verify every event in an NDJSON audit log and return the final event hash.
///
/// Verification is intentionally performed at the persistence boundary: a
/// caller must not resume an audit log merely because its final line has a
/// hash. Every event must be a locked envelope, satisfy the event taxonomy,
/// point at the preceding hash, and reproduce its own hash.
fn verify_ndjson(ndjson: &str) -> CoreResult<String> {
    let mut previous_hash = ZERO_HASH_64.to_string();
    let mut event_count = 0usize;

    for (line_index, line) in ndjson.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let value: Value = serde_json::from_str(line).map_err(|error| {
            CoreError::InvalidInput(format!(
                "audit_log line {} is not valid JSON: {}",
                line_index + 1,
                error
            ))
        })?;
        let object = value.as_object().ok_or_else(|| {
            CoreError::InvalidInput(format!(
                "audit_log line {} must be a JSON object",
                line_index + 1
            ))
        })?;

        if object.len() != AUDIT_EVENT_KEYS.len()
            || object
                .keys()
                .any(|key| !AUDIT_EVENT_KEYS.contains(&key.as_str()))
        {
            return Err(CoreError::InvalidInput(format!(
                "audit_log line {} must contain only the locked event envelope keys",
                line_index + 1
            )));
        }

        let event: AuditEvent = serde_json::from_value(value).map_err(|error| {
            CoreError::InvalidInput(format!(
                "audit_log line {} has an invalid event envelope: {}",
                line_index + 1,
                error
            ))
        })?;

        if event.prev_event_hash != previous_hash {
            return Err(CoreError::InvalidInput(format!(
                "audit_log line {} has prev_event_hash {}, expected {}",
                line_index + 1,
                event.prev_event_hash,
                previous_hash
            )));
        }

        let finalized = finalize_event(event.clone()).map_err(|error| {
            CoreError::InvalidInput(format!(
                "audit_log line {} failed event validation: {}",
                line_index + 1,
                error
            ))
        })?;
        if finalized.event_hash != event.event_hash {
            return Err(CoreError::InvalidInput(format!(
                "audit_log line {} has event_hash {}, expected {}",
                line_index + 1,
                event.event_hash,
                finalized.event_hash
            )));
        }

        previous_hash = event.event_hash;
        event_count += 1;
    }

    if event_count == 0 {
        return Ok(ZERO_HASH_64.to_string());
    }
    Ok(previous_hash)
}
