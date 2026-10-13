//! Reopened logs are accepted only when every canonical event hash and previous-hash link verifies.

use crate::audit::event::{finalize_event, AuditEvent, ZERO_HASH_64};
use crate::error::{CoreError, CoreResult};
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
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
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| CoreError::io("create audit log directory", parent, e))?;
        }
        // Never truncate: another writer may have created and extended the log
        // between any existence check and this open.
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .map_err(|e| CoreError::io("open audit log", &path, e))?;
        // A shared lock keeps a concurrent append from being read half-written.
        file.lock_shared()
            .map_err(|e| CoreError::io("lock audit log", &path, e))?;
        let result = (|| {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|e| CoreError::io("read audit log", &path, e))?;
            if !bytes.is_empty() && !bytes.ends_with(b"\n") {
                return Err(CoreError::InvalidInput(
                    "AUDIT_UNTERMINATED_TAIL: refusing to append to an incomplete final record"
                        .into(),
                ));
            }
            let contents = String::from_utf8(bytes).map_err(|error| {
                CoreError::InvalidInput(format!("audit log is not UTF-8: {error}"))
            })?;
            verify_ndjson(&contents)
        })();
        let unlock = file.unlock();
        let last_hash = result?;
        unlock.map_err(|e| CoreError::io("unlock audit log", &path, e))?;
        Ok(Self { path, last_hash })
    }

    pub fn append(&mut self, mut event: AuditEvent) -> CoreResult<AuditEvent> {
        let mut f = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| CoreError::io("open audit log", &self.path, e))?;
        f.lock()
            .map_err(|e| CoreError::io("lock audit log", &self.path, e))?;
        let result = (|| {
            let opened_hash = self.last_hash.clone();
            let persisted_len = f.metadata()?.len();
            let (persisted_hash, persisted_previous_hash) =
                read_verified_tail(&mut f, persisted_len)?;
            if persisted_hash != opened_hash && persisted_previous_hash != opened_hash {
                return Err(CoreError::InvalidInput(
                    "AUDIT_STALE_WRITER: persisted tail does not extend the opened chain by one event"
                        .into(),
                ));
            }
            self.last_hash = persisted_hash;
            event.prev_event_hash = self.last_hash.clone();
            let event = finalize_event(event)?;
            let mut line = serde_json::to_string(&event)?;
            line.push('\n');
            // One write keeps the record and its terminator together.
            f.write_all(line.as_bytes())
                .map_err(|e| CoreError::io("append audit record", &self.path, e))?;
            f.sync_all()
                .map_err(|e| CoreError::io("sync audit log", &self.path, e))?;
            self.last_hash = event.event_hash.clone();
            Ok(event)
        })();
        let unlock = f.unlock();
        let event = result?;
        unlock.map_err(|e| CoreError::io("unlock audit log", &self.path, e))?;
        Ok(event)
    }

    pub fn read_all_ndjson(&self) -> CoreResult<String> {
        Ok(fs::read_to_string(&self.path)?)
    }
}

fn read_verified_tail<R: Read + Seek>(file: &mut R, length: u64) -> CoreResult<(String, String)> {
    if length == 0 {
        return Ok((ZERO_HASH_64.to_string(), ZERO_HASH_64.to_string()));
    }
    file.seek(SeekFrom::End(-1))?;
    let mut final_byte = [0u8; 1];
    file.read_exact(&mut final_byte)?;
    if final_byte[0] != b'\n' {
        return Err(CoreError::InvalidInput(
            "AUDIT_UNTERMINATED_TAIL: refusing to append to an incomplete final record".into(),
        ));
    }
    let mut cursor = length - 1;
    let mut tail_start = 0u64;
    let mut buffer = [0u8; 4096];
    while cursor > 0 {
        let start = cursor.saturating_sub(buffer.len() as u64);
        let count = (cursor - start) as usize;
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut buffer[..count])?;
        if let Some(position) = buffer[..count].iter().rposition(|byte| *byte == b'\n') {
            tail_start = start + position as u64 + 1;
            break;
        }
        cursor = start;
    }
    let tail_len = length - 1 - tail_start;
    let mut tail = vec![0u8; tail_len as usize];
    file.seek(SeekFrom::Start(tail_start))?;
    file.read_exact(&mut tail)?;
    let line = String::from_utf8(tail)
        .map_err(|error| CoreError::InvalidInput(format!("audit tail is not UTF-8: {error}")))?;
    let value: Value = serde_json::from_str(&line)
        .map_err(|error| CoreError::InvalidInput(format!("audit tail is invalid JSON: {error}")))?;
    let object = value.as_object().ok_or_else(|| {
        CoreError::InvalidInput("AUDIT_INVALID_TAIL: final record must be an object".into())
    })?;
    if object.len() != AUDIT_EVENT_KEYS.len()
        || object
            .keys()
            .any(|key| !AUDIT_EVENT_KEYS.contains(&key.as_str()))
    {
        return Err(CoreError::InvalidInput(
            "AUDIT_INVALID_TAIL: final record has an unlocked envelope".into(),
        ));
    }
    let event: AuditEvent = serde_json::from_value(value)?;
    let finalized = finalize_event(event.clone())?;
    if finalized.event_hash != event.event_hash {
        return Err(CoreError::InvalidInput(
            "AUDIT_INVALID_TAIL: final event hash does not verify".into(),
        ));
    }
    Ok((event.event_hash, event.prev_event_hash))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::Actor;
    use std::cell::Cell;
    use std::io::Cursor;
    use std::rc::Rc;

    struct CountedCursor {
        cursor: Cursor<Vec<u8>>,
        bytes_read: Rc<Cell<usize>>,
    }

    impl Read for CountedCursor {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let count = self.cursor.read(output)?;
            self.bytes_read.set(self.bytes_read.get() + count);
            Ok(count)
        }
    }

    impl Seek for CountedCursor {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.cursor.seek(position)
        }
    }

    #[test]
    fn append_tail_verification_reads_constant_tail_bytes() {
        let event = finalize_event(AuditEvent {
            ts_utc: "2026-01-01T00:00:00Z".into(),
            event_type: "RUN_COMPLETED".into(),
            run_id: "r_test".into(),
            vault_id: "v_test".into(),
            actor: Actor::System,
            details: serde_json::json!({}),
            prev_event_hash: ZERO_HASH_64.into(),
            event_hash: String::new(),
        })
        .unwrap();
        let mut bytes = vec![b'x'; 1_000_000];
        bytes.push(b'\n');
        bytes.extend_from_slice(serde_json::to_string(&event).unwrap().as_bytes());
        bytes.push(b'\n');
        let length = bytes.len() as u64;
        let bytes_read = Rc::new(Cell::new(0));
        let mut input = CountedCursor {
            cursor: Cursor::new(bytes),
            bytes_read: bytes_read.clone(),
        };
        assert_eq!(
            read_verified_tail(&mut input, length).unwrap().0,
            event.event_hash
        );
        assert!(bytes_read.get() < 8192, "read {} bytes", bytes_read.get());
    }
}
