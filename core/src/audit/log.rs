use crate::audit::event::{finalize_event, AuditEvent, ZERO_HASH_64};
use crate::error::{CoreError, CoreResult};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

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

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let mut last_hash = ZERO_HASH_64.to_string();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(&line)?;
            let eh = v
                .get("event_hash")
                .and_then(|x| x.as_str())
                .ok_or_else(|| {
                    CoreError::InvalidInput("audit_log line missing event_hash".to_string())
                })?;
            last_hash = eh.to_string();
        }
        Ok(Self { path, last_hash })
    }

    pub fn append(&mut self, mut event: AuditEvent) -> CoreResult<AuditEvent> {
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
