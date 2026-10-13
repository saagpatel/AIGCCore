//! Operational logging, kept separate from the evidence audit trail.
//!
//! The logger deliberately prints only the level and the log target, never the
//! message: messages may carry payloads, paths or secrets. Call sites therefore
//! choose a distinct target per operation. `RUST_LOG` is read once at startup.

use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::sync::OnceLock;

const DEFAULT_LEVEL: LevelFilter = LevelFilter::Info;

/// A parsed `RUST_LOG` value: an optional global level plus per-target levels,
/// for example `warn,aigc_core::vault=debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFilter {
    default: LevelFilter,
    targets: Vec<(String, LevelFilter)>,
}

impl LogFilter {
    pub fn parse(spec: Option<&str>) -> Self {
        let mut filter = Self {
            default: DEFAULT_LEVEL,
            targets: Vec::new(),
        };
        for directive in spec.unwrap_or("").split(',').map(str::trim) {
            if directive.is_empty() {
                continue;
            }
            match directive.split_once('=') {
                Some((target, level)) => {
                    // An unparsable level drops the directive rather than guessing.
                    if let (false, Ok(level)) = (target.trim().is_empty(), level.trim().parse()) {
                        filter.targets.push((target.trim().to_string(), level));
                    }
                }
                None => match directive.parse::<LevelFilter>() {
                    Ok(level) => filter.default = level,
                    // A bare word names a target: enable everything for it.
                    Err(_) => filter
                        .targets
                        .push((directive.to_string(), LevelFilter::Trace)),
                },
            }
        }
        filter
    }

    /// The most verbose level any directive asks for; the `log` crate uses it
    /// to skip work for records nothing will print.
    pub fn max_level(&self) -> LevelFilter {
        self.targets
            .iter()
            .map(|(_, level)| *level)
            .fold(self.default, std::cmp::max)
    }

    pub fn allows(&self, target: &str, level: Level) -> bool {
        let level_for_target = self
            .targets
            .iter()
            .filter(|(prefix, _)| {
                target == prefix
                    || target
                        .strip_prefix(prefix.as_str())
                        .is_some_and(|rest| rest.starts_with("::"))
            })
            .max_by_key(|(prefix, _)| prefix.len())
            .map_or(self.default, |(_, level)| *level);
        level <= level_for_target
    }
}

struct RedactedLogger {
    filter: LogFilter,
}

impl Log for RedactedLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.filter.allows(metadata.target(), metadata.level())
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            eprintln!("{} {}", record.level(), record.target());
        }
    }

    fn flush(&self) {}
}

static LOGGER: OnceLock<RedactedLogger> = OnceLock::new();

/// Install the logger, reading `RUST_LOG` exactly once.
pub fn init() -> Result<(), SetLoggerError> {
    let logger = LOGGER.get_or_init(|| RedactedLogger {
        filter: LogFilter::parse(std::env::var("RUST_LOG").ok().as_deref()),
    });
    log::set_max_level(logger.filter.max_level());
    log::set_logger(logger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_info_and_reads_a_bare_level() {
        let default = LogFilter::parse(None);
        assert!(default.allows("any", Level::Info));
        assert!(!default.allows("any", Level::Debug));
        let warn = LogFilter::parse(Some(" warn "));
        assert!(warn.allows("any", Level::Warn));
        assert!(!warn.allows("any", Level::Info));
        assert_eq!(LogFilter::parse(Some("off")).max_level(), LevelFilter::Off);
    }

    #[test]
    fn comma_separated_directives_apply_by_most_specific_target() {
        let filter = LogFilter::parse(Some("warn,aigc_core=debug,aigc_core::vault=error"));
        assert!(filter.allows("other", Level::Warn));
        assert!(!filter.allows("other", Level::Info));
        assert!(filter.allows("aigc_core::audit", Level::Debug));
        assert!(!filter.allows("aigc_core::vault", Level::Warn));
        assert!(filter.allows("aigc_core::vault::cleanup", Level::Error));
        // A shared name prefix without a path separator is a different target.
        assert!(!filter.allows("aigc_core_tauri", Level::Debug));
        assert_eq!(filter.max_level(), LevelFilter::Debug);
    }

    #[test]
    fn malformed_directives_are_ignored_and_bare_words_name_targets() {
        let filter = LogFilter::parse(Some("aigc_core::vault=loud,=debug,,my_target"));
        assert_eq!(filter.default, LevelFilter::Info);
        assert!(!filter.allows("aigc_core::vault", Level::Debug));
        assert!(filter.allows("my_target", Level::Trace));
    }
}
