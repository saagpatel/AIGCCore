#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(error) = init_logging() {
        eprintln!("operational logging initialization failed: {error}");
    }
    aigc_core_tauri::run();
}

struct RedactedLogger;

impl log::Log for RedactedLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= configured_level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            // Deliberately omit message fields: they may contain payloads, paths, or secrets.
            eprintln!("{} {}", record.level(), record.target());
        }
    }

    fn flush(&self) {}
}

static LOGGER: RedactedLogger = RedactedLogger;

fn configured_level() -> log::LevelFilter {
    let value = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let level = value
        .rsplit('=')
        .next()
        .unwrap_or("info")
        .trim()
        .to_ascii_lowercase();
    match level.as_str() {
        "off" => log::LevelFilter::Off,
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    }
}

fn init_logging() -> Result<(), log::SetLoggerError> {
    log::set_logger(&LOGGER)?;
    log::set_max_level(configured_level());
    Ok(())
}
