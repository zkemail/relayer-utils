//! Logger module for initializing a global logger instance using `slog`.

use file_rotate::{
    compression::Compression,
    suffix::{AppendTimestamp, FileLimit},
    ContentLimit, FileRotate,
};
use lazy_static::lazy_static;
use slog::{o, Drain};
use slog_async;
use slog_json;
use slog_term;
use std::env;

use crate::JSON_LOGGER_KEY;

lazy_static! {
    /// Global logger instance using `slog`.
    pub static ref LOG: slog::Logger = init_logger();
}

/// Initializes the logger with specific configurations for terminal and file output.
///
/// The logger outputs to the terminal and a file located in the `logs` directory.
/// The file output includes rotation and compression features.
/// The terminal output format is determined by the `JSON_LOGGER_KEY` environment variable.
///
/// # Returns
///
/// A `slog::Logger` instance with the configured drains.
fn init_logger() -> slog::Logger {
    // Define the directory and file path for the log files.
    let directory = std::path::Path::new("logs");
    let log_path = directory.join("relayer.log");

    // Configure file rotation, size limits, and compression.
    let file_rotate = FileRotate::new(
        log_path.clone(),
        AppendTimestamp::default(FileLimit::MaxFiles(1_000_000)),
        ContentLimit::Bytes(5_000_000),
        Compression::OnRotate(5),
        #[cfg(unix)]
        None,
    );

    // Create a JSON drain for logging to files.
    let log_file_drain = slog_json::Json::default(file_rotate).fuse();

    // Determine if JSON output to the terminal is enabled via environment variable.
    let terminal_json_output = match env::var(JSON_LOGGER_KEY) {
        Ok(val) => val.eq_ignore_ascii_case("true"),
        Err(_) => false,
    };

    // Configure terminal output decorators and drains.
    let log_terminal_decorator = slog_term::TermDecorator::new().build();
    let log_terminal_drain = slog_term::FullFormat::new(log_terminal_decorator)
        .build()
        .fuse();
    let log_terminal_json_drain = slog_json::Json::default(std::io::stdout()).fuse();

    // Create the logger drain based on the terminal output configuration.
    if terminal_json_output {
        // If JSON output is enabled, duplicate logs to both terminal and file in JSON format.
        let log_drain =
            slog_async::Async::new(slog::Duplicate(log_terminal_json_drain, log_file_drain).fuse())
                .build()
                .fuse();
        slog::Logger::root(
            log_drain,
            o!("version" => env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string())),
        )
    } else {
        // Otherwise, use formatted text for terminal and JSON for file logging.
        let log_drain =
            slog_async::Async::new(slog::Duplicate(log_terminal_drain, log_file_drain).fuse())
                .chan_size(10_000) // Increase the channel size for the async drain.
                .overflow_strategy(slog_async::OverflowStrategy::Block) // Set overflow strategy to block when the channel is full.
                .build()
                .fuse();
        slog::Logger::root(
            log_drain,
            o!("version" => env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string())),
        )
    }
}
