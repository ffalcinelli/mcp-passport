//! # mcp-passport: The AI-to-MCP Bridge
//!
//! This is the main entry point for the `mcp-passport` CLI.

use anyhow::Result;
use mcp_passport::config::Config;
use tokio::io;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse configuration from CLI and Environment Variables
    let config = Config::parse();

    // Ensure logs directory exists
    std::fs::create_dir_all("logs")?;

    // Setup logging to file (rotating daily)
    let file_appender = tracing_appender::rolling::daily("logs", "mcp-passport.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    // Initialize tracing with dual outputs: stderr (for human/client) and file (for debugging)
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(fmt::layer().with_ansi(false).with_writer(non_blocking))
        .init();

    info!("mcp-passport starting up...");
    info!("Configuration: {:?}", config);

    mcp_passport::run(config, io::stdin(), io::stdout()).await
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_main_help() {
        // We can't easily test main() because it calls Config::parse() which might exit.
        // But we can test that it compiles and has basic structure.
    }
}
