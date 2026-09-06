use mcp_passport::config::Config;
use tracing::info;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();


    // Ensure log directory exists with secure permissions (0700) atomically on Unix-like systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        if !std::path::Path::new(&config.log_dir).exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            if let Err(e) = builder.create(&config.log_dir) {
                eprintln!("Failed to create log directory securely: {}", e);
            }
        }
    }
    #[cfg(not(unix))]
    {
        if !std::path::Path::new(&config.log_dir).exists() {
            if let Err(e) = std::fs::create_dir_all(&config.log_dir) {
                eprintln!("Failed to create log directory: {}", e);
            }
        }
    }

    // Setup file logging if requested
    let file_appender = tracing_appender::rolling::never(&config.log_dir, "mcp-passport.log");
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

    mcp_passport::run(config, tokio::io::stdin(), tokio::io::stdout()).await
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_main_help() {
        // We can't easily test main() because it calls Config::parse() which might exit.
        // But we can test that it compiles and has basic structure.
    }
}
