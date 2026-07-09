use std::path::PathBuf;

use clap::Parser;
use niralis_auth::{Authenticator, MockAuthenticator, PamAuthenticator};
use niralis_session::MockSessionLauncher;
use niralisd::config::{AuthBackend, Config, DEFAULT_CONFIG_PATH};
use niralisd::handler::DaemonHandler;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "Niralis display manager daemon")]
struct Cli {
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("niralisd: {error}");
        std::process::exit(1);
    }
}

type MainResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn run() -> MainResult<()> {
    let cli = Cli::parse();
    let config = Config::load_default_or_builtin(&cli.config)?;

    init_logging(&config.daemon.log_level)?;
    info!(config = %cli.config.display(), "starting niralisd");

    let authenticator = build_authenticator(&config);
    let handler = DaemonHandler::new(config.clone(), authenticator, MockSessionLauncher);
    niralisd::server::run(&config, handler)?;

    Ok(())
}

fn build_authenticator(config: &Config) -> Box<dyn Authenticator> {
    match config.auth.backend {
        AuthBackend::Mock => Box::new(MockAuthenticator),
        AuthBackend::Pam => Box::new(PamAuthenticator::new(config.auth.pam_service.clone())),
    }
}

fn init_logging(log_level: &str) -> MainResult<()> {
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(log_level))?;

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()?;

    Ok(())
}
