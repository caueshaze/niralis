use std::path::PathBuf;

use clap::Parser;
use niralis_discovery::{
    DesktopSessionDirectory, NssUserDirectory, SessionDirectory, SessionDiscoveryConfig,
    SessionSourceTrustPolicy, UserDirectory, UserDiscoveryConfig,
};
use niralisd::config::{AuthBackend, Config, DEFAULT_CONFIG_PATH};
use niralisd::handler::DaemonHandler;
use niralisd::login_backend::build_login_backend;
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

    let login_backend = build_login_backend(&config)?;
    let user_directory = build_user_directory(&config);
    let session_directory = build_session_directory(&config);
    let handler = DaemonHandler::new(
        config.clone(),
        login_backend,
        user_directory,
        session_directory,
    );
    niralisd::server::run(&config, handler)?;

    Ok(())
}

fn build_user_directory(config: &Config) -> Box<dyn UserDirectory> {
    Box::new(NssUserDirectory::new(UserDiscoveryConfig {
        min_uid: config.users.min_uid,
        allow_root: config.users.allow_root,
        exclude: config.users.exclude.clone(),
    }))
}

fn build_session_directory(config: &Config) -> Box<dyn SessionDirectory> {
    Box::new(DesktopSessionDirectory::new(SessionDiscoveryConfig {
        wayland_dirs: config.sessions.wayland_dirs.clone(),
        include_x11: config.sessions.include_x11,
        x11_dirs: config.sessions.x11_dirs.clone(),
        exec_search_path: config.sessions.exec_search_path.clone(),
        source_trust: if matches!(config.auth.backend, AuthBackend::Pam) {
            SessionSourceTrustPolicy::RootOwned
        } else {
            SessionSourceTrustPolicy::Permissive
        },
    }))
}

fn init_logging(log_level: &str) -> MainResult<()> {
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(log_level))?;

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()?;

    Ok(())
}
