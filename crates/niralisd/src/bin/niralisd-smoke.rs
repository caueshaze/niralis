use std::path::PathBuf;

use clap::{Parser, Subcommand};
use niralis_session::{
    PhysicalPreviousBootSmoke, PhysicalPreviousBootSmokeFailpoint, PhysicalPreviousBootSmokePaths,
};
use niralisd::config::{Config, DEFAULT_CONFIG_PATH};
use niralisd::session_launcher::build_worker_session_launcher_for_physical_smoke;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Fixture-only physical PreviousBoot startup smoke daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create one isolated SameBoot record that becomes PreviousBoot only
    /// after a physical reboot.
    Seed { run_id: String },
    /// Persist the one fixture-only failpoint used on the next boot.
    Arm { run_id: String, stage: String },
    /// Clear an armed failpoint only after its exact durable stage exists.
    Disarm { run_id: String },
    /// Run the normal persistent launcher startup against the isolated ledger.
    Run {
        run_id: String,
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
}

fn main() {
    init_logging();
    if let Err(error) = run() {
        eprintln!("niralisd-smoke: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    require_root()?;
    match Cli::parse().command {
        Command::Seed { run_id } => smoke(&run_id)?.seed()?,
        Command::Arm { run_id, stage } => {
            smoke(&run_id)?.arm(PhysicalPreviousBootSmokeFailpoint::parse(&stage)?)?
        }
        Command::Disarm { run_id } => smoke(&run_id)?.disarm()?,
        Command::Run { run_id, config } => {
            let smoke = smoke(&run_id)?;
            bind_controlled_failpoint(&smoke)?;
            smoke.assert_previous_boot_ready()?;
            let config = Config::load(&config)?;
            let _launcher = build_worker_session_launcher_for_physical_smoke(&config, &smoke)?;
            info!(run_id = %run_id, "previous_boot_physical_smoke_startup_complete");
        }
    }
    Ok(())
}

fn bind_controlled_failpoint(
    smoke: &PhysicalPreviousBootSmoke,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let armed = smoke.armed_failpoint()?;
    let environment = std::env::var("NIRALIS_PREVIOUS_BOOT_FAILPOINT")
        .ok()
        .map(|stage| PhysicalPreviousBootSmokeFailpoint::parse(&stage))
        .transpose()?;
    if environment.is_some_and(|value| Some(value) != armed) {
        return Err("systemd failpoint environment disagrees with root-owned control file".into());
    }
    if let Some(failpoint) = armed {
        std::env::set_var("NIRALIS_PREVIOUS_BOOT_FAILPOINT", failpoint.as_str());
    }
    Ok(())
}

fn smoke(run_id: &str) -> std::io::Result<PhysicalPreviousBootSmoke> {
    Ok(PhysicalPreviousBootSmoke::new(
        PhysicalPreviousBootSmokePaths::for_run_id(run_id)?,
    ))
}

fn require_root() -> std::io::Result<()> {
    // SAFETY: geteuid has no Rust-visible preconditions.
    if unsafe { libc::geteuid() } != 0 {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "niralisd-smoke requires uid 0",
        ))
    } else {
        Ok(())
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_style_run_arguments_are_accepted() {
        let cli = Cli::try_parse_from([
            "niralisd-smoke",
            "run",
            "a343c-historical",
            "--config",
            "/etc/niralis/niralis.toml",
        ])
        .unwrap();
        match cli.command {
            Command::Run { run_id, config } => {
                assert_eq!(run_id, "a343c-historical");
                assert_eq!(config, PathBuf::from("/etc/niralis/niralis.toml"));
            }
            _ => panic!("expected run command"),
        }
    }
}
