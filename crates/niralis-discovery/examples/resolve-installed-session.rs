//! Read-only smoke harness for desktop-session launch-spec resolution.
//!
//! It does not create a PAM transaction, spawn a worker, or execute the
//! resolved program. Run it with `cargo run -p niralis-discovery --example
//! resolve-installed-session -- niri`.

use niralis_discovery::{DesktopSessionDirectory, SessionDirectory, SessionDiscoveryConfig};

fn main() {
    let session_id = std::env::args().nth(1).unwrap_or_else(|| "niri".to_owned());
    let directory = DesktopSessionDirectory::new(SessionDiscoveryConfig::default());

    match directory.resolve_launch_spec(&session_id) {
        Ok(Some(spec)) => {
            println!("session_id={}", spec.session.id);
            println!("session_kind={:?}", spec.session.kind);
            println!("source_path={}", spec.source_path.display());
            println!("executable={}", spec.executable.display());
            println!("argc={}", spec.argv.len());
            println!("argv={:?}", spec.argv);
        }
        Ok(None) => {
            eprintln!("session unavailable: {session_id}");
            std::process::exit(2);
        }
        Err(error) => {
            eprintln!("session resolution failed: {error}");
            std::process::exit(1);
        }
    }
}
