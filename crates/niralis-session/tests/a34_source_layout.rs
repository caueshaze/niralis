use std::path::Path;
use std::process::Command;

const MAX_RUST_SOURCE_LINES: usize = 250;

#[test]
fn authored_rust_source_files_stay_small_and_module_scoped() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.rs",
        ])
        .current_dir(root)
        .output()
        .expect("git is available for source-layout validation");
    assert!(output.status.success(), "git ls-files must succeed");
    let oversized = std::str::from_utf8(&output.stdout)
        .expect("Git paths are UTF-8")
        .split('\0')
        .filter(|path| !path.is_empty())
        .filter(|path| !path.ends_with("/supervisor_loop/admission.rs"))
        .filter(|path| !path.ends_with("/supervisor_loop/admission_tests.rs"))
        .filter(|path| !path.ends_with("/launcher/login_transaction.rs"))
        .filter(|path| !path.ends_with("/launcher/public_api.rs"))
        .filter(|path| !path.ends_with("/launcher/launch_completion.rs"))
        .filter(|path| !path.ends_with("/src/tests.rs"))
        .filter_map(|relative| {
            let path = root.join(relative);
            let lines = std::fs::read_to_string(&path).ok()?.lines().count();
            (lines > MAX_RUST_SOURCE_LINES).then(|| format!("{} ({lines})", path.display()))
        })
        .collect::<Vec<_>>();
    assert!(
        oversized.is_empty(),
        "authored Rust source files exceed {MAX_RUST_SOURCE_LINES} lines: {oversized:?}"
    );
}

#[test]
fn no_direct_seat_mutation_exists_outside_controller() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "crates/niralis-session/src/launcher/supervisor_loop/*.rs",
        ])
        .current_dir(root)
        .output()
        .expect("git is available for seat authority validation");
    assert!(output.status.success());
    let violations = std::str::from_utf8(&output.stdout)
        .expect("Git paths are UTF-8")
        .split('\0')
        .filter(|path| !path.is_empty() && !path.ends_with("/admission.rs"))
        .filter_map(|relative| {
            let path = root.join(relative);
            let contents = std::fs::read_to_string(&path).ok()?;
            contents.lines().enumerate().find_map(|(line, text)| {
                (text.contains("self.seat =") || text.contains("*seat ="))
                    .then(|| format!("{}:{}", path.display(), line + 1))
            })
        })
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "direct seat mutation outside SeatAdmissionController: {violations:?}"
    );
}

#[test]
fn control_handlers_require_transaction_identity_not_transport_identity() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    let source = std::fs::read_to_string(
        root.join("crates/niralis-session/src/launcher/launch_protocol.rs"),
    )
    .expect("launch protocol source is readable");
    assert!(source.contains("ControlTransactionIdentity"));
    assert!(source.contains("matches_worker("));
    assert!(
        source.contains("request_transaction.matches_worker("),
        "transport binding must be accompanied by transaction identity validation"
    );
}

#[test]
fn no_independent_local_backend_owner_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    let transaction = std::fs::read_to_string(
        root.join("crates/niralis-session/src/launcher/login_transaction.rs"),
    )
    .expect("transaction source is readable");
    let daemon_backend =
        std::fs::read_to_string(root.join("crates/niralisd/src/login_backend/local.rs"))
            .expect("daemon backend source is readable");
    assert!(transaction.contains("fn attach_backend("));
    assert!(transaction.contains("struct TransactionOwnedLoginBackend"));
    assert!(!daemon_backend.contains("struct TransactionOwnedLoginBackend"));
    assert!(!daemon_backend.contains("next_transaction_id"));
}

#[test]
fn session_launcher_trait_has_no_legacy_pre_auth_default() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    let source = std::fs::read_to_string(root.join("crates/niralis-session/src/types.rs"))
        .expect("session type source is readable");
    assert!(source.contains("pub trait SessionLauncher"));
    assert!(
        !source.contains("fn start_session("),
        "public launcher trait must not expose start_session"
    );
    assert!(
        !source.contains("self.start_session("),
        "launcher trait must not retain the legacy default pre-auth path"
    );
}

#[test]
fn legacy_authenticated_launch_test_shortcuts_are_absent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.rs",
        ])
        .current_dir(root)
        .output()
        .expect("git is available for source-layout validation");
    assert!(output.status.success());
    let violations = std::str::from_utf8(&output.stdout)
        .expect("Git paths are UTF-8")
        .split('\0')
        .filter(|path| !path.is_empty())
        .filter_map(|relative| {
            let path = root.join(relative);
            if relative == "crates/niralis-session/tests/a34_source_layout.rs" {
                return None;
            }
            let contents = std::fs::read_to_string(&path).ok()?;
            [
                "launch_authenticated",
                "authentication_result: true",
                ".start_session(",
            ]
            .into_iter()
            .find(|needle| contents.contains(needle))
            .map(|needle| format!("{} contains `{needle}`", path.display()))
        })
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "legacy authenticated-launch shortcuts remain: {violations:?}"
    );
}
