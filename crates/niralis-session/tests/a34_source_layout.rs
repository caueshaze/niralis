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
