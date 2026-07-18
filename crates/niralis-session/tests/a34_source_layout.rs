use std::fs;
use std::path::Path;

const MAX_A34_SOURCE_LINES: usize = 250;
const A34_DIRECTORIES: &[&str] = &[
    "src/launcher/recovery",
    "src/launcher/supervisor_loop",
    "tests/supervisor_full_process_cases",
];
const A34_FILES: &[&str] = &[
    "src/launcher.rs",
    "src/launcher/contracts.rs",
    "src/launcher/launch_completion.rs",
    "src/launcher/launch_protocol.rs",
    "src/launcher/public_api.rs",
    "src/launcher/supervisor_api.rs",
    "src/launcher/supervisor_shutdown.rs",
    "src/worker_attempt/io_wait.rs",
    "src/worker_attempt/process.rs",
    "src/bin/fixture-supervisor-worker.rs",
    "tests/supervisor_full_process.rs",
];

#[test]
fn a34_source_files_stay_small_and_module_scoped() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = A34_FILES
        .iter()
        .map(|relative| root.join(relative))
        .collect::<Vec<_>>();
    for directory in A34_DIRECTORIES {
        collect_rust_files(&root.join(directory), &mut files);
    }
    let oversized = files
        .iter()
        .filter_map(|path| {
            let lines = fs::read_to_string(path).ok()?.lines().count();
            (lines > MAX_A34_SOURCE_LINES).then(|| format!("{} ({lines})", path.display()))
        })
        .collect::<Vec<_>>();
    assert!(
        oversized.is_empty(),
        "A3.4 source files exceed {MAX_A34_SOURCE_LINES} lines: {oversized:?}"
    );
}

fn collect_rust_files(directory: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(directory).expect("A3.4 source directory exists") {
        let path = entry.expect("A3.4 source entry").path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}
