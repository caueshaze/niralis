#![cfg(feature = "worker-test-fixtures")]

include!("full_worker/prelude.rs");
include!("full_worker/harness_spawn.rs");
include!("full_worker/harness_control.rs");
include!("full_worker/running.rs");
include!("full_worker/barriers.rs");
include!("full_worker/precommit.rs");
