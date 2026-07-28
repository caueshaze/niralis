use super::*;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

impl Drop for PreCommitRuntimeStore {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl PreCommitRuntimeStore {
    pub(crate) fn open(
        directory: impl AsRef<Path>,
        lock_path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let directory = directory.as_ref().to_path_buf();
        create_secure_directory(&directory)?;
        if let Some(parent) = lock_path.as_ref().parent() {
            create_lock_parent(parent)?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(lock_path)?;
        let metadata = lock.metadata()?;
        if (metadata.uid() != 0 && !allow_non_root_test_storage())
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "precommit runtime lock permissions",
            ));
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "precommit runtime lock is held",
            ));
        }
        Ok(Self {
            directory: directory.clone(),
            _lock: lock,
            records: load_records(&directory)?,
            startup_quarantined: false,
            startup_quarantined_seats: Default::default(),
        })
    }

    pub(crate) fn create_reserved(
        &mut self,
        lifecycle_id: &str,
        attempt_id: u64,
        seat: &str,
        seat_generation: u64,
    ) -> io::Result<PreCommitRuntimeBinding> {
        if self.records.contains_key(lifecycle_id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "duplicate precommit lifecycle",
            ));
        }
        let boot_id = recovery::current_boot_id()?;
        let record = PreCommitRuntimeRecord {
            format_version: PRECOMMIT_FORMAT_VERSION,
            transaction_id: lifecycle_id.to_owned(),
            admission_attempt_id: attempt_id,
            lifecycle_id: lifecycle_id.to_owned(),
            seat: seat.to_owned(),
            seat_generation,
            boot_id,
            stage: "reserved".to_owned(),
            worker_pid: None,
            worker_starttime: None,
            worker_executable: None,
            channel_worker_id: None,
            sequence: 0,
            handoff_committed: false,
        };
        self.commit(record.clone())?;
        Ok(PreCommitRuntimeBinding {
            authority: self.binding_for(&record)?,
            record,
        })
    }

    pub(crate) fn update_stage(
        &mut self,
        binding: PreCommitRuntimeBinding,
        stage: &'static str,
        worker_id: Option<&str>,
        worker_pid: Option<u32>,
    ) -> io::Result<PreCommitRuntimeBinding> {
        self.update(binding, |record| {
            record.stage = stage.to_owned();
            if let Some(id) = worker_id {
                record.channel_worker_id = Some(id.to_owned());
            }
            if let Some(pid) = worker_pid {
                record.worker_pid = Some(pid);
                record.worker_starttime = proc_starttime(pid);
                record.worker_executable = proc_executable(pid);
            }
        })
    }

    pub(crate) fn mark_handoff_committed(
        &mut self,
        binding: PreCommitRuntimeBinding,
    ) -> io::Result<PreCommitRuntimeBinding> {
        self.update(binding, |record| {
            record.stage = "handoff_started".to_owned();
            record.handoff_committed = true;
        })
    }

    pub(crate) fn remove(&mut self, binding: &PreCommitRuntimeBinding) -> io::Result<()> {
        self.ensure_current_authority(binding)?;
        fs::remove_file(self.record_path(&binding.record.lifecycle_id)?)?;
        sync_directory(&self.directory)?;
        self.records.remove(&binding.record.lifecycle_id);
        Ok(())
    }

    pub(crate) fn startup_quarantined(&self) -> bool {
        self.startup_quarantined
    }

    pub(crate) fn seat_startup_quarantined(&self, seat: &str) -> bool {
        self.startup_quarantined_seats.contains(seat)
    }

    pub(super) fn remove_record_by_id(&mut self, lifecycle_id: &str) -> io::Result<()> {
        fs::remove_file(self.record_path(lifecycle_id)?)?;
        sync_directory(&self.directory)?;
        self.records.remove(lifecycle_id);
        Ok(())
    }

    pub(super) fn record_path(&self, lifecycle_id: &str) -> io::Result<PathBuf> {
        validate_lifecycle_id(lifecycle_id)?;
        Ok(self.directory.join(format!("{lifecycle_id}.json")))
    }

    pub(super) fn commit(&mut self, record: PreCommitRuntimeRecord) -> io::Result<()> {
        validate_record(&record)?;
        let path = self.record_path(&record.lifecycle_id)?;
        let tmp = filesystem::temporary_record_path(&self.directory, &record.lifecycle_id);
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_PRECOMMIT_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "precommit runtime record too large",
            ));
        }
        let mut file = filesystem::open_temporary_record(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &path)?;
        sync_directory(&self.directory)?;
        self.records.insert(record.lifecycle_id.clone(), record);
        Ok(())
    }

    fn update(
        &mut self,
        binding: PreCommitRuntimeBinding,
        mut apply: impl FnMut(&mut PreCommitRuntimeRecord),
    ) -> io::Result<PreCommitRuntimeBinding> {
        self.ensure_current_authority(&binding)?;
        let mut current = self
            .records
            .get(&binding.record.lifecycle_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "precommit runtime record"))?;
        current.sequence = current.sequence.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "precommit sequence overflow")
        })?;
        apply(&mut current);
        self.commit(current.clone())?;
        Ok(PreCommitRuntimeBinding {
            authority: self.binding_for(&current)?,
            record: current,
        })
    }

    fn binding_for(
        &self,
        record: &PreCommitRuntimeRecord,
    ) -> io::Result<PreCommitRuntimeAuthority> {
        let metadata = fs::symlink_metadata(self.record_path(&record.lifecycle_id)?)?;
        Ok(PreCommitRuntimeAuthority {
            lifecycle_id: record.lifecycle_id.clone(),
            seat_generation: record.seat_generation,
            boot_id: record.boot_id.clone(),
            sequence: record.sequence,
            file: PreCommitRecordFileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                links: metadata.nlink(),
            },
        })
    }

    fn ensure_current_authority(&self, binding: &PreCommitRuntimeBinding) -> io::Result<()> {
        let current = self
            .records
            .get(&binding.record.lifecycle_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "precommit runtime record"))?;
        if current.sequence != binding.authority.sequence
            || current.seat_generation != binding.authority.seat_generation
            || current.boot_id != binding.authority.boot_id
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "precommit runtime authority mismatch",
            ));
        }
        let metadata = fs::symlink_metadata(self.record_path(&binding.record.lifecycle_id)?)?;
        if metadata.dev() != binding.authority.file.device
            || metadata.ino() != binding.authority.file.inode
            || metadata.nlink() != binding.authority.file.links
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "precommit runtime file identity changed",
            ));
        }
        Ok(())
    }
}
