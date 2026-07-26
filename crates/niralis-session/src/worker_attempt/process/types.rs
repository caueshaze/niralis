use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, ChildStdout, ExitStatus};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::{
    worker_io::{read_envelope, write_envelope},
    SessionError, WorkerEnvelope, WorkerRequest, WorkerResponse,
};

pub(crate) struct WorkerAttempt {
    child: Arc<Mutex<Child>>,
    retained_by_supervisor: bool,
    supervisor_channel: Option<UnixStream>,
    fixture_supervisor_transport: Option<FixtureSupervisorTransportHandle>,
    writer: Option<JoinHandle<()>>,
    writer_rx: Receiver<Result<(), SessionError>>,
    reader: Option<JoinHandle<()>>,
    reader_rx: Receiver<Result<WorkerEnvelope<WorkerResponse>, SessionError>>,
}

#[derive(Debug)]
pub(crate) struct FixtureSupervisorTransportHandle {
    reader: File,
    writer: File,
}

impl FixtureSupervisorTransportHandle {
    pub(crate) fn send_request(
        &mut self,
        request: crate::WorkerControlRequest,
    ) -> Result<(), SessionError> {
        crate::write_control_request(&mut self.writer, request)
    }

    pub(crate) fn read_request(
        &mut self,
    ) -> Result<crate::WorkerEnvelope<crate::WorkerControlRequest>, SessionError> {
        crate::read_control_request(&mut self.reader)
    }
}

impl WorkerAttempt {
    pub(crate) fn child_id(&self) -> u32 {
        self.child.lock().expect("worker child lock").id()
    }

    pub(crate) fn is_alive(&mut self) -> Result<bool, SessionError> {
        Ok(self
            .child
            .lock()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .try_wait()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .is_none())
    }

    pub(crate) fn shared_child(&self) -> Arc<Mutex<Child>> {
        Arc::clone(&self.child)
    }

    pub(crate) fn retain_by_supervisor(&mut self) {
        self.retained_by_supervisor = true;
    }

    pub(crate) fn take_supervisor_channel(&mut self) -> UnixStream {
        self.supervisor_channel
            .take()
            .expect("worker supervisor channel ownership exists")
    }

    #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    pub(crate) fn take_fixture_supervisor_transport(
        &mut self,
    ) -> Option<FixtureSupervisorTransportHandle> {
        self.fixture_supervisor_transport.take()
    }

    pub(crate) fn send_supervisor_control_request(
        &mut self,
        request: crate::WorkerControlRequest,
    ) -> Result<(), SessionError> {
        if let Some(transport) = self.fixture_supervisor_transport.as_mut() {
            return transport.send_request(request);
        }
        crate::write_control_request(
            self.supervisor_channel
                .as_mut()
                .expect("worker supervisor channel exists"),
            request,
        )
    }

    pub(crate) fn read_supervisor_control_request(
        &mut self,
    ) -> Result<crate::WorkerEnvelope<crate::WorkerControlRequest>, SessionError> {
        if let Some(transport) = self.fixture_supervisor_transport.as_mut() {
            return transport.read_request();
        }
        crate::read_control_request(
            self.supervisor_channel
                .as_mut()
                .expect("worker supervisor channel exists"),
        )
    }

    pub(crate) fn spawn(
        worker_path: &Path,
        worker_environment: &[(String, String)],
        request: WorkerRequest,
        fixture_supervisor_transport: bool,
    ) -> Result<Self, SessionError> {
        let (mut child, supervisor_channel, fixture_transport) = spawn_worker(
            worker_path,
            worker_environment,
            fixture_supervisor_transport,
        )?;
        let stdin = child.stdin.take().ok_or(SessionError::WorkerIoFailed)?;
        let stdout = child.stdout.take().ok_or(SessionError::WorkerIoFailed)?;
        let (writer, writer_rx) = spawn_writer(stdin, request);
        let (reader, reader_rx) = spawn_reader(stdout);

        Ok(Self {
            child: Arc::new(Mutex::new(child)),
            retained_by_supervisor: false,
            supervisor_channel: Some(supervisor_channel),
            fixture_supervisor_transport: fixture_transport,
            writer: Some(writer),
            writer_rx,
            reader: Some(reader),
            reader_rx,
        })
    }

    pub(crate) fn wait_writer(&mut self, deadline: Instant) -> Result<(), SessionError> {
        wait_thread_result(&self.writer_rx, deadline, &self.child)
    }

    pub(crate) fn wait_reader(
        &mut self,
        deadline: Instant,
    ) -> Result<WorkerEnvelope<WorkerResponse>, SessionError> {
        wait_thread_result(&self.reader_rx, deadline, &self.child)
    }

    pub(crate) fn wait_child(&mut self, deadline: Instant) -> Result<Option<ExitStatus>, SessionError> {
        wait_for_exit(&self.child, deadline).map(Some)
    }

    pub(crate) fn kill_and_reap(&mut self) {
        kill_and_reap(&self.child);
    }

    pub(crate) fn finish(&mut self) {
        if let Some(handle) = self.writer.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for WorkerAttempt {
    fn drop(&mut self) {
        if !self.retained_by_supervisor {
            self.kill_and_reap();
        }
        self.finish();
    }
}
