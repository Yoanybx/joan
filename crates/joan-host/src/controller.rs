//! Parent-side process lifecycle. The controller does not link the native backend.

use crate::{
    ExecutorResponseStatus, HostError, HostExecutionReason, HostExecutionReceipt,
    HostExecutionStatus, HostLimits, HostOperation, MAX_HOST_RESPONSE_FRAME_BYTES,
    decode_response_frame, encode_request_frame, make_host_receipt, read_bounded,
    validate_bound_response,
};
use joan_bytecode::BytecodeProgram;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(2);
const PIPE_SETTLE_LIMIT: Duration = Duration::from_millis(250);

/// Resolve and verify the dedicated executor beside the current binary.
pub fn ensure_sibling_executor() -> Result<PathBuf, HostError> {
    let current = std::env::current_exe()?;
    let name = if cfg!(windows) {
        "joan-executor.exe"
    } else {
        "joan-executor"
    };
    let path = current
        .parent()
        .ok_or_else(|| HostError::InvalidRequest("current executable has no parent".to_owned()))?
        .join(name);
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
        HostError::InvalidRequest(format!("JOAN executor is unavailable: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HostError::InvalidRequest(
            "JOAN executor path is not a regular non-symlink file".to_owned(),
        ));
    }
    Ok(path)
}

/// Execute using the dedicated executor installed beside the current binary.
pub fn execute_sibling(
    bytecode: &BytecodeProgram,
    operation: HostOperation,
    limits: HostLimits,
) -> Result<HostExecutionReceipt, HostError> {
    let path = ensure_sibling_executor()?;
    execute_with_path(&path, bytecode, operation, limits)
}

/// Execute using an explicit child path, primarily for hermetic tests and launchers.
#[allow(
    clippy::too_many_lines,
    reason = "the linear lifecycle keeps every child-state transition auditable in one place"
)]
pub fn execute_with_path(
    executor_path: &Path,
    bytecode: &BytecodeProgram,
    operation: HostOperation,
    limits: HostLimits,
) -> Result<HostExecutionReceipt, HostError> {
    let (request, frame) = encode_request_frame(bytecode, operation)?;
    let mut command = Command::new(executor_path);
    command
        .env_clear()
        .current_dir(Path::new("/"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let Ok(mut child) = command.spawn() else {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Failed,
            HostExecutionReason::SpawnFailed,
            None,
            None,
            None,
        );
    };

    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::RequestWriteFailed,
            None,
            None,
            None,
        );
    };
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::OutputReadFailed,
            None,
            None,
            None,
        );
    };

    let (write_sender, write_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = stdin.write_all(&frame).and_then(|()| stdin.flush());
        drop(stdin);
        let _ = write_sender.send(result);
    });

    let (read_sender, read_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = read_bounded(&mut stdout, MAX_HOST_RESPONSE_FRAME_BYTES);
        let _ = read_sender.send(result);
    });

    let deadline = Instant::now() + Duration::from_millis(limits.wall_time_ms());
    let (status, timed_out, wait_failed) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false, false),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                let _ = child.kill();
                break (child.wait().ok(), true, false);
            }
            Err(_) => {
                let _ = child.kill();
                let waited = child.wait().ok();
                break (waited, false, true);
            }
        }
    };

    let exit_code = status.as_ref().and_then(ExitStatus::code);
    if timed_out {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::Timeout,
            exit_code,
            None,
            None,
        );
    }
    if wait_failed {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::ProcessWaitFailed,
            exit_code,
            None,
            None,
        );
    }
    let write_result = write_receiver.recv_timeout(PIPE_SETTLE_LIMIT);
    if !matches!(write_result, Ok(Ok(()))) {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::RequestWriteFailed,
            exit_code,
            None,
            None,
        );
    }
    let Ok(read_result) = read_receiver.recv_timeout(PIPE_SETTLE_LIMIT) else {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::OutputReadFailed,
            exit_code,
            None,
            None,
        );
    };
    let Ok((output, oversized)) = read_result else {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::OutputReadFailed,
            exit_code,
            None,
            None,
        );
    };
    if oversized {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::OutputLimitExceeded,
            exit_code,
            None,
            None,
        );
    }
    if status.as_ref().is_none_or(|value| !value.success()) {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::ChildExitUnknown,
            exit_code,
            None,
            None,
        );
    }
    let Ok(response) = decode_response_frame(&output) else {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::MalformedResponse,
            exit_code,
            None,
            None,
        );
    };
    if validate_bound_response(&request, &response).is_err() {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::BindingMismatch,
            exit_code,
            None,
            None,
        );
    }
    match response.status {
        ExecutorResponseStatus::Completed => make_host_receipt(
            &request,
            HostExecutionStatus::Completed,
            HostExecutionReason::ExecutorCompleted,
            exit_code,
            Some(&response),
            None,
        ),
        ExecutorResponseStatus::Failed => {
            let detail = response.failure_message.clone();
            make_host_receipt(
                &request,
                HostExecutionStatus::Failed,
                HostExecutionReason::ExecutorRejected,
                exit_code,
                Some(&response),
                detail,
            )
        }
    }
}
