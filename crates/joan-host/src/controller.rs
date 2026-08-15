//! Parent-side process lifecycle. The controller does not link the native backend.

use crate::{
    ExecutorResponseStatus, HostError, HostExecutionReason, HostExecutionReceipt,
    HostExecutionStatus, HostLimits, HostOperation, MAX_HOST_RESPONSE_FRAME_BYTES,
    decode_response_frame, encode_request_frame_with_limits, make_host_receipt,
    validate_bound_response,
};
use joan_bytecode::BytecodeProgram;
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

const POLL_INTERVAL: Duration = Duration::from_millis(2);
const POST_EXIT_GROUP_GRACE: Duration = Duration::from_millis(10);
const PIPE_BUFFER_BYTES: usize = 16 * 1_024;

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
    let (request, frame) = encode_request_frame_with_limits(bytecode, operation, limits)?;
    let mut command = Command::new(executor_path);
    command
        .env_clear()
        .current_dir(Path::new("/"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    configure_process_group(&mut command);
    let Ok(mut child) = command.spawn() else {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Failed,
            HostExecutionReason::SpawnFailed,
            None,
            None,
            None,
            None,
        );
    };
    let process_group_id = child.id();

    let Some(stdin) = child.stdin.take() else {
        let status = terminate_process_tree(&mut child, process_group_id);
        let (exit_code, unix_signal) = exit_parts(status.as_ref());
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::RequestWriteFailed,
            exit_code,
            unix_signal,
            None,
            None,
        );
    };
    let Some(mut stdout) = child.stdout.take() else {
        let status = terminate_process_tree(&mut child, process_group_id);
        let (exit_code, unix_signal) = exit_parts(status.as_ref());
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::OutputReadFailed,
            exit_code,
            unix_signal,
            None,
            None,
        );
    };

    if set_nonblocking(&stdin).is_err() || set_nonblocking(&stdout).is_err() {
        drop(stdin);
        drop(stdout);
        let status = terminate_process_tree(&mut child, process_group_id);
        let (exit_code, unix_signal) = exit_parts(status.as_ref());
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::ProcessWaitFailed,
            exit_code,
            unix_signal,
            None,
            None,
        );
    }

    let mut stdin = Some(stdin);
    let deadline = Instant::now() + Duration::from_millis(limits.wall_time_ms());
    let mut input_offset = 0;
    let mut input_closed = false;
    let mut output = Vec::new();
    let mut output_eof = false;
    let mut status = None;
    let mut leader_exit_observed_at = None;
    let mut forced_reason = None;

    while forced_reason.is_none() {
        if !input_closed {
            let mut close_input = false;
            if let Some(input) = stdin.as_mut() {
                match input.write(&frame[input_offset..]) {
                    Ok(0) => forced_reason = Some(HostExecutionReason::RequestWriteFailed),
                    Ok(written) => {
                        input_offset += written;
                        if input_offset == frame.len() {
                            if input.flush().is_err() {
                                forced_reason = Some(HostExecutionReason::RequestWriteFailed);
                            } else {
                                close_input = true;
                            }
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => forced_reason = Some(HostExecutionReason::RequestWriteFailed),
                }
            } else {
                forced_reason = Some(HostExecutionReason::RequestWriteFailed);
            }
            if close_input {
                input_closed = true;
                stdin.take();
            }
        }

        if !output_eof {
            let mut buffer = [0_u8; PIPE_BUFFER_BYTES];
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => {
                        output_eof = true;
                        break;
                    }
                    Ok(read) => {
                        output.extend_from_slice(&buffer[..read]);
                        if output.len() > MAX_HOST_RESPONSE_FRAME_BYTES {
                            forced_reason = Some(HostExecutionReason::OutputLimitExceeded);
                            break;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => {
                        forced_reason = Some(HostExecutionReason::OutputReadFailed);
                        break;
                    }
                }
            }
        }

        if status.is_none() {
            match child.try_wait() {
                Ok(Some(child_status)) => {
                    status = Some(child_status);
                    leader_exit_observed_at = Some(Instant::now());
                }
                Ok(None) => {}
                Err(_) => forced_reason = Some(HostExecutionReason::ProcessWaitFailed),
            }
        }

        if let Some(exit_observed_at) = leader_exit_observed_at
            && exit_observed_at.elapsed() >= POST_EXIT_GROUP_GRACE
        {
            match terminate_remaining_group(process_group_id) {
                Ok(true) => forced_reason = Some(HostExecutionReason::DescendantDetected),
                Ok(false) if output_eof => break,
                Ok(false) => forced_reason = Some(HostExecutionReason::OutputReadFailed),
                Err(_) => forced_reason = Some(HostExecutionReason::ProcessWaitFailed),
            }
        }
        if Instant::now() >= deadline {
            forced_reason = Some(HostExecutionReason::Timeout);
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    drop(stdin);
    drop(stdout);
    if forced_reason.is_some() && status.is_none() {
        status = terminate_process_tree(&mut child, process_group_id);
    } else {
        let _ = terminate_remaining_group(process_group_id);
    }

    let (exit_code, unix_signal) = exit_parts(status.as_ref());
    if let Some(reason) = forced_reason {
        return make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            reason,
            exit_code,
            unix_signal,
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
            unix_signal,
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
            unix_signal,
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
            unix_signal,
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
            unix_signal,
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
                unix_signal,
                Some(&response),
                detail,
            )
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn set_nonblocking<Fd: std::os::fd::AsFd>(fd: &Fd) -> Result<(), HostError> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

    let flags = fcntl_getfl(fd).map_err(|error| HostError::Io(error.into()))?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|error| HostError::Io(error.into()))
}

#[cfg(not(unix))]
fn set_nonblocking<Fd>(_fd: &Fd) -> Result<(), HostError> {
    Err(HostError::ResourceLimit(
        "bounded nonblocking host pipes are unavailable on this platform".to_owned(),
    ))
}

fn terminate_process_tree(child: &mut Child, process_group_id: u32) -> Option<ExitStatus> {
    let _ = terminate_remaining_group(process_group_id);
    let _ = child.kill();
    child.wait().ok()
}

#[cfg(unix)]
fn terminate_remaining_group(process_group_id: u32) -> Result<bool, HostError> {
    use rustix::process::{Pid, Signal, kill_process_group};

    let Ok(raw_pid) = i32::try_from(process_group_id) else {
        return Ok(false);
    };
    let Some(pid) = Pid::from_raw(raw_pid) else {
        return Ok(false);
    };
    match kill_process_group(pid, Signal::KILL) {
        Ok(()) => Ok(true),
        Err(error) if error == rustix::io::Errno::SRCH => Ok(false),
        Err(error) => Err(HostError::Io(error.into())),
    }
}

#[cfg(not(unix))]
fn terminate_remaining_group(_process_group_id: u32) -> Result<bool, HostError> {
    Ok(false)
}

fn exit_parts(status: Option<&ExitStatus>) -> (Option<i32>, Option<i32>) {
    let exit_code = status.and_then(ExitStatus::code);
    #[cfg(unix)]
    let unix_signal = status.and_then(std::os::unix::process::ExitStatusExt::signal);
    #[cfg(not(unix))]
    let unix_signal = None;
    (exit_code, unix_signal)
}
