//! End-to-end process isolation, parity and failure-state tests.

use joan_bytecode::Value;
use joan_compiler::compile_source;
use joan_host::{
    HostExecutionReason, HostExecutionStatus, HostLimits, HostOperation, execute_with_path,
};
use joan_native::compile_bytecode;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

const PURE: &str = r"module host_process;
fn score(left: i64, right: i64) -> i64 effects [] {
  return left * right;
}
fn main() -> i64 effects [] {
  return 0;
}
";

fn executor() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_joan-executor"))
}

#[test]
fn sidecar_matches_in_process_native_receipts() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE)?;
    let direct = compile_bytecode(&artifact.bytecode)?;

    let compile = execute_with_path(
        &executor(),
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::default(),
    )?;
    assert_eq!(
        compile.status,
        HostExecutionStatus::Completed,
        "{compile:#?}"
    );
    assert_eq!(compile.reason, HostExecutionReason::ExecutorCompleted);
    assert_eq!(compile.compile_receipt.as_ref(), Some(direct.receipt()));

    let arguments = vec![Value::I64(6), Value::I64(7)];
    let expected = direct.invoke("score", &arguments, 100)?;
    let run = execute_with_path(
        &executor(),
        &artifact.bytecode,
        HostOperation::Run {
            function: "score".to_owned(),
            arguments,
            instruction_budget: 100,
        },
        HostLimits::default(),
    )?;
    assert_eq!(run.status, HostExecutionStatus::Completed);
    assert_eq!(run.execution_receipt, Some(expected));
    Ok(())
}

#[test]
fn deterministic_native_rejections_are_failed_not_completed()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE)?;
    let receipt = execute_with_path(
        &executor(),
        &artifact.bytecode,
        HostOperation::Run {
            function: "score".to_owned(),
            arguments: vec![Value::I64(6), Value::I64(7)],
            instruction_budget: 1,
        },
        HostLimits::default(),
    )?;
    assert_eq!(receipt.status, HostExecutionStatus::Failed, "{receipt:#?}");
    assert_eq!(receipt.reason, HostExecutionReason::ExecutorRejected);
    assert!(
        receipt
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("instruction budget exhausted"))
    );
    assert!(receipt.execution_receipt.is_none());

    let effectful = compile_source(
        r#"module effectful_host;
fn main() -> unit effects [network_send] {
  request network_send("blocked");
  return;
}
"#,
    )?;
    let rejected = execute_with_path(
        &executor(),
        &effectful.bytecode,
        HostOperation::Compile,
        HostLimits::default(),
    )?;
    assert_eq!(rejected.status, HostExecutionStatus::Failed);
    assert!(rejected.compile_receipt.is_none());
    Ok(())
}

#[cfg(unix)]
#[test]
fn timeout_malformed_output_flood_and_spawn_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let artifact = compile_source(PURE)?;
    let directory = tempdir()?;

    let timeout = executable_script(directory.path(), "timeout.sh", "exec /bin/sleep 2")?;
    let timed_out = execute_with_path(
        &timeout,
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::new(25)?,
    )?;
    assert_eq!(timed_out.status, HostExecutionStatus::Unknown);
    assert_eq!(timed_out.reason, HostExecutionReason::Timeout);

    let malformed = executable_script(
        directory.path(),
        "malformed.sh",
        "/bin/cat >/dev/null\nif /usr/bin/env | /usr/bin/grep -Eq '^(HOME|USER|PATH|TMPDIR|CARGO_HOME|RUSTUP_HOME)='; then exit 9; fi\nprintf x",
    )?;
    let malformed_receipt = execute_with_path(
        &malformed,
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::default(),
    )?;
    assert_eq!(malformed_receipt.status, HostExecutionStatus::Unknown);
    assert_eq!(
        malformed_receipt.reason,
        HostExecutionReason::MalformedResponse
    );

    let flood = executable_script(
        directory.path(),
        "flood.sh",
        "/bin/cat >/dev/null\nwhile :; do printf '0123456789abcdef'; done",
    )?;
    let flooded = execute_with_path(
        &flood,
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::default(),
    )?;
    assert_eq!(flooded.status, HostExecutionStatus::Unknown);
    assert_eq!(flooded.reason, HostExecutionReason::OutputLimitExceeded);

    let executor_command = shell_quote(&executor());
    let nonzero = executable_script(
        directory.path(),
        "valid-then-nonzero.sh",
        &format!("{executor_command}\nexit 7"),
    )?;
    let nonzero_receipt = execute_with_path(
        &nonzero,
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::default(),
    )?;
    assert_eq!(nonzero_receipt.status, HostExecutionStatus::Unknown);
    assert_eq!(
        nonzero_receipt.reason,
        HostExecutionReason::ChildExitUnknown
    );

    let hanging = executable_script(
        directory.path(),
        "valid-then-hang.sh",
        &format!("{executor_command}\nexec /bin/sleep 2"),
    )?;
    let hanging_receipt = execute_with_path(
        &hanging,
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::new(250)?,
    )?;
    assert_eq!(hanging_receipt.status, HostExecutionStatus::Unknown);
    assert_eq!(
        hanging_receipt.reason,
        HostExecutionReason::Timeout,
        "{hanging_receipt:#?}"
    );

    let absent = execute_with_path(
        &directory.path().join("absent"),
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::default(),
    )?;
    assert_eq!(absent.status, HostExecutionStatus::Failed);
    assert_eq!(absent.reason, HostExecutionReason::SpawnFailed);
    Ok(())
}

#[cfg(unix)]
#[test]
fn timeout_kills_child_and_grandchild_process_group() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE)?;
    let directory = tempdir()?;
    let descendant_pid = directory.path().join("descendant.pid");
    let descendant_pid_quoted = shell_quote(&descendant_pid);
    let script = executable_script(
        directory.path(),
        "descendant-timeout.sh",
        &format!(
            "/bin/sleep 30 &\ndescendant=$!\nprintf '%s' \"$descendant\" > {descendant_pid_quoted}\nexec /bin/sleep 30"
        ),
    )?;

    let receipt = execute_with_path(
        &script,
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::new(5_000)?,
    )?;
    assert_eq!(receipt.status, HostExecutionStatus::Unknown);
    assert_eq!(receipt.reason, HostExecutionReason::Timeout);
    assert!(receipt.child_exit_code.is_none());
    assert!(receipt.child_unix_signal.is_some());

    let pid = read_recorded_pid(&descendant_pid)?;
    assert_process_gone(pid)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn terminated_leader_with_live_descendant_is_never_completed()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE)?;
    let directory = tempdir()?;
    let descendant_pid = directory.path().join("retained-stdout.pid");
    let descendant_pid_quoted = shell_quote(&descendant_pid);
    let script = executable_script(
        directory.path(),
        "leader-exit.sh",
        &format!(
            "/bin/cat >/dev/null\n/bin/sleep 30 &\ndescendant=$!\nprintf '%s' \"$descendant\" > {descendant_pid_quoted}\nkill -TERM $$"
        ),
    )?;

    let receipt = execute_with_path(
        &script,
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::new(5_000)?,
    )?;
    assert_eq!(receipt.status, HostExecutionStatus::Unknown);
    assert_eq!(
        receipt.reason,
        HostExecutionReason::DescendantDetected,
        "{receipt:#?}"
    );

    let pid = read_recorded_pid(&descendant_pid)?;
    assert_process_gone(pid)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn unix_signal_is_distinct_from_exit_code_and_receipt_is_deterministic()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE)?;
    let directory = tempdir()?;
    let script = executable_script(
        directory.path(),
        "signal.sh",
        "/bin/cat >/dev/null\nkill -TERM $$",
    )?;

    let first = execute_with_path(
        &script,
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::default(),
    )?;
    let second = execute_with_path(
        &script,
        &artifact.bytecode,
        HostOperation::Compile,
        HostLimits::default(),
    )?;
    assert_eq!(first.status, HostExecutionStatus::Unknown);
    assert_eq!(first.reason, HostExecutionReason::ChildExitUnknown);
    assert_eq!(first.child_exit_code, None);
    assert_eq!(first.child_unix_signal, Some(15));
    assert_eq!(first, second);
    Ok(())
}

#[cfg(unix)]
#[test]
fn repeated_timeouts_do_not_deadlock_the_controller() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE)?;
    let directory = tempdir()?;
    let script = executable_script(directory.path(), "spin.sh", "while :; do :; done")?;

    for iteration in 0..100 {
        let receipt = execute_with_path(
            &script,
            &artifact.bytecode,
            HostOperation::Compile,
            HostLimits::new(5)?,
        )?;
        assert_eq!(
            receipt.reason,
            HostExecutionReason::Timeout,
            "iteration {iteration}: {receipt:#?}"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn executable_script(
    directory: &Path,
    name: &str,
    body: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let path = directory.join(name);
    fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n"))?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

#[cfg(unix)]
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

#[cfg(unix)]
fn read_recorded_pid(path: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(fs::read_to_string(path)?.trim().parse()?)
}

#[cfg(unix)]
fn assert_process_gone(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if !Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()?
            .success()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(format!("descendant process {pid} remained alive").into())
}
