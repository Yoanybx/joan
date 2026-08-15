//! End-to-end process isolation, parity and failure-state tests.

use joan_bytecode::Value;
use joan_compiler::compile_source;
use joan_host::{
    HostExecutionReason, HostExecutionStatus, HostLimits, HostOperation, execute_with_path,
};
use joan_native::compile_bytecode;
use std::fs;
use std::path::{Path, PathBuf};
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
    assert_eq!(compile.status, HostExecutionStatus::Completed);
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
    assert_eq!(receipt.status, HostExecutionStatus::Failed);
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
    assert_eq!(hanging_receipt.reason, HostExecutionReason::Timeout);

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
