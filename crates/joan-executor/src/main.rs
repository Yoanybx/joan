//! Dedicated one-shot native executor for the JOAN host protocol.

use joan_host::{
    ExecutorFailureCode, HostError, HostOperation, MAX_HOST_REQUEST_FRAME_BYTES,
    completed_compile_response, completed_run_response, decode_request_frame,
    encode_response_frame, failed_executor_response, read_bounded,
};
use joan_native::{NativeError, compile_bytecode};
use std::io::{self, Write as _};

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == ["--self-check"] {
        println!(
            "{{\"profile\":\"pure-native-v0\",\"schema\":\"joan.executor-self-check.v0\",\"status\":\"ready\"}}"
        );
        return;
    }
    if !arguments.is_empty() {
        let _ = writeln!(io::stderr(), "joan-executor: unsupported arguments");
        std::process::exit(2);
    }
    if let Err(error) = run_one() {
        let _ = writeln!(io::stderr(), "joan-executor: {error}");
        std::process::exit(2);
    }
}

fn run_one() -> Result<(), HostError> {
    let (input, oversized) = read_bounded(&mut io::stdin().lock(), MAX_HOST_REQUEST_FRAME_BYTES)?;
    if oversized {
        return Err(HostError::InvalidRequest(format!(
            "request exceeds {MAX_HOST_REQUEST_FRAME_BYTES} bytes"
        )));
    }
    let request = decode_request_frame(&input)?;
    let native = match compile_bytecode(&request.bytecode) {
        Ok(native) => native,
        Err(error) => {
            let (code, message) = classify_native_error(&error);
            let response = failed_executor_response(&request.control, None, code, &message)?;
            return write_response(&response);
        }
    };
    let compile_receipt = native.receipt().clone();
    let response = match &request.control.operation {
        HostOperation::Compile => completed_compile_response(&request.control, compile_receipt)?,
        HostOperation::Run {
            function,
            arguments,
            instruction_budget,
        } => match native.invoke(function, arguments, *instruction_budget) {
            Ok(execution) => completed_run_response(&request.control, compile_receipt, execution)?,
            Err(error) => {
                let (code, message) = classify_native_error(&error);
                failed_executor_response(&request.control, Some(compile_receipt), code, &message)?
            }
        },
    };
    write_response(&response)
}

fn write_response(response: &joan_host::ExecutorResponse) -> Result<(), HostError> {
    let frame = encode_response_frame(response)?;
    let mut output = io::stdout().lock();
    output.write_all(&frame)?;
    output.flush()?;
    Ok(())
}

fn classify_native_error(error: &NativeError) -> (ExecutorFailureCode, String) {
    let code = match error {
        NativeError::Bytecode(_) => ExecutorFailureCode::BytecodeRejected,
        NativeError::Unsupported(_) => ExecutorFailureCode::UnsupportedNativeSubset,
        NativeError::ResourceLimit(_) => ExecutorFailureCode::ResourceLimit,
        NativeError::Codegen(_) => ExecutorFailureCode::CodegenFailed,
        NativeError::Identity(_) => ExecutorFailureCode::IdentityFailed,
        NativeError::Runtime(message) if message.contains("instruction budget exhausted") => {
            ExecutorFailureCode::InstructionBudgetExhausted
        }
        NativeError::Runtime(_) => ExecutorFailureCode::RuntimeFailed,
    };
    (code, error.to_string())
}
