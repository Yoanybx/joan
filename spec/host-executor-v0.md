# JOAN Host Executor v0

## Scope

H01A moves the experimental pure Cranelift backend out of the `joan` process.
The controller retains source, task context and future authority. The dedicated
`joan-executor` process receives one bounded request, emits one bounded response
and exits. It accepts no JOAN effects or capability handles.

This is process separation, not a complete operating-system sandbox. Kernel
syscall policy, RSS/CPU enforcement, seccomp/namespaces/cgroups and the macOS
equivalent remain H08 work.

## Dependency boundary

- `joan-host` owns protocol types, framing and child lifecycle. It does not
  depend on `joan-native` or Cranelift.
- `joan-executor` is the only official binary that links `joan-native`.
- `joan-node` invokes the sibling executor by absolute path and does not search
  `PATH`.

The low-level `joan-native` library remains available for tests and embedders,
but it is explicitly not a sandbox.

## IPC

Each attempt uses fresh anonymous stdin/stdout pipes and one child. The parent
clears the inherited environment, sets `/` as the working directory, pipes
stdin/stdout and discards stderr. It sends no command arguments.

The request is one complete Lattice v0 frame of at most 2 MiB:

- L1 Shape: exact canonical JCE1 `joan.host-execution-request.v0`;
- L4 Evidence: exact canonical verified JOAN bytecode;
- all other levels empty;
- `receipt-required` is mandatory.

The response is one complete Lattice v0 frame of at most 256 KiB. Only L5
Result is populated with exact canonical JCE1
`joan.host-executor-response.v0`. Extra bytes, duplicate frames, unsupported
levels, noncanonical JSON, unknown fields, digest mismatch, truncation and
oversize fail closed.

SHA-256 transport digests bind the exact schema identifier and canonical level
bytes. Typed JCE1 identities separately bind request, response and parent
receipt under registered domains.

## Result state

`completed` requires exit code zero, one canonical response and exact request,
semantic, bytecode, native artifact and function bindings. A deterministic
backend rejection is `failed`. Spawn failure is also `failed` because no child
started.

Timeout, request-write uncertainty, signal/nonzero exit, read failure,
oversized output, malformed response or binding mismatch is `unknown`. The
controller never retries automatically and never converts `unknown` into an
effect, payment, settlement or success.

## Limits

- one child per attempt;
- 30 second default and 60 second hard wall-time maximum;
- 64 arguments and 1,000,000,000 maximum JOAN instruction budget;
- existing bytecode and native limits remain mandatory;
- 2 MiB request and 256 KiB response hard bounds;
- child failure diagnostics are truncated at a UTF-8 boundary to 1,024 bytes.

Fuel, input, output, code and wall-time are enforced here. RSS and operating
system CPU quotas remain partial until H08.

## Compatibility

On success, `joan native compile` and `joan native run` emit the existing
native receipt schemas unchanged. On failure they emit the new host receipt to
stdout and return nonzero, preserving the previous stderr failure behavior
while making ambiguity machine-readable.

Replay within one child is rejected because exactly one complete frame is read
to EOF. Durable replay prevention across separate attempts remains open until
capability handles and a transactional consumption ledger exist. No effects,
network listeners, secrets or payments are enabled by this protocol.
