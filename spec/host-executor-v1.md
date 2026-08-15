# JOAN Host Executor v1

## Scope

H04A/H05A hardens the one-shot native sidecar introduced by Host Executor v0.
The trusted `joan-node` process still owns source, authority and task context;
`joan-executor` receives one pure request, emits at most one bounded response
and exits. Effects, capability handles, listeners and payment operations remain
unavailable.

This is a process-lifecycle and POSIX-limit boundary, not a complete operating-
system sandbox. A descendant can escape a process group by creating another
session, and POSIX limits do not provide a portable RSS or OOM attribution
contract. H08 remains responsible for a kernel-enforced sandbox such as Linux
cgroups/namespaces/seccomp or a measured macOS equivalent.

## Versioning and identity

The immutable v0 schema files remain available for historical receipts. New
traffic uses:

- `joan.host-execution-request.v1`;
- `joan.host-executor-response.v1`;
- `joan.host-execution-receipt.v1`.

Their typed identities use the new domains
`joan.host-execution-request.v2`, `joan.host-executor-response.v2` and
`joan.host-execution-receipt.v2`. The domain version advances independently
because each digest now includes resource policy or process-signal state that
was absent from the v0 wire contract.

The request digest binds operation, semantic identity, bytecode identity and
the complete limit profile. The response binds the request digest. The parent
receipt binds the same limits, response identity when present, exit code or
Unix signal, but never both.

## Controller lifecycle

The parent starts the child in a fresh process group, clears its environment,
sets `/` as its working directory and exposes only anonymous stdin/stdout
pipes. Stderr is discarded. One nonblocking event loop writes the request,
drains at most 256 KiB of response and polls child state; no detached I/O
threads exist.

Timeout or protocol uncertainty sends `SIGKILL` to the process group and waits
for the leader. After the leader exits, the controller allows a 10 ms pipe and
kernel-state grace period. A remaining process-group member is killed and the
attempt becomes `unknown/descendant_detected`; it can never become completed.

`completed` still requires exit code zero and a canonical, fully bound child
response. A nonzero code or Unix signal is `unknown/child_exit_unknown` unless
another stronger lifecycle reason already applies. Signal 9 is not labeled as
OOM because POSIX process status cannot prove that cause.

## Resource profile

The child applies the request profile after strict frame and bytecode decoding
and before native compilation:

- wall time: 30 seconds default, 60 seconds maximum, enforced by the parent;
- CPU time: 10 seconds default, 30 seconds maximum; soft limit is the request
  value and hard limit is one second higher;
- open files: 64 default, bounded from 16 through 256;
- regular-file output: zero bytes by default, 1 MiB maximum;
- core dumps: always zero;
- process memory: 16 GiB virtual-address limit by default where `RLIMIT_AS`
  works.

macOS returns `EINVAL` for finite `RLIMIT_AS` and `RLIMIT_DATA` in the tested
environment. Its default profile therefore records
`memory_limit_kind=unavailable` and `memory_limit_bytes=0` instead of claiming
a limit that was not applied. This mode is rejected on non-Apple hosts so a
caller cannot downgrade Linux enforcement. Linux uses `address_space`;
callers may request `data_segment` on a supporting Unix host. The selected
primitive and byte value are part of request and receipt identity.

## Compatibility and limits

Successful CLI commands still emit the unchanged native compile/execution v0
receipts. Deterministic backend rejection emits a host receipt v1 and remains
`failed`; ambiguous process state remains `unknown`. No automatic retry turns
an unknown attempt into success.

The test corpus covers parity, malformed/truncated/oversized frames, output
floods, nonzero exit, Unix signal separation, 100 repeated timeouts, child and
grandchild cleanup, and leader termination with a live descendant. These tests
reduce lifecycle risk but do not establish zero bugs, production readiness or
a universal memory sandbox.
