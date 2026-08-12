# JOAN Linear One-Shot Authority v1

## Status

This document freezes the first executable linear-authority profile. It adds
effect-specific authority slots to JOAN source, canonical identity, verified
bytecode, VM receipts and external effect planning. It does not grant host
authority or execute an effect.

## Source contract

```joan
fn main() -> unit effects [network_send]
  authorities [send_once: network_send] {
  request network_send("agent-b") using send_once;
  return;
}
```

`authorities [slot: effect]` declares a per-invocation external requirement.
`using slot` is a move, not a copy or grant. In the linear profile:

`authorities` and `using` are contextual words, not globally reserved
identifiers, so legacy parameters and locals with those names remain valid.

- every function, including pure functions, declares `authorities [...]`;
- every request moves exactly one declared slot;
- each slot names one effect in the function's effect row;
- each slot is moved exactly once in the function body;
- missing, unknown, wrong-effect, reused or unconsumed slots reject the module;
- legacy and linear functions cannot be mixed in one module.

The current language has no conditionals, loops or recursion. Exact once-use is
therefore checked over the only straight-line body path. Each call creates a new
invocation of the callee's declared slots; ordinary parameters cannot yet carry,
return, split or delegate authority.

## Identity and bytecode

Legacy source continues to use:

- `joan.canonical-ast.v0`;
- `joan.canonical-ast-identity.v0`;
- digest domain `joan.language-canonical-ast.v1`;
- `joan.bytecode-program.v1` and digest domain of the same name.

Linear source uses separate, non-interchangeable profiles:

- `joan.canonical-ast.v1`;
- `joan.canonical-ast-identity.v1`;
- digest domain `joan.language-canonical-ast.v2`;
- `joan.bytecode-program.v2` and digest domain of the same name.

The bytecode verifier independently emits the authority table and request-slot
bindings from the canonical AST. It also abstractly consumes every slot and
rejects reuse or omission before execution. Schema pairs cannot be mixed.

## Runtime binding

The VM performs no I/O. A linear request receipt contains the exact source slot
and a typed ID over program identity, sequence, function, effect, slot and
evaluated arguments. `joan-runtime` requires one external approval whose task,
nonce, capability and slot all match. It validates the complete
legacy/linear receipt profile before planning, validates every request before
mutating state, and commits all approval nonces atomically only after the plan
receipt is built.

Runtime receipt validation prevents removing a slot, changing request payload or
order, or relabeling a linear receipt as legacy between the VM and the host.
Durable, multi-process replay
prevention remains the host's responsibility; the current ledger is in-process
and no real effect executor is enabled.

## Security boundary

Repository text, generated code and model output cannot mint a slot's external
approval. Static acceptance proves only that authority requirements are explicit
and consumed according to this bounded profile. It does not prove that the
compiler, verifier or host has no defects, and it does not make JOAN unhackable.

## Deferred work

- linear authority parameters and return values across calls;
- attenuation, borrowing and explicit delegation;
- control-flow joins and path-sensitive ownership checking;
- durable transactional approval storage;
- signed remote authority proofs and revocation;
- an executor boundary with idempotency and recovery.
