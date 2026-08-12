# JOAN Tenant-Purpose Information Flow v1

## Status

This document freezes the first executable JOAN information-flow profile. It
adds explicit value and effect-sink labels to source, canonical identity,
verified bytecode, VM receipts and one-use approvals. It tracks explicit data
flow in the bounded language preview; it is not a general confidentiality proof.

## Source contract

An information-flow module is declared explicitly:

```joan
module secure flow;

fn main() -> unit flow [public] effects [network_send]
  authorities [send_once: network_send] {
  let payload: string flow [secret, tenant:agent_a, purpose:handoff] = "data";
  request network_send(payload) using send_once
    flow [secret, tenant:agent_a, purpose:handoff];
  return;
}
```

`flow` is contextual. Every parameter, return type, local and request sink in a
flow module must declare exactly one label:

- `flow [public]`;
- `flow [secret, tenant:<identifier>, purpose:<identifier>]`.

Flow modules also use the complete linear-authority profile: every function
declares `authorities [...]` and every request moves one matching slot.

## Algebra

The partial order is deliberately small:

- public information may flow to public or any secret destination;
- secret information may flow only to the exact same tenant and purpose;
- two expression labels join when equal or when one is public;
- two different secret labels have no join and reject the program.

Literals are public. Variables carry their declared labels. Unary operators
preserve labels. Binary operators join operand labels. Calls enforce argument
flow into parameter labels and return the callee's declared label. Locals,
returns and request arguments must flow into their declared destination labels.
There is no implicit or explicit declassification in this profile.

## Identity and bytecode

The profile uses non-interchangeable contracts:

- `joan.canonical-ast.v2`;
- `joan.canonical-ast-identity.v2`;
- digest domain `joan.language-canonical-ast.v3`;
- `joan.bytecode-program.v3` and digest domain of the same name;
- `joan.bytecode-verification-receipt.v2`;
- `joan.compile-artifact.v3` and `joan.execution-receipt.v3`.

The standalone verifier validates complete parameter, local and return label
tables, abstractly propagates labels over every instruction, checks calls,
stores, returns and request sinks, then independently emits bytecode from the
embedded canonical AST and requires exact equality. Profile/schema pairs cannot
be mixed.

## Runtime binding

The VM performs no I/O. A v3 request ID binds the semantic digest, request
sequence, function, effect, linear authority slot, information label and
evaluated arguments. `joan-runtime` accepts exactly one approval with the same
task, nonce, capability, slot and label. It validates all requests before
atomically recording in-process nonce consumption.

Changing or removing a tenant/purpose label invalidates semantic identity,
bytecode verification, request identity or exact approval matching, depending
on the boundary changed.

## Security boundary and limitations

This profile covers explicit data flow in a language without branches, loops,
mutable locals, shared memory or recursion. It does not yet cover timing,
resource, termination or host side channels; data hidden in untyped strings;
distributed persistence; durable multi-process replay protection; real effect
execution; declassification; endorsement; dynamic principals; or control-flow
joins. Host adapters must preserve labels and enforce their own tenant boundary.

Passing the current gates is evidence for the implemented cases, not proof of
zero defects, invulnerability or universal superiority over another language.
