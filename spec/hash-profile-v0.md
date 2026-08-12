# JOAN Hash Profile v0

Every digest carries:

- algorithm: `sha256`;
- profile: `joan-hash-v0`;
- printable ASCII domain;
- lowercase 32-byte hexadecimal value.

Construction:

```text
SHA-256(
  "JOAN\\0HASH\\0V0"
  || u64be(len(domain)) || domain
  || u64be(len(payload)) || payload
)
```

The profile provides domain separation and deterministic identity, not proof that the represented claim is true. Future algorithms require a new tagged profile and explicit migration evidence; silent fallback is forbidden.
