# Architecture: how cryptolab-suite extends cryptolab-kit

```
cryptolab-kit (package: cryptolab)
  classic / number_theory / rsa_edu     EDUCATIONAL
  modern (AES-GCM, RSA-OAEP, X25519…)   SAFE wrappers
  hybrid envelope                       SAFE

cryptolab-suite (package: cryptolab_suite)
  shamir, merkle, x509_tools, vault,
  streaming, handshake, bench, challenges
  kit_bridge  →  optional import of cryptolab
```

## Relationship

- **Suite enhances kit**; it is not a fork. New capabilities live here.
- Install kit editable beside suite (`pip install -e ../cryptolab-kit -e ".[dev]"`).
- `cryptolab_suite.kit_bridge.require_cryptolab()` imports `cryptolab` or
  raises a clear message. `suite kit-check` validates the link.
- Streaming AES-GCM reuses the same AEAD primitive (AESGCM, 12-byte
  nonce, 32-byte key) as kit’s one-shot API, with suite-specific framing.
- Benchmarks call kit `rsa_edu` for the educational RSA row and
  `cryptography` for OAEP / AES-GCM rows.
- Challenges embody classical concepts taught in the kit but keep canned
  answers as digests inside the suite.

## Module map

| Module | Role |
|--------|------|
| `shamir` | GF(256) split/combine |
| `merkle` | Tree + inclusion proof |
| `x509_tools` | CA / leaf / inspect |
| `vault` | Argon2id + AES-GCM store |
| `streaming` | Chunked file AEAD |
| `handshake` | Offline ECDH demo |
| `bench` | Live timings |
| `challenges` | Offline CTF lab |
| `cli` | `suite` / `cryptolab-suite` |

## Non-goals

- No network MITM / attack frameworks
- No production HSM / multiparty custody product
- No wrapping the entire kit CLI — use `cryptolab` for kit commands
