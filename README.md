# cryptolab-suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

Advanced cryptography **lab suite** by **Hossein Tabasi**. This project
**enhances** [cryptolab-kit](https://github.com/hosseinTabasi/cryptolab-kit)
with Shamir secret sharing, Merkle trees, an X.509 toolkit, a local
encrypted vault, streaming AES-GCM, a toy handshake demo, live
benchmarks, and an offline challenge lab.

**This is a laboratory. Educational modules are labelled EDUCATIONAL
and must never protect real secrets or production key custody.
Safe commands use the `cryptography` and `argon2-cffi` packages; they
still require careful key and passphrase handling. Read
[docs/SECURITY.md](docs/SECURITY.md).**

## Features: new vs inherited

| Capability | Where | Label |
|---|---|---|
| Caesar / Vigenère / frequency / textbook RSA / hybrid envelope | [cryptolab-kit](https://github.com/hosseinTabasi/cryptolab-kit) | EDUCATIONAL / SAFE (see kit) |
| Shamir secret sharing (GF(256)) | **suite** | EDUCATIONAL |
| Merkle tree + inclusion proofs (SHA-256) | **suite** | SAFE construction (integrity) |
| X.509 CA + leaf issue + PEM inspect | **suite** | SAFE path (`cryptography`) |
| Local vault (Argon2id → AES-256-GCM JSON) | **suite** | SAFE |
| Streaming / chunked AES-GCM files | **suite** | SAFE |
| Toy X25519 + HKDF + Finished handshake (offline MITM sim) | **suite** | EDUCATIONAL |
| Live benches (tiny RSA vs OAEP; AES-GCM MiB/s) | **suite** | mixed |
| Offline challenge lab (canned only) | **suite** | EDUCATIONAL |

Topics: `cryptography`, `shamir`, `merkle-tree`, `x509`, `vault`, `aes-gcm`, `educational`.

## Dependency strategy

**Preferred (local / CI / this box):** install the sibling kit editable,
then the suite:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ../cryptolab-kit -e ".[dev]"
```

Suite code imports the `cryptolab` package when present
(`cryptolab_suite.kit_bridge`). Benchmarks that exercise textbook RSA
and optional classic helpers need the kit. Core suite modules
(Shamir, Merkle, vault, streaming, X.509, handshake, challenges) use
`cryptography` / `argon2-cffi` directly and remain usable without the
kit for most commands; `suite kit-check` verifies the bridge.

**GitHub standalone clone:** either clone both repos as siblings and use
the path install above, or:

```bash
pip install "cryptolab-kit @ git+https://github.com/hosseinTabasi/cryptolab-kit.git"
pip install -e ".[dev]"
```

(`.[kit]` also declares the git URL optional extra.) Git dependencies
need network at install time; path/editable installs work offline for
tests once wheels are cached.

There is no mandatory `vendor/` copy of the kit — the suite is a
**substantial** separate package, not a thin wrapper.

## Install

Python 3.11+.

```bash
cd cryptolab-suite
python -m venv .venv && source .venv/bin/activate
pip install -e ../cryptolab-kit -e ".[dev]"
```

Windows PowerShell:

```powershell
python -m venv .venv; .venv\Scripts\Activate.ps1
pip install -e ..\cryptolab-kit -e ".[dev]"
```

CLI entry points: `cryptolab-suite`, `suite`, and `python -m cryptolab_suite`.

## Quickstart

### Vault (SAFE)

```bash
suite vault-init --path ./lab.vault --passphrase 'demo-only-passphrase'
suite vault-set  --path ./lab.vault --passphrase 'demo-only-passphrase' --name api --value 'tok-1'
suite vault-list --path ./lab.vault --passphrase 'demo-only-passphrase'
suite vault-get  --path ./lab.vault --passphrase 'demo-only-passphrase' --name api
```

Prefer `--passphrase-env VAULT_PASS` so the passphrase is not in shell history.

### Shamir (EDUCATIONAL)

```bash
suite share-split --secret 'demo-secret' -n 5 -k 3 --out ./shares
suite share-combine ./shares/share-01.txt ./shares/share-02.txt ./shares/share-03.txt --hex
```

### Handshake demo (EDUCATIONAL)

```bash
suite handshake-demo
```

### Benchmarks (live)

```bash
python -m cryptolab_suite bench
# or: suite bench
```

Sample measured output: [examples/bench_sample.txt](examples/bench_sample.txt).

### More

```bash
suite merkle-build --leaves examples/leaves.txt --out /tmp/tree.json
suite cert-ca --out /tmp/ca && suite cert-issue --ca-cert /tmp/ca/ca.crt --ca-key /tmp/ca/ca.key --cn app.test --out /tmp/leaf
suite stream-encrypt --src README.md --dest /tmp/readme.strm --key-out /tmp/k.bin
suite challenge list
suite challenge solve chal-01 --answer 'CRYPTOGRAPHY IS FUN'
```

See [examples/demo_session.md](examples/demo_session.md).

## Architecture & security

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the suite extends the kit
- [docs/SECURITY.md](docs/SECURITY.md) — EDUCATIONAL vs SAFE labels

## Tests

No network required for pytest (after packages are installed):

```bash
pytest -q
```

## License

MIT. Copyright (c) 2026 Hossein Tabasi. See [LICENSE](LICENSE).

GitHub: [hosseinTabasi](https://github.com/hosseinTabasi) ·
Related: [cryptolab-kit](https://github.com/hosseinTabasi/cryptolab-kit)
