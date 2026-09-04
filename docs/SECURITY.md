# Security model

**cryptolab-suite is a laboratory and teaching toolkit** that extends
[cryptolab-kit](https://github.com/hosseinTabasi/cryptolab-kit). Treat
every educational primitive as unsuitable for real custody. “Safe” APIs
wrap constructions from `cryptography` and `argon2-cffi`; they are only
as safe as your operational practice.

## Educational (do not use for real secrets)

| Component | Why it is unsafe / limited |
|-----------|----------------------------|
| Shamir (GF(256)) | Correct field arithmetic for labs, but **not audited** for production key custody; no share authentication; side-channel free coding not claimed. |
| Toy handshake | Offline X25519 + HKDF + Finished demo. **Not TLS.** MITM scenario is a canned in-process simulation only — no network attack tooling. |
| Challenge lab | Canned classical ciphertexts only. No network cryptanalysis. |
| Benchmarks (textbook RSA row) | Tiny moduli from cryptolab-kit `rsa_edu`. |

Loud `EDUCATIONAL` notes appear in docstrings and CLI output.

## Safe path (library-backed)

| Construction | Notes |
|--------------|--------|
| Vault | Argon2id KDF → AES-256-GCM over JSON. Disk stores salt + ciphertext only. Never log passphrases. |
| Streaming AES-GCM | Chunked frames with per-chunk nonces and AAD binding index. Never reuse a (key, nonce) pair. |
| X.509 toolkit | Self-signed CA + leaf for **local labs**. Not a public CA. |
| Merkle tree | SHA-256 domain-separated hashes for inclusion proofs. Integrity tool, not confidentiality. |
| AES-GCM / RSA-OAEP benches | Use `cryptography` directly. |

## Operational rules

1. **No hardcoded secrets** in source. Demo passphrases in docs are examples only.
2. **Passphrases** via prompt or environment (`--passphrase-env`); avoid shell history.
3. **Gitignore** vaults, keys, PEMs, share directories.
4. **No malware / ransomware / keyloggers / exploit tooling** in this repository.
5. Shamir shares and vault files are sensitive — treat them like keys.

## Field choice for Shamir

Suite Shamir uses **GF(256)** (AES polynomial `0x11b`), byte-oriented.
A prime-field implementation is not shipped.
