"""Command-line interface for cryptolab-suite.

Entry points: ``cryptolab-suite``, ``suite``, and ``python -m cryptolab_suite``.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path


def _read_secret_bytes(arg: str | None, file: str | None) -> bytes:
    if file:
        return Path(file).read_bytes()
    if arg is not None:
        return arg.encode("utf-8")
    raise SystemExit("provide --secret or --secret-file")


def _passphrase_arg(ns: argparse.Namespace) -> str:
    if getattr(ns, "passphrase", None):
        return ns.passphrase
    if getattr(ns, "passphrase_env", None):
        import os

        val = os.environ.get(ns.passphrase_env)
        if not val:
            raise SystemExit(f"env var {ns.passphrase_env} is empty or unset")
        return val
    # Interactive — never echo.
    return getpass.getpass("Passphrase: ")


def cmd_share_split(ns: argparse.Namespace) -> int:
    from cryptolab_suite.shamir import split_to_files

    secret = _read_secret_bytes(ns.secret, ns.secret_file)
    paths = split_to_files(secret, ns.n, ns.k, ns.out)
    print("EDUCATIONAL Shamir split (GF(256)) — not for unaudited custody.")
    print(f"Wrote {len(paths)} shares (threshold k={ns.k}) under {ns.out}:")
    for p in paths:
        print(f"  {p}")
    return 0


def cmd_share_combine(ns: argparse.Namespace) -> int:
    from cryptolab_suite.shamir import combine_from_files

    secret = combine_from_files(ns.shares)
    print("EDUCATIONAL Shamir combine (GF(256)).")
    if ns.out:
        Path(ns.out).write_bytes(secret)
        print(f"Wrote {len(secret)} bytes to {ns.out}")
    else:
        # Prefer hex to avoid binary stdout issues.
        print(secret.hex() if ns.hex else secret.decode("utf-8", errors="replace"))
    return 0


def cmd_merkle_build(ns: argparse.Namespace) -> int:
    from cryptolab_suite.merkle import build_from_file, save_tree_meta

    tree = build_from_file(ns.leaves)
    dest = Path(ns.out)
    save_tree_meta(tree, dest)
    print(f"Merkle root: {tree.root.hex()}")
    print(f"Leaves: {len(tree.leaves)}  meta: {dest}")
    return 0


def cmd_merkle_prove(ns: argparse.Namespace) -> int:
    import json

    from cryptolab_suite.merkle import load_tree_meta

    tree = load_tree_meta(ns.tree)
    proof = tree.prove(ns.index)
    out = Path(ns.out) if ns.out else None
    text = json.dumps(proof.to_dict(), indent=2) + "\n"
    if out:
        out.write_text(text, encoding="utf-8")
        print(f"Wrote proof to {out}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_merkle_verify(ns: argparse.Namespace) -> int:
    import json

    from cryptolab_suite.merkle import InclusionProof, verify_inclusion

    data = json.loads(Path(ns.proof).read_text(encoding="utf-8"))
    proof = InclusionProof.from_dict(data)
    leaf = Path(ns.leaf).read_bytes() if ns.leaf else None
    ok = verify_inclusion(proof, leaf)
    print("VALID" if ok else "INVALID")
    return 0 if ok else 1


def cmd_cert_ca(ns: argparse.Namespace) -> int:
    from cryptolab_suite.x509_tools import generate_ca, write_bundle

    bundle = generate_ca(ns.cn, key_type=ns.key_type, days=ns.days)
    out = Path(ns.out)
    out.mkdir(parents=True, exist_ok=True)
    write_bundle(bundle, out / "ca.crt", out / "ca.key")
    print(f"SAFE path: wrote CA cert {out / 'ca.crt'} and key {out / 'ca.key'}")
    print(f"subject: {bundle.cert.subject.rfc4514_string()}")
    return 0


def cmd_cert_issue(ns: argparse.Namespace) -> int:
    from cryptolab_suite.x509_tools import issue_leaf, load_pem_file, write_bundle

    sans = ns.san if ns.san else None
    bundle = issue_leaf(
        load_pem_file(ns.ca_cert),
        load_pem_file(ns.ca_key),
        ns.cn,
        sans=sans,
        key_type=ns.key_type,
        days=ns.days,
    )
    out = Path(ns.out)
    out.mkdir(parents=True, exist_ok=True)
    write_bundle(bundle, out / "leaf.crt", out / "leaf.key")
    print(f"SAFE path: issued leaf {out / 'leaf.crt'}")
    return 0


def cmd_cert_show(ns: argparse.Namespace) -> int:
    from cryptolab_suite.x509_tools import inspect_cert, load_pem_file

    info = inspect_cert(load_pem_file(ns.cert))
    for k, v in info.items():
        print(f"{k}: {v}")
    return 0


def cmd_vault_init(ns: argparse.Namespace) -> int:
    from cryptolab_suite.vault import init_vault

    pw = _passphrase_arg(ns)
    init_vault(ns.path, pw)
    print(f"SAFE vault created at {ns.path}")
    return 0


def cmd_vault_set(ns: argparse.Namespace) -> int:
    from cryptolab_suite.vault import unlock_vault

    pw = _passphrase_arg(ns)
    vault = unlock_vault(ns.path, pw)
    value = ns.value if ns.value is not None else getpass.getpass("Secret value: ")
    vault.set(ns.name, value)
    print(f"Set secret {ns.name!r}")
    return 0


def cmd_vault_get(ns: argparse.Namespace) -> int:
    from cryptolab_suite.vault import unlock_vault

    pw = _passphrase_arg(ns)
    vault = unlock_vault(ns.path, pw)
    print(vault.get(ns.name))
    return 0


def cmd_vault_list(ns: argparse.Namespace) -> int:
    from cryptolab_suite.vault import unlock_vault

    pw = _passphrase_arg(ns)
    vault = unlock_vault(ns.path, pw)
    names = vault.list_names()
    if not names:
        print("(empty)")
    else:
        for n in names:
            print(n)
    return 0


def cmd_vault_export(ns: argparse.Namespace) -> int:
    from cryptolab_suite.vault import unlock_vault

    pw = _passphrase_arg(ns)
    vault = unlock_vault(ns.path, pw)
    dest = vault.export_encrypted(ns.out)
    print(f"Exported encrypted vault blob to {dest}")
    return 0


def cmd_stream_encrypt(ns: argparse.Namespace) -> int:
    from cryptolab_suite.streaming import encrypt_stream, generate_key

    if ns.key_file:
        key = Path(ns.key_file).read_bytes()
    else:
        key = generate_key()
        Path(ns.key_out).write_bytes(key)
        print(f"Wrote new key to {ns.key_out}")
    aad = ns.aad.encode("utf-8") if ns.aad else b""
    encrypt_stream(ns.src, ns.dest, key, associated_data=aad, chunk_size=ns.chunk)
    print(f"SAFE stream-encrypt: {ns.src} -> {ns.dest}")
    return 0


def cmd_stream_decrypt(ns: argparse.Namespace) -> int:
    from cryptolab_suite.streaming import decrypt_stream

    key = Path(ns.key_file).read_bytes()
    aad = ns.aad.encode("utf-8") if ns.aad is not None else None
    decrypt_stream(ns.src, ns.dest, key, associated_data=aad)
    print(f"SAFE stream-decrypt: {ns.src} -> {ns.dest}")
    return 0


def cmd_handshake_demo(ns: argparse.Namespace) -> int:
    from cryptolab_suite.handshake import demo_report

    sys.stdout.write(demo_report(include_mitm=not ns.no_mitm))
    return 0


def cmd_bench(_ns: argparse.Namespace) -> int:
    from cryptolab_suite.bench import format_table, run_all

    rows = run_all()
    sys.stdout.write(format_table(rows))
    return 0


def cmd_challenge(ns: argparse.Namespace) -> int:
    from cryptolab_suite import challenges as ch

    if ns.challenge_cmd == "list":
        sys.stdout.write(ch.format_list())
        return 0
    if ns.challenge_cmd == "solve":
        ok = ch.check_answer(ns.id, ns.answer)
        if ok:
            print(f"CORRECT — {ns.id}")
            return 0
        print(f"WRONG — {ns.id}")
        if ns.show_hint:
            print(f"hint: {ch.get_challenge(ns.id).hint}")
        return 1
    if ns.challenge_cmd == "show":
        c = ch.get_challenge(ns.id)
        print(f"{c.id} [{c.difficulty}] {c.title}")
        print(c.description)
        print(f"ciphertext: {c.ciphertext}")
        print(f"hint: {c.hint}")
        return 0
    raise SystemExit(f"unknown challenge subcommand: {ns.challenge_cmd}")


def cmd_kit_check(_ns: argparse.Namespace) -> int:
    from cryptolab_suite.kit_bridge import KitNotInstalledError, require_cryptolab

    try:
        mod = require_cryptolab()
    except KitNotInstalledError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"cryptolab-kit OK: version={getattr(mod, '__version__', '?')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    p = argparse.ArgumentParser(
        prog="suite",
        description=(
            "cryptolab-suite — Shamir, Merkle, X.509, vault, streaming AES-GCM, "
            "handshake demo, benches, challenges. Extends cryptolab-kit."
        ),
    )
    p.add_argument("--version", action="version", version="cryptolab-suite 0.1.0")
    sub = p.add_subparsers(dest="command", required=True)

    # Shamir
    sp = sub.add_parser("share-split", help="EDUCATIONAL: Shamir split (GF(256))")
    sp.add_argument("--secret", help="secret string")
    sp.add_argument("--secret-file", help="read secret bytes from file")
    sp.add_argument("-n", type=int, required=True, help="number of shares")
    sp.add_argument("-k", type=int, required=True, help="threshold")
    sp.add_argument("--out", required=True, help="output directory")
    sp.set_defaults(func=cmd_share_split)

    sp = sub.add_parser("share-combine", help="EDUCATIONAL: Shamir combine")
    sp.add_argument("shares", nargs="+", help="share files")
    sp.add_argument("--out", help="write raw secret to file")
    sp.add_argument("--hex", action="store_true", help="print hex if no --out")
    sp.set_defaults(func=cmd_share_combine)

    # Merkle
    sp = sub.add_parser("merkle-build", help="Build Merkle tree from leaf file")
    sp.add_argument("--leaves", required=True, help="text file, one leaf per line")
    sp.add_argument("--out", required=True, help="JSON meta output")
    sp.set_defaults(func=cmd_merkle_build)

    sp = sub.add_parser("merkle-prove", help="Generate inclusion proof")
    sp.add_argument("--tree", required=True, help="JSON from merkle-build")
    sp.add_argument("--index", type=int, required=True)
    sp.add_argument("--out", help="write proof JSON")
    sp.set_defaults(func=cmd_merkle_prove)

    sp = sub.add_parser("merkle-verify", help="Verify inclusion proof")
    sp.add_argument("--proof", required=True)
    sp.add_argument("--leaf", help="optional leaf data file to re-hash")
    sp.set_defaults(func=cmd_merkle_verify)

    # X.509
    sp = sub.add_parser("cert-ca", help="SAFE: generate self-signed CA")
    sp.add_argument("--cn", default="CryptoLab Suite Test CA")
    sp.add_argument("--key-type", choices=("rsa", "ec"), default="rsa")
    sp.add_argument("--days", type=int, default=3650)
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=cmd_cert_ca)

    sp = sub.add_parser("cert-issue", help="SAFE: issue leaf cert under CA")
    sp.add_argument("--ca-cert", required=True)
    sp.add_argument("--ca-key", required=True)
    sp.add_argument("--cn", required=True)
    sp.add_argument("--san", action="append", default=[], help="DNS SAN (repeatable)")
    sp.add_argument("--key-type", choices=("rsa", "ec"), default="rsa")
    sp.add_argument("--days", type=int, default=365)
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=cmd_cert_issue)

    sp = sub.add_parser("cert-show", help="SAFE: inspect PEM certificate")
    sp.add_argument("--cert", required=True)
    sp.set_defaults(func=cmd_cert_show)

    # Vault helpers
    def _vault_pw(sp_: argparse.ArgumentParser) -> None:
        sp_.add_argument("--path", required=True, help="vault file path")
        sp_.add_argument("--passphrase", help="prefer env or prompt in real use")
        sp_.add_argument(
            "--passphrase-env",
            help="read passphrase from environment variable (never logged)",
        )

    sp = sub.add_parser("vault-init", help="SAFE: create encrypted vault")
    _vault_pw(sp)
    sp.set_defaults(func=cmd_vault_init)

    sp = sub.add_parser("vault-set", help="SAFE: set named secret")
    _vault_pw(sp)
    sp.add_argument("--name", required=True)
    sp.add_argument("--value", help="secret value (or prompt)")
    sp.set_defaults(func=cmd_vault_set)

    sp = sub.add_parser("vault-get", help="SAFE: get named secret")
    _vault_pw(sp)
    sp.add_argument("--name", required=True)
    sp.set_defaults(func=cmd_vault_get)

    sp = sub.add_parser("vault-list", help="SAFE: list secret names")
    _vault_pw(sp)
    sp.set_defaults(func=cmd_vault_list)

    sp = sub.add_parser("vault-export", help="SAFE: copy encrypted vault blob")
    _vault_pw(sp)
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=cmd_vault_export)

    # Streaming
    sp = sub.add_parser("stream-encrypt", help="SAFE: chunked AES-GCM encrypt")
    sp.add_argument("--src", required=True)
    sp.add_argument("--dest", required=True)
    sp.add_argument("--key-file", help="existing 32-byte key file")
    sp.add_argument("--key-out", default="stream.key", help="where to write new key")
    sp.add_argument("--aad", default="", help="associated data string")
    sp.add_argument("--chunk", type=int, default=65536)
    sp.set_defaults(func=cmd_stream_encrypt)

    sp = sub.add_parser("stream-decrypt", help="SAFE: chunked AES-GCM decrypt")
    sp.add_argument("--src", required=True)
    sp.add_argument("--dest", required=True)
    sp.add_argument("--key-file", required=True)
    sp.add_argument("--aad", default=None, help="must match encrypt AAD if set")
    sp.set_defaults(func=cmd_stream_decrypt)

    # Handshake / bench / challenges
    sp = sub.add_parser("handshake-demo", help="EDUCATIONAL: offline X25519 handshake")
    sp.add_argument("--no-mitm", action="store_true", help="skip MITM simulation")
    sp.set_defaults(func=cmd_handshake_demo)

    sp = sub.add_parser("bench", help="Live educational vs SAFE micro-benchmarks")
    sp.set_defaults(func=cmd_bench)

    sp = sub.add_parser("challenge", help="EDUCATIONAL: offline challenge lab")
    csub = sp.add_subparsers(dest="challenge_cmd", required=True)
    c1 = csub.add_parser("list", help="list challenges")
    c1.set_defaults(func=cmd_challenge)
    c2 = csub.add_parser("solve", help="submit an answer")
    c2.add_argument("id")
    c2.add_argument("--answer", required=True)
    c2.add_argument("--show-hint", action="store_true")
    c2.set_defaults(func=cmd_challenge)
    c3 = csub.add_parser("show", help="show one challenge")
    c3.add_argument("id")
    c3.set_defaults(func=cmd_challenge)

    sp = sub.add_parser("kit-check", help="Verify cryptolab-kit import")
    sp.set_defaults(func=cmd_kit_check)

    return p


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    ns = parser.parse_args(argv)
    return int(ns.func(ns))


if __name__ == "__main__":
    raise SystemExit(main())
