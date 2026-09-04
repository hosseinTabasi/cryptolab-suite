"""X.509 certificate toolkit via the ``cryptography`` package.

**SAFE path:** generates self-signed CA and leaf certificates for local
lab / development use. Not a public CA; not for browser trust stores
without your own operational review.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

KeyType = Literal["rsa", "ec"]
PrivateKey = RSAPrivateKey | EllipticCurvePrivateKey


@dataclass(frozen=True)
class CertBundle:
    """PEM-encoded certificate and matching private key."""

    cert_pem: bytes
    key_pem: bytes
    cert: x509.Certificate


def _make_key(key_type: KeyType, rsa_bits: int = 2048) -> PrivateKey:
    if key_type == "rsa":
        if rsa_bits < 2048:
            raise ValueError("RSA key size must be >= 2048")
        return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    if key_type == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    raise ValueError(f"unsupported key type: {key_type}")


def _name(common_name: str, org: str = "CryptoLab Suite") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _serialize_key(key: PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _serialize_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_ca(
    common_name: str = "CryptoLab Suite Test CA",
    *,
    key_type: KeyType = "rsa",
    days: int = 3650,
    rsa_bits: int = 2048,
) -> CertBundle:
    """Generate a self-signed CA certificate and private key.

    **SAFE library path** — for local labs only; do not ship as a public CA.
    """
    key = _make_key(key_type, rsa_bits)
    subject = _name(common_name)
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    return CertBundle(cert_pem=_serialize_cert(cert), key_pem=_serialize_key(key), cert=cert)


def issue_leaf(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    common_name: str,
    *,
    sans: list[str] | None = None,
    key_type: KeyType = "rsa",
    days: int = 365,
    rsa_bits: int = 2048,
) -> CertBundle:
    """Issue a leaf (end-entity) certificate signed by the given CA.

    ``sans`` are DNS names added as Subject Alternative Names.
    """
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    if not isinstance(ca_key, (RSAPrivateKey, EllipticCurvePrivateKey)):
        raise TypeError("CA key must be RSA or EC")

    leaf_key = _make_key(key_type, rsa_bits)
    subject = _name(common_name)
    now = dt.datetime.now(dt.timezone.utc)
    san_list = sans or [common_name]
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san_list]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    return CertBundle(
        cert_pem=_serialize_cert(cert),
        key_pem=_serialize_key(leaf_key),
        cert=cert,
    )


def inspect_cert(pem: bytes) -> dict[str, object]:
    """Return a dict summary: subject, issuer, SAN, dates, fingerprint."""
    cert = x509.load_pem_x509_certificate(pem)
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(n) for n in ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        pass
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "san_dns": sans,
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "is_ca": _is_ca(cert),
    }


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bool(bc.value.ca)
    except x509.ExtensionNotFound:
        return False


def write_bundle(bundle: CertBundle, cert_path: str | Path, key_path: str | Path) -> None:
    """Write PEM cert and key to disk (key permissions left to caller)."""
    Path(cert_path).write_bytes(bundle.cert_pem)
    Path(key_path).write_bytes(bundle.key_pem)


def load_pem_file(path: str | Path) -> bytes:
    """Read a PEM file as bytes."""
    return Path(path).read_bytes()
