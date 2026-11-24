"""Real cert + key pairs for credential tests (TRUS-2374).

``load_credentials`` reads the expiry from ``cert.pem`` and checks the cert
matches ``key.pem``, so a test that persists and reloads credentials needs a
real pair rather than placeholder strings.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from functools import lru_cache

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from edge.identity import EdgeCredentials


@lru_cache(maxsize=4)
def rsa_key_pem(index: int = 0) -> str:
    """One cached RSA key per index, so the suite pays for only a few keygens."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def cert_pem_for(key_pem: str, not_after: datetime) -> str:
    """Self-signed cert for ``key_pem`` that expires at ``not_after``."""
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "edge-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - timedelta(days=90))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def make_credentials(
    *, days_valid: float = 90, key_index: int = 0, edge_id: str = "abc-123"
) -> EdgeCredentials:
    """Credentials whose cert really expires ``days_valid`` days from now."""
    # X.509 stores whole seconds; match it so loaded == persisted.
    not_after = (datetime.now(UTC) + timedelta(days=days_valid)).replace(microsecond=0)
    key_pem = rsa_key_pem(key_index)
    return EdgeCredentials(
        edge_id=edge_id,
        tenant_id="acme",
        cert_pem=cert_pem_for(key_pem, not_after),
        key_pem=key_pem,
        ca_chain_pem="CA",
        cert_valid_to=not_after,
        agp_endpoint="https://api.trustmodel.ai",
        telemetry_endpoint="https://api.trustmodel.ai/api/v1/edge/telemetry",
    )
