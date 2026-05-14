from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent.parent
CERTS_DIR = ROOT / "certs"
CA_DIR = CERTS_DIR / "ca"
UPDATER_DIR = CERTS_DIR / "updater"
SECURITY_DIR = CERTS_DIR / "security"


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _build_name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Reaction Game DevSecOps"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _generate_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = _build_name("Reaction Game DevSecOps CA")
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def _generate_leaf(
    *,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    san_dns: list[str],
    san_ips: list[str],
    usage: ExtendedKeyUsageOID,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = _build_name(common_name)
    now = datetime.now(timezone.utc)
    san_items = [x509.DNSName(name) for name in san_dns] + [x509.IPAddress(ip_address(ip)) for ip in san_ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_items), critical=False)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    return key, cert


def main() -> None:
    CA_DIR.mkdir(parents=True, exist_ok=True)
    UPDATER_DIR.mkdir(parents=True, exist_ok=True)
    SECURITY_DIR.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = _generate_ca()
    _write_private_key(CA_DIR / "ca.key", ca_key)
    _write_cert(CA_DIR / "ca.crt", ca_cert)

    updater_key, updater_cert = _generate_leaf(
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name="updater-service",
        san_dns=["updater-service", "localhost"],
        san_ips=["127.0.0.1"],
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    _write_private_key(UPDATER_DIR / "updater.key", updater_key)
    _write_cert(UPDATER_DIR / "updater.crt", updater_cert)

    security_key, security_cert = _generate_leaf(
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name="security-service",
        san_dns=["security-service", "localhost"],
        san_ips=["127.0.0.1"],
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    _write_private_key(SECURITY_DIR / "security.key", security_key)
    _write_cert(SECURITY_DIR / "security.crt", security_cert)

    print(f"Generated CA and mTLS certs under {CERTS_DIR}")


if __name__ == "__main__":
    main()
