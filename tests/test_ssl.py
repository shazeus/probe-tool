import pytest
import datetime


def _make_mock_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert


def test_parse_cert_expiry():
    from probe.modules.ssl_scan import parse_cert_info
    cert = _make_mock_cert()
    info = parse_cert_info(cert)
    assert "not_after" in info
    assert info["subject"] == "test.example.com"


def test_parse_cert_self_signed():
    from probe.modules.ssl_scan import parse_cert_info
    cert = _make_mock_cert()
    info = parse_cert_info(cert)
    # subject is test.example.com, issuer is Test CA — NOT self-signed
    assert info["self_signed"] is False


def test_parse_cert_expiry_fields():
    from probe.modules.ssl_scan import parse_cert_info
    cert = _make_mock_cert()
    info = parse_cert_info(cert)
    assert info["days_left"] > 0
    assert info["expired"] is False
    assert info["expiring_soon"] is False


def test_check_weak_ciphers_flags_rc4():
    from probe.modules.ssl_scan import is_weak_cipher
    assert is_weak_cipher("RC4-SHA") is True
    assert is_weak_cipher("DES-CBC-SHA") is True
    assert is_weak_cipher("TLS_AES_256_GCM_SHA384") is False


def test_check_weak_ciphers_flags_md5():
    from probe.modules.ssl_scan import is_weak_cipher
    assert is_weak_cipher("AES128-MD5") is True
