import base64
import json
import pytest
from probe.modules.jwt_scan import decode_jwt, check_jwt, none_attack, crack_jwt, forge_jwt


def _make_token(header: dict, payload: dict, signature: str = "fakesig") -> str:
    def enc(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc(header)}.{enc(payload)}.{signature}"


HS256_TOKEN = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1234", "name": "test", "iat": 1516239022})


def test_decode_jwt_returns_header_and_payload():
    header, payload = decode_jwt(HS256_TOKEN)
    assert header["alg"] == "HS256"
    assert payload["sub"] == "1234"


def test_decode_jwt_invalid_raises():
    with pytest.raises(ValueError):
        decode_jwt("not.a.token")


def test_check_jwt_detects_none_alg():
    none_token = _make_token({"alg": "none", "typ": "JWT"}, {"sub": "admin"}, "")
    findings = check_jwt(none_token)
    assert any("none" in f["detail"].lower() for f in findings)


def test_check_jwt_hs256_ok():
    findings = check_jwt(HS256_TOKEN)
    alg_findings = [f for f in findings if "none" in f["detail"].lower()]
    assert len(alg_findings) == 0


def test_none_attack_produces_valid_structure():
    result = none_attack(HS256_TOKEN)
    header, payload = decode_jwt(result)
    assert header["alg"] == "none"


def test_crack_jwt_finds_secret(tmp_path):
    import jwt as pyjwt
    secret = "supersecret"
    token = pyjwt.encode({"sub": "test"}, secret, algorithm="HS256")
    wl = tmp_path / "secrets.txt"
    wl.write_text("wrong\nsupersecret\nother\n")
    result = crack_jwt(token, str(wl))
    assert result == "supersecret"


def test_crack_jwt_not_found(tmp_path):
    import jwt as pyjwt
    token = pyjwt.encode({"sub": "test"}, "impossiblesecret", algorithm="HS256")
    wl = tmp_path / "secrets.txt"
    wl.write_text("admin\npassword\n")
    result = crack_jwt(token, str(wl))
    assert result is None


def test_forge_jwt():
    import jwt as pyjwt
    original = pyjwt.encode({"sub": "user"}, "key", algorithm="HS256")
    forged = forge_jwt(original, "key")
    header, payload = decode_jwt(forged)
    assert payload["sub"] == "user"
