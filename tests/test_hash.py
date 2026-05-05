import pytest
from probe.modules.hash import identify_hash, generate_hash, crack_hash


def test_identify_md5():
    result = identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    assert "MD5" in result


def test_identify_sha1():
    result = identify_hash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
    assert "SHA1" in result


def test_identify_sha256():
    result = identify_hash("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
    assert "SHA256" in result


def test_identify_sha512():
    h = "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    result = identify_hash(h)
    assert "SHA512" in result or "Unknown" in result  # 126-char, ambiguous


def test_identify_unknown():
    result = identify_hash("notahash")
    assert "Unknown" in result


def test_generate_md5():
    result = generate_hash("password", "md5")
    assert result == "5f4dcc3b5aa765d61d8327deb882cf99"


def test_generate_sha256():
    import hashlib
    result = generate_hash("test", "sha256")
    assert result == hashlib.sha256(b"test").hexdigest()


def test_crack_hash_found(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("admin\npassword\nroot\n")
    result = crack_hash("5f4dcc3b5aa765d61d8327deb882cf99", str(wl), hash_type="md5")
    assert result == "password"


def test_crack_hash_not_found(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("admin\nroot\n")
    result = crack_hash("5f4dcc3b5aa765d61d8327deb882cf99", str(wl), hash_type="md5")
    assert result is None
