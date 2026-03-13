import base64
from pathlib import Path

import pytest

from hiera_eyaml.keys import load_key

FIXTURES = Path(__file__).parent / "fixtures"
KEYS = FIXTURES / "keys"


def test_load_key_from_file() -> None:
    key = load_key(path=KEYS / "public_key.pkcs7.pem")
    assert "BEGIN CERTIFICATE" in key


def test_load_key_from_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    monkeypatch.setenv("TEST_PUB_KEY", expected)
    key = load_key(env_var="TEST_PUB_KEY")
    assert key == expected


def test_load_key_from_b64_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    original = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    encoded = base64.b64encode(original.encode()).decode()
    monkeypatch.setenv("TEST_B64_KEY", encoded)
    key = load_key(b64_env_var="TEST_B64_KEY")
    assert key == original


def test_load_key_env_var_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = "from_env_var"
    monkeypatch.setenv("TEST_PUB_KEY", expected)
    key = load_key(path=KEYS / "public_key.pkcs7.pem", env_var="TEST_PUB_KEY")
    assert key == expected


def test_load_key_missing_file() -> None:
    with pytest.raises(FileNotFoundError, match="does not exist"):
        load_key(path="/nonexistent/key.pem")


def test_load_key_missing_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFINITELY_NOT_SET", raising=False)
    with pytest.raises(ValueError, match="is not set"):
        load_key(env_var="DEFINITELY_NOT_SET")


def test_load_key_missing_b64_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFINITELY_NOT_SET_B64", raising=False)
    with pytest.raises(ValueError, match="is not set"):
        load_key(b64_env_var="DEFINITELY_NOT_SET_B64")


def test_load_key_no_source() -> None:
    with pytest.raises(ValueError, match="no key source configured"):
        load_key()
