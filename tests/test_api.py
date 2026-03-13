from pathlib import Path

import pytest

import hiera_eyaml
from hiera_eyaml.parser import TokenFormat

FIXTURES = Path(__file__).parent / "fixtures"
KEYS = FIXTURES / "keys"


@pytest.fixture
def public_key_pem() -> str:
    return (KEYS / "public_key.pkcs7.pem").read_text()


@pytest.fixture
def private_key_pem() -> str:
    return (KEYS / "private_key.pkcs7.pem").read_text()


RUBY_ENC_STRING = (
    "ENC[PKCS7,MIIBiQYJKoZIhvcNAQcDoIIBejCCAXYCAQAxggEhMIIBHQIBADAFMAACAQAw"
    "DQYJKoZIhvcNAQEBBQAEggEAgld+rftjW8WmMwTJLX/3Kk9hQv9ZUufsieij"
    "xhnCo3gtR/6xaKdMC4wpYM9Eck7FFdmjz2XnJK9o5rlvjW5ZBH3u2A3tphs6"
    "cgy7HzsfrsJvw1Mc+CLSNL35MVi/YvNCxezn+rXn28NW8NntByoLTzZnd6iGx"
    "SBk4S7Z7XwvdQWuUjXy0muEeAUYtS/eppNZYdyeMpzE9oHmfMM+zwdOYzc/n"
    "fwvnoLHGP+sv6KmnzCyNtqyrdvCIn+m+ljPWpGvj410Q52Xili1Scgi+ALJf4"
    "xiEnD5c5YjEkYY8uUe4etCDYZ/aXp9RGvZiHD8Le6jz34fcWbLZlQacCfgcyY"
    "8AzBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBD4CRz8QLvbtgRx/NTxEnpf"
    "gCBLQD1ei8KAcd0LTT7sezZPt6LQnLxPuwx5StflI5xOgA==]"
)


def test_decrypt_value(private_key_pem: str, public_key_pem: str) -> None:
    result = hiera_eyaml.decrypt_value(
        RUBY_ENC_STRING,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
    )
    assert result == "planet of the apes"


def test_encrypt_value_string(private_key_pem: str, public_key_pem: str) -> None:
    encrypted = hiera_eyaml.encrypt_value("hello", public_key_pem=public_key_pem)
    assert encrypted.startswith("ENC[PKCS7,")
    assert encrypted.endswith("]")
    # Round-trip
    decrypted = hiera_eyaml.decrypt_value(
        encrypted,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
    )
    assert decrypted == "hello"


def test_encrypt_value_block(private_key_pem: str, public_key_pem: str) -> None:
    encrypted = hiera_eyaml.encrypt_value(
        "hello", public_key_pem=public_key_pem, output=TokenFormat.BLOCK
    )
    assert encrypted.startswith(">\n    ENC[PKCS7,")
    lines = encrypted.split("\n")
    assert lines[0] == ">"
    for line in lines[1:]:
        assert len(line) <= 64  # 4 indent + 60 content


def test_decrypt_text_plain(private_key_pem: str, public_key_pem: str) -> None:
    text = (FIXTURES / "test_input.yaml").read_text()
    result = hiera_eyaml.decrypt_text(
        text,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
    )
    assert "planet of the apes" in result
    assert "gangs of new york" in result
    assert "apocalypse now" in result
    assert "the count of monte cristo" in result
    assert "dr strangelove" in result
    assert "kramer vs kramer" in result
    assert "the manchurian candidate" in result
    assert "much ado about nothing" in result
    assert "the english patient" in result
    assert "the pink panther" in result
    assert "value5" in result
    assert "value6" in result
    assert "ENC[" not in result


def test_decrypt_text_eyaml(private_key_pem: str, public_key_pem: str) -> None:
    text = (FIXTURES / "test_input.yaml").read_text()
    result = hiera_eyaml.decrypt_text(
        text,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        eyaml=True,
    )
    assert "DEC::PKCS7[planet of the apes]!" not in result  # should have index
    assert "DEC(1)::PKCS7[planet of the apes]!" in result
    assert "ENC[" not in result


def test_decrypt_text_eyaml_indices(private_key_pem: str, public_key_pem: str) -> None:
    text = (FIXTURES / "test_input.yaml").read_text()
    result = hiera_eyaml.decrypt_text(
        text,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        eyaml=True,
    )
    assert "DEC(1)::PKCS7[planet of the apes]!" in result
    assert "DEC(13)::PKCS7[the count of monte cristo]!" in result


def test_decrypt_file(private_key_pem: str, public_key_pem: str) -> None:
    result = hiera_eyaml.decrypt_file(
        str(FIXTURES / "test_input.yaml"),
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
    )
    assert "planet of the apes" in result
    assert "ENC[" not in result


def test_decrypt_encrypted_txt(private_key_pem: str, public_key_pem: str) -> None:
    result = hiera_eyaml.decrypt_file(
        str(FIXTURES / "test_input.encrypted.txt"),
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
    )
    assert result.strip() == "danger will robinson"


def test_decrypt_value_default_encryption(
    private_key_pem: str, public_key_pem: str
) -> None:
    """Handle ENC[<base64>] without explicit PKCS7 tag (defaults to PKCS7)."""
    # Use same ciphertext as RUBY_ENC_STRING but without the PKCS7, prefix
    enc_no_tag = RUBY_ENC_STRING.replace("PKCS7,", "")
    result = hiera_eyaml.decrypt_value(
        enc_no_tag,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
    )
    assert result == "planet of the apes"
