from pathlib import Path

import base64

import pytest

from hiera_eyaml import pkcs7
from hiera_eyaml.parser import (
    EncToken,
    NonMatchToken,
    TokenFormat,
    encrypted_token_types,
    parse,
)

FIXTURES = Path(__file__).parent / "fixtures"
KEYS = FIXTURES / "keys"


@pytest.fixture
def public_key_pem() -> str:
    return (KEYS / "public_key.pkcs7.pem").read_text()


@pytest.fixture
def private_key_pem() -> str:
    return (KEYS / "private_key.pkcs7.pem").read_text()


def make_decrypt_fn(private_key_pem: str, public_key_pem: str):
    def decrypt_fn(tag: str, cipher_b64: str) -> str:
        if tag == "PLAINTEXT":
            return base64.b64decode(cipher_b64).decode("utf-8")
        cipher_bytes = pkcs7.decode(cipher_b64)
        plain_bytes = pkcs7.decrypt(cipher_bytes, private_key_pem, public_key_pem)
        return plain_bytes.decode("utf-8")

    return decrypt_fn


def test_parse_empty_string(private_key_pem: str, public_key_pem: str) -> None:
    token_types = encrypted_token_types(decrypt_fn=make_decrypt_fn(private_key_pem, public_key_pem))
    tokens = parse("", token_types)
    assert tokens == []


def test_parse_no_enc_markers(private_key_pem: str, public_key_pem: str) -> None:
    token_types = encrypted_token_types(decrypt_fn=make_decrypt_fn(private_key_pem, public_key_pem))
    tokens = parse("just plain text", token_types)
    assert len(tokens) == 1
    assert isinstance(tokens[0], NonMatchToken)
    assert tokens[0].match == "just plain text"


def test_parse_no_regexs() -> None:
    text = (FIXTURES / "test_input.yaml").read_text()
    tokens = parse(text, [])
    assert len(tokens) == 1
    assert isinstance(tokens[0], NonMatchToken)


def test_parse_encrypted_yaml_token_count(private_key_pem: str, public_key_pem: str) -> None:
    text = (FIXTURES / "test_input.yaml").read_text()
    token_types = encrypted_token_types(decrypt_fn=make_decrypt_fn(private_key_pem, public_key_pem))
    tokens = parse(text, token_types)
    assert len(tokens) == 35


def test_parse_first_token_is_nonmatch(private_key_pem: str, public_key_pem: str) -> None:
    text = (FIXTURES / "test_input.yaml").read_text()
    token_types = encrypted_token_types(decrypt_fn=make_decrypt_fn(private_key_pem, public_key_pem))
    tokens = parse(text, token_types)
    assert isinstance(tokens[0], NonMatchToken)


def test_parse_second_token_is_enc(private_key_pem: str, public_key_pem: str) -> None:
    text = (FIXTURES / "test_input.yaml").read_text()
    token_types = encrypted_token_types(decrypt_fn=make_decrypt_fn(private_key_pem, public_key_pem))
    tokens = parse(text, token_types)

    token = tokens[1]
    assert isinstance(token, EncToken)
    assert token.match.startswith("ENC[PKCS7,MIIBiQYJKoZIhvcNAQ")
    assert token.plain_text == "planet of the apes"


def test_parse_indexed_decryption(private_key_pem: str, public_key_pem: str) -> None:
    """Matches Ruby parser.feature: 'Output indexed decryption tokens'."""
    text = (FIXTURES / "test_input.yaml").read_text()
    token_types = encrypted_token_types(decrypt_fn=make_decrypt_fn(private_key_pem, public_key_pem))
    tokens = parse(text, token_types)

    decrypted = [t.to_decrypted(index=i) for i, t in enumerate(tokens)]
    assert decrypted[1] == "DEC(1)::PKCS7[planet of the apes]!"
    assert decrypted[13] == "DEC(13)::PKCS7[the count of monte cristo]!"


def test_enc_token_to_encrypted_string() -> None:
    token = EncToken(
        format=TokenFormat.STRING,
        plain_text="hello",
        cipher="YWJjZGVm",
        match="ENC[PKCS7,YWJjZGVm]",
        tag="PKCS7",
    )
    assert token.to_encrypted() == "ENC[PKCS7,YWJjZGVm]"


def test_enc_token_to_encrypted_block() -> None:
    long_cipher = "A" * 200
    token = EncToken(
        format=TokenFormat.BLOCK,
        plain_text="hello",
        cipher=long_cipher,
        match="original",
        indentation="    ",
        tag="PKCS7",
    )
    result = token.to_encrypted()
    assert result.startswith(">\n    ENC[PKCS7,")
    lines = result.split("\n")
    # First line is ">", remaining lines are indented and <=64 chars (4 indent + 60 content)
    assert lines[0] == ">"
    for line in lines[1:]:
        assert len(line) <= 64


def test_enc_token_to_decrypted_string() -> None:
    token = EncToken(
        format=TokenFormat.STRING,
        plain_text="hello world",
        cipher="abc123",
        match="ENC[PKCS7,abc123]",
        tag="PKCS7",
    )
    assert token.to_decrypted() == "DEC::PKCS7[hello world]!"


def test_enc_token_to_decrypted_block() -> None:
    token = EncToken(
        format=TokenFormat.BLOCK,
        plain_text="hello world",
        cipher="abc123",
        match="original",
        indentation="    ",
        tag="PKCS7",
    )
    assert token.to_decrypted() == ">\n    DEC::PKCS7[hello world]!"


def test_enc_token_to_decrypted_with_index() -> None:
    token = EncToken(
        format=TokenFormat.STRING,
        plain_text="hello",
        cipher="abc",
        match="ENC[PKCS7,abc]",
        tag="PKCS7",
    )
    assert token.to_decrypted(index=5) == "DEC(5)::PKCS7[hello]!"


def test_enc_token_to_plain_text() -> None:
    token = EncToken(
        format=TokenFormat.STRING,
        plain_text="secret value",
        cipher="abc",
        match="ENC[PKCS7,abc]",
        tag="PKCS7",
    )
    assert token.to_plain_text() == "secret value"


def test_nonmatch_passthrough() -> None:
    token = NonMatchToken(match="plain text here")
    assert token.to_encrypted() == "plain text here"
    assert token.to_decrypted() == "plain text here"
    assert token.to_plain_text() == "plain text here"
