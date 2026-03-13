from pathlib import Path

import pytest

from hiera_eyaml import pkcs7

FIXTURES = Path(__file__).parent / "fixtures"
KEYS = FIXTURES / "keys"


@pytest.fixture
def public_key_pem() -> str:
    return (KEYS / "public_key.pkcs7.pem").read_text()


@pytest.fixture
def private_key_pem() -> str:
    return (KEYS / "private_key.pkcs7.pem").read_text()


def test_encrypt_decrypt_roundtrip(public_key_pem: str, private_key_pem: str) -> None:
    plaintext = b"hello world from python"
    ciphertext = pkcs7.encrypt(plaintext, public_key_pem)
    result = pkcs7.decrypt(ciphertext, private_key_pem, public_key_pem)
    assert result == plaintext


def test_encrypt_decrypt_empty_string(public_key_pem: str, private_key_pem: str) -> None:
    plaintext = b""
    ciphertext = pkcs7.encrypt(plaintext, public_key_pem)
    result = pkcs7.decrypt(ciphertext, private_key_pem, public_key_pem)
    assert result == plaintext


def test_encrypt_decrypt_unicode(public_key_pem: str, private_key_pem: str) -> None:
    plaintext = "héllo wörld 🌍".encode("utf-8")
    ciphertext = pkcs7.encrypt(plaintext, public_key_pem)
    result = pkcs7.decrypt(ciphertext, private_key_pem, public_key_pem)
    assert result == plaintext


def test_decrypt_ruby_encrypted_value(private_key_pem: str, public_key_pem: str) -> None:
    """Decrypt a value known to have been encrypted by Ruby hiera-eyaml."""
    ruby_cipher_b64 = (
        "MIIBiQYJKoZIhvcNAQcDoIIBejCCAXYCAQAxggEhMIIBHQIBADAFMAACAQAw"
        "DQYJKoZIhvcNAQEBBQAEggEAgld+rftjW8WmMwTJLX/3Kk9hQv9ZUufsieij"
        "xhnCo3gtR/6xaKdMC4wpYM9Eck7FFdmjz2XnJK9o5rlvjW5ZBH3u2A3tphs6"
        "cgy7HzsfrsJvw1Mc+CLSNL35MVi/YvNCxezn+rXn28NW8NntByoLTzZnd6iGx"
        "SBk4S7Z7XwvdQWuUjXy0muEeAUYtS/eppNZYdyeMpzE9oHmfMM+zwdOYzc/n"
        "fwvnoLHGP+sv6KmnzCyNtqyrdvCIn+m+ljPWpGvj410Q52Xili1Scgi+ALJf4"
        "xiEnD5c5YjEkYY8uUe4etCDYZ/aXp9RGvZiHD8Le6jz34fcWbLZlQacCfgcyY"
        "8AzBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBD4CRz8QLvbtgRx/NTxEnpf"
        "gCBLQD1ei8KAcd0LTT7sezZPt6LQnLxPuwx5StflI5xOgA=="
    )
    ciphertext = pkcs7.decode(ruby_cipher_b64)
    result = pkcs7.decrypt(ciphertext, private_key_pem, public_key_pem)
    assert result == b"planet of the apes"


def test_decrypt_ruby_encrypted_file(private_key_pem: str, public_key_pem: str) -> None:
    """Decrypt the test_input.encrypted.txt fixture from Ruby."""
    enc_text = (FIXTURES / "test_input.encrypted.txt").read_text().strip()
    # Extract base64 from ENC[PKCS7,...] wrapper
    assert enc_text.startswith("ENC[PKCS7,")
    cipher_b64 = enc_text[len("ENC[PKCS7,") : -1]
    ciphertext = pkcs7.decode(cipher_b64)
    result = pkcs7.decrypt(ciphertext, private_key_pem, public_key_pem)
    assert result == b"danger will robinson"


def test_encode_decode_roundtrip() -> None:
    data = b"some binary data \x00\x01\x02"
    encoded = pkcs7.encode(data)
    assert isinstance(encoded, str)
    assert pkcs7.decode(encoded) == data


def test_load_certificate_from_cert_pem(public_key_pem: str) -> None:
    from cryptography import x509

    cert = pkcs7._load_certificate(public_key_pem)
    assert isinstance(cert, x509.Certificate)


def test_load_certificate_from_public_key_pem(
    public_key_pem: str, private_key_pem: str
) -> None:
    """Extract the public key from the cert, re-wrap as BEGIN PUBLIC KEY, and
    verify we can still encrypt/decrypt with the synthesized cert."""
    from cryptography import x509

    cert = pkcs7._load_certificate(public_key_pem)
    pub_key = cert.public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub_pem = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    assert "BEGIN PUBLIC KEY" in pub_pem

    synth_cert = pkcs7._load_certificate(pub_pem)
    assert isinstance(synth_cert, x509.Certificate)

    # Encrypt with synthesized cert, decrypt with original cert + private key
    plaintext = b"test with public key format"
    ciphertext = pkcs7.encrypt(plaintext, pub_pem)

    # Decrypt requires the cert that matches the PKCS7 recipient info,
    # so we need to use the same synthesized cert for decryption too.
    # However, in practice users would encrypt with pub key and decrypt
    # with the original cert. Let's test that round-trip with same cert.
    result = pkcs7.decrypt(ciphertext, private_key_pem, pub_pem)
    assert result == plaintext


def test_load_certificate_invalid_format() -> None:
    with pytest.raises(ValueError, match="invalid public key format"):
        pkcs7._load_certificate("not a pem")
