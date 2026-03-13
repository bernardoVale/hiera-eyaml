from __future__ import annotations

import base64
from collections.abc import Callable

from hiera_eyaml import parser, pkcs7
from hiera_eyaml.keys import load_key
from hiera_eyaml.parser import TokenFormat

__all__ = [
    "decrypt_value",
    "encrypt_value",
    "decrypt_file",
    "decrypt_text",
    "load_key",
]


def _make_decrypt_fn(
    private_key_pem: str, public_key_pem: str
) -> Callable[[str, str], str]:
    def decrypt_fn(tag: str, cipher_b64: str) -> str:
        if tag != "PKCS7":
            return base64.b64decode(cipher_b64).decode("utf-8")
        cipher_bytes = pkcs7.decode(cipher_b64)
        plain_bytes = pkcs7.decrypt(cipher_bytes, private_key_pem, public_key_pem)
        return plain_bytes.decode("utf-8")

    return decrypt_fn


def decrypt_value(
    encrypted_string: str,
    *,
    private_key_pem: str,
    public_key_pem: str,
) -> str:
    """Decrypt a single ENC[PKCS7,...] string, returning the plaintext."""
    decrypt_fn = _make_decrypt_fn(private_key_pem, public_key_pem)
    token_types = parser.encrypted_token_types(decrypt_fn=decrypt_fn)
    tokens = parser.parse(encrypted_string, token_types)
    return "".join(t.to_plain_text() for t in tokens)


def encrypt_value(
    plaintext: str,
    *,
    public_key_pem: str,
    output: TokenFormat = TokenFormat.STRING,
) -> str:
    """Encrypt a plaintext string, returning ENC[PKCS7,...] format."""
    cipher_bytes = pkcs7.encrypt(plaintext.encode("utf-8"), public_key_pem)
    cipher_b64 = pkcs7.encode(cipher_bytes)

    if output == TokenFormat.BLOCK:
        enc_str = f"ENC[PKCS7,{cipher_b64}]"
        lines = [enc_str[i : i + 60] for i in range(0, len(enc_str), 60)]
        indentation = "    "
        return ">\n" + indentation + ("\n" + indentation).join(lines)

    return f"ENC[PKCS7,{cipher_b64}]"


def decrypt_text(
    text: str,
    *,
    private_key_pem: str,
    public_key_pem: str,
    eyaml: bool = False,
) -> str:
    """Decrypt all ENC[PKCS7,...] markers in a text string.

    If eyaml=False: encrypted values are replaced with plain text.
    If eyaml=True: encrypted values are replaced with DEC::PKCS7[plaintext]! markers.
    """
    decrypt_fn = _make_decrypt_fn(private_key_pem, public_key_pem)
    token_types = parser.encrypted_token_types(decrypt_fn=decrypt_fn)
    tokens = parser.parse(text, token_types)

    if eyaml:
        parts: list[str] = []
        for i, token in enumerate(tokens):
            if isinstance(token, parser.EncToken):
                parts.append(token.to_decrypted(index=i))
            else:
                parts.append(token.to_decrypted())
        return "".join(parts)

    return "".join(t.to_plain_text() for t in tokens)


def decrypt_file(
    path: str,
    *,
    private_key_pem: str,
    public_key_pem: str,
    eyaml: bool = False,
) -> str:
    """Decrypt all ENC[PKCS7,...] markers in a file."""
    from pathlib import Path

    text = Path(path).read_text()
    return decrypt_text(
        text,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        eyaml=eyaml,
    )
