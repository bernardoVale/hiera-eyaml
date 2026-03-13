from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable


class TokenFormat(str, Enum):
    STRING = "string"
    BLOCK = "block"


@dataclass
class NonMatchToken:
    """Text that doesn't match any encrypted/decrypted pattern."""

    match: str

    def to_encrypted(self) -> str:
        return self.match

    def to_decrypted(self, index: int | None = None) -> str:
        return self.match

    def to_plain_text(self) -> str:
        return self.match


@dataclass
class EncToken:
    """An encrypted or decrypted value token."""

    format: TokenFormat
    plain_text: str
    cipher: str
    match: str
    indentation: str = ""
    tag: str = "PKCS7"

    def to_encrypted(self) -> str:
        if self.format == TokenFormat.BLOCK:
            clean_cipher = self.cipher.replace(" ", "").replace("\n", "").replace("\r", "")
            enc_str = f"ENC[{self.tag},{clean_cipher}]"
            lines = [enc_str[i : i + 60] for i in range(0, len(enc_str), 60)]
            return ">\n" + self.indentation + ("\n" + self.indentation).join(lines)

        clean_cipher = self.cipher.replace("\n", "").replace("\r", "")
        return f"ENC[{self.tag},{clean_cipher}]"

    def to_decrypted(self, index: int | None = None) -> str:
        index_str = f"({index})" if index is not None else ""
        dec_str = f"DEC{index_str}::{self.tag}[{self.plain_text}]!"

        if self.format == TokenFormat.BLOCK:
            return ">\n" + self.indentation + dec_str

        return dec_str

    def to_plain_text(self) -> str:
        return self.plain_text


Token = NonMatchToken | EncToken

ENC_STRING_REGEX = re.compile(r"ENC\[(\w+,)?([a-zA-Z0-9+/=]+?)\]")
ENC_BLOCK_REGEX = re.compile(r">\n(\s*)ENC\[(\w+,)?([a-zA-Z0-9+/=\s]+?)\]")


@dataclass
class TokenType:
    regex: re.Pattern[str]
    create_token: Callable[[str], Token]


def _create_enc_string_token(
    string: str, *, decrypt_fn: Callable[[str, str], str]
) -> EncToken:
    md = ENC_STRING_REGEX.search(string)
    assert md is not None
    enc_comma = md.group(1)
    cipher = md.group(2)
    tag = enc_comma.rstrip(",") if enc_comma else "PKCS7"
    plain_text = decrypt_fn(tag, cipher)
    return EncToken(
        format=TokenFormat.STRING,
        plain_text=plain_text,
        cipher=cipher,
        match=string,
        tag=tag,
    )


def _create_enc_block_token(
    string: str, *, decrypt_fn: Callable[[str, str], str]
) -> EncToken:
    md = ENC_BLOCK_REGEX.search(string)
    assert md is not None
    indentation = md.group(1)
    enc_comma = md.group(2)
    cipher = md.group(3)
    tag = enc_comma.rstrip(",") if enc_comma else "PKCS7"
    plain_text = decrypt_fn(tag, cipher)
    return EncToken(
        format=TokenFormat.BLOCK,
        plain_text=plain_text,
        cipher=cipher,
        match=string,
        indentation=indentation,
        tag=tag,
    )


def encrypted_token_types(*, decrypt_fn: Callable[[str, str], str]) -> list[TokenType]:
    """Token types for parsing ENC[...] markers."""

    def string_factory(s: str) -> Token:
        return _create_enc_string_token(s, decrypt_fn=decrypt_fn)

    def block_factory(s: str) -> Token:
        return _create_enc_block_token(s, decrypt_fn=decrypt_fn)

    return [
        TokenType(regex=ENC_STRING_REGEX, create_token=string_factory),
        TokenType(regex=ENC_BLOCK_REGEX, create_token=block_factory),
    ]


def parse(text: str, token_types: list[TokenType]) -> list[Token]:
    """Parse text into a list of tokens using the given token type regexes.

    Algorithm (matches Ruby's parse_scanner):
    1. At current position, check if any token type regex matches
    2. If yes -> create the token, advance position
    3. If no -> find the nearest match, emit NonMatchToken for text before it
    4. Repeat until end of text
    """
    tokens: list[Token] = []
    pos = 0

    while pos < len(text):
        current_match = None
        for tt in token_types:
            m = tt.regex.match(text, pos)
            if m:
                current_match = (tt, m)
                break

        if current_match:
            tt, m = current_match
            tokens.append(tt.create_token(m.group(0)))
            pos = m.end()
            continue

        nearest_pos = len(text)
        for tt in token_types:
            m = tt.regex.search(text, pos)
            if m and m.start() < nearest_pos:
                nearest_pos = m.start()

        tokens.append(NonMatchToken(match=text[pos:nearest_pos]))
        pos = nearest_pos

    return tokens
