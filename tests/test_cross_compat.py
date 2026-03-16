"""Cross-compatibility integration tests between Python hiera-eyaml and Ruby eyaml CLI.

Tests all four encrypt/decrypt interactions:
1. Python encrypts → Python decrypts (baseline)
2. Ruby encrypts → Ruby decrypts (baseline)
3. Python encrypts → Ruby decrypts
4. Ruby encrypts → Python decrypts

Requires: `eyaml` CLI installed (gem install hiera-eyaml).
"""

import shutil
import subprocess
from pathlib import Path

import pytest

import hiera_eyaml

FIXTURES = Path(__file__).parent / "fixtures"
KEYS = FIXTURES / "keys"

EYAML_BIN = shutil.which("eyaml")
SKIP_REASON = "eyaml CLI not installed (gem install hiera-eyaml)"

PLAINTEXT = "cross-compat-test-value-42"


@pytest.fixture
def public_key_pem() -> str:
    return (KEYS / "public_key.pkcs7.pem").read_text()


@pytest.fixture
def private_key_pem() -> str:
    return (KEYS / "private_key.pkcs7.pem").read_text()


@pytest.fixture
def public_key_path() -> Path:
    return KEYS / "public_key.pkcs7.pem"


@pytest.fixture
def private_key_path() -> Path:
    return KEYS / "private_key.pkcs7.pem"


def ruby_encrypt(plaintext: str, public_key_path: Path) -> str:
    result = subprocess.run(
        [
            "eyaml",
            "encrypt",
            "-o",
            "string",
            "-s",
            plaintext,
            "--pkcs7-public-key",
            str(public_key_path),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return result.stdout.strip()


def ruby_decrypt(
    encrypted: str, private_key_path: Path, public_key_path: Path
) -> str:
    result = subprocess.run(
        [
            "eyaml",
            "decrypt",
            "-s",
            encrypted,
            "--pkcs7-private-key",
            str(private_key_path),
            "--pkcs7-public-key",
            str(public_key_path),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return result.stdout.strip()


@pytest.mark.skipif(EYAML_BIN is None, reason=SKIP_REASON)
class TestCrossCompatibility:
    def test_python_encrypt_python_decrypt(
        self, public_key_pem: str, private_key_pem: str
    ) -> None:
        encrypted = hiera_eyaml.encrypt_value(PLAINTEXT, public_key_pem=public_key_pem)
        decrypted = hiera_eyaml.decrypt_value(
            encrypted,
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem,
        )
        assert decrypted == PLAINTEXT

    def test_ruby_encrypt_ruby_decrypt(
        self, public_key_path: Path, private_key_path: Path
    ) -> None:
        encrypted = ruby_encrypt(PLAINTEXT, public_key_path)
        decrypted = ruby_decrypt(encrypted, private_key_path, public_key_path)
        assert decrypted == PLAINTEXT

    def test_python_encrypt_ruby_decrypt(
        self,
        public_key_pem: str,
        public_key_path: Path,
        private_key_path: Path,
    ) -> None:
        encrypted = hiera_eyaml.encrypt_value(PLAINTEXT, public_key_pem=public_key_pem)
        decrypted = ruby_decrypt(encrypted, private_key_path, public_key_path)
        assert decrypted == PLAINTEXT

    def test_ruby_encrypt_python_decrypt(
        self,
        public_key_pem: str,
        private_key_pem: str,
        public_key_path: Path,
    ) -> None:
        encrypted = ruby_encrypt(PLAINTEXT, public_key_path)
        decrypted = hiera_eyaml.decrypt_value(
            encrypted,
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem,
        )
        assert decrypted == PLAINTEXT

    def test_python_encrypt_ruby_decrypt_multiline(
        self,
        public_key_pem: str,
        public_key_path: Path,
        private_key_path: Path,
    ) -> None:
        multiline = "line one\nline two\nline three"
        encrypted = hiera_eyaml.encrypt_value(multiline, public_key_pem=public_key_pem)
        decrypted = ruby_decrypt(encrypted, private_key_path, public_key_path)
        assert decrypted == multiline

    def test_ruby_encrypt_python_decrypt_multiline(
        self,
        public_key_pem: str,
        private_key_pem: str,
        public_key_path: Path,
    ) -> None:
        multiline = "line one\nline two\nline three"
        encrypted = ruby_encrypt(multiline, public_key_path)
        decrypted = hiera_eyaml.decrypt_value(
            encrypted,
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem,
        )
        assert decrypted == multiline

    def test_python_encrypt_ruby_decrypt_special_chars(
        self,
        public_key_pem: str,
        public_key_path: Path,
        private_key_path: Path,
    ) -> None:
        special = "p@ssw0rd!#$%^&*(){}[]|\\:\";<>?,./~`"
        encrypted = hiera_eyaml.encrypt_value(special, public_key_pem=public_key_pem)
        decrypted = ruby_decrypt(encrypted, private_key_path, public_key_path)
        assert decrypted == special

    def test_ruby_encrypt_python_decrypt_special_chars(
        self,
        public_key_pem: str,
        private_key_pem: str,
        public_key_path: Path,
    ) -> None:
        special = "p@ssw0rd!#$%^&*(){}[]|\\:\";<>?,./~`"
        encrypted = ruby_encrypt(special, public_key_path)
        decrypted = hiera_eyaml.decrypt_value(
            encrypted,
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem,
        )
        assert decrypted == special

    def test_python_encrypt_ruby_decrypt_empty(
        self,
        public_key_pem: str,
        public_key_path: Path,
        private_key_path: Path,
    ) -> None:
        encrypted = hiera_eyaml.encrypt_value("", public_key_pem=public_key_pem)
        decrypted = ruby_decrypt(encrypted, private_key_path, public_key_path)
        assert decrypted == ""

    def test_ruby_encrypt_python_decrypt_empty(
        self,
        public_key_pem: str,
        private_key_pem: str,
        public_key_path: Path,
    ) -> None:
        encrypted = ruby_encrypt("", public_key_path)
        decrypted = hiera_eyaml.decrypt_value(
            encrypted,
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem,
        )
        assert decrypted == ""

    def test_ruby_encrypt_python_decrypt_unicode(
        self,
        public_key_pem: str,
        private_key_pem: str,
        public_key_path: Path,
    ) -> None:
        unicode_text = "héllo wörld 日本語 🔐"
        encrypted = ruby_encrypt(unicode_text, public_key_path)
        decrypted = hiera_eyaml.decrypt_value(
            encrypted,
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem,
        )
        assert decrypted == unicode_text

    def test_python_encrypt_ruby_decrypt_unicode(
        self,
        public_key_pem: str,
        public_key_path: Path,
        private_key_path: Path,
    ) -> None:
        unicode_text = "héllo wörld 日本語 🔐"
        encrypted = hiera_eyaml.encrypt_value(
            unicode_text, public_key_pem=public_key_pem
        )
        decrypted = ruby_decrypt(encrypted, private_key_path, public_key_path)
        assert decrypted == unicode_text
