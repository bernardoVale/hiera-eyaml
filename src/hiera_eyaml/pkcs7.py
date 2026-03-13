import base64
import datetime
import logging
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

TAG = "PKCS7"


def encrypt(plaintext: bytes, public_key_pem: str) -> bytes:
    """Encrypt plaintext using PKCS7 envelope encryption with AES-256-CBC.

    Returns DER-encoded PKCS7 envelope bytes.
    """
    cert = _load_certificate(public_key_pem)

    return (
        pkcs7.PKCS7EnvelopeBuilder()
        .set_data(plaintext)
        .set_content_encryption_algorithm(algorithms.AES256)
        .add_recipient(cert)
        .encrypt(serialization.Encoding.DER, [])
    )


def decrypt(ciphertext: bytes, private_key_pem: str, public_key_pem: str) -> bytes:
    """Decrypt PKCS7 DER-encoded ciphertext.

    Returns decrypted plaintext bytes.
    """
    cert = _load_certificate(public_key_pem)
    pem_bytes = private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem
    private_key = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(private_key, RSAPrivateKey):
        raise ValueError("only RSA private keys are supported")

    return pkcs7.pkcs7_decrypt_der(ciphertext, cert, private_key, [])


def encode(data: bytes) -> str:
    """Base64 strict encode (no line breaks)."""
    return base64.b64encode(data).decode("ascii")


def decode(string: str) -> bytes:
    """Base64 decode."""
    return base64.b64decode(string)


def _load_certificate(pem: str) -> x509.Certificate:
    """Load a certificate from PEM string.

    Supports both X.509 certificate format (BEGIN CERTIFICATE) and
    raw public key format (BEGIN PUBLIC KEY) — for the latter, a
    self-signed certificate is synthesized wrapping the public key.
    """
    pem_bytes = pem.encode() if isinstance(pem, str) else pem

    if b"BEGIN CERTIFICATE" in pem_bytes:
        with warnings.catch_warnings():
            # Ruby hiera-eyaml generates certs with serial=0, violating RFC 5280.
            # This is harmless for PKCS7 envelope encryption — suppress the warning.
            warnings.filterwarnings("ignore", message=".*serial number.*", category=UserWarning)
            return x509.load_pem_x509_certificate(pem_bytes)

    if b"BEGIN PUBLIC KEY" in pem_bytes:
        public_key = serialization.load_pem_public_key(pem_bytes)
        if not isinstance(public_key, RSAPublicKey):
            raise ValueError("only RSA public keys are supported")
        return _create_self_signed_cert(public_key)

    raise ValueError("invalid public key format: expected BEGIN CERTIFICATE or BEGIN PUBLIC KEY")


def _create_self_signed_cert(public_key: rsa.RSAPublicKey) -> x509.Certificate:
    """Create a minimal self-signed certificate wrapping a public key.

    This is needed because PKCS7 envelope encryption requires an X.509
    certificate. When only a raw public key is provided, we synthesize one.

    We generate a throwaway RSA key to sign the cert — the signature is
    irrelevant for PKCS7 envelope encryption, only the embedded public key
    matters for encrypting the symmetric key.
    """
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "hiera-eyaml"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(signing_key, hashes.SHA256())
    )
