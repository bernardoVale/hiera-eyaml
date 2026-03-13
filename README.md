## hiera-eyaml

Python library for encrypting and decrypting [hiera-eyaml](https://github.com/voxpupuli/hiera-eyaml) values. Cross-compatible with the Ruby gem — files encrypted by Ruby can be decrypted by Python and vice versa.

### Installation

```bash
pip install hiera-eyaml
# or
uv add hiera-eyaml
```

### Usage

```python
import hiera_eyaml

# Load keys from files
public_key = hiera_eyaml.load_key(path="keys/public_key.pkcs7.pem")
private_key = hiera_eyaml.load_key(path="keys/private_key.pkcs7.pem")

# Encrypt a value
encrypted = hiera_eyaml.encrypt_value("my secret", public_key_pem=public_key)
# => "ENC[PKCS7,MIIBiQYJKoZI...]"

# Decrypt a value
plain = hiera_eyaml.decrypt_value(encrypted, private_key_pem=private_key, public_key_pem=public_key)
# => "my secret"

# Decrypt all ENC[...] markers in a file
plain_yaml = hiera_eyaml.decrypt_file(
    "secrets.eyaml",
    private_key_pem=private_key,
    public_key_pem=public_key,
)

# Decrypt with DEC::PKCS7[...]! markers (eyaml format)
eyaml_output = hiera_eyaml.decrypt_text(
    yaml_text,
    private_key_pem=private_key,
    public_key_pem=public_key,
    eyaml=True,
)
```

### Key loading

Keys can be loaded from files, environment variables, or base64-encoded environment variables:

```python
# From file
key = hiera_eyaml.load_key(path="/path/to/key.pem")

# From environment variable (PEM string)
key = hiera_eyaml.load_key(env_var="EYAML_PUBLIC_KEY")

# From base64-encoded environment variable
key = hiera_eyaml.load_key(b64_env_var="EYAML_PUBLIC_KEY_B64")
```

Priority: `env_var` > `b64_env_var` > `path`.

### Key generation

This library does not generate keys. Use OpenSSL:

```bash
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout private_key.pkcs7.pem \
  -out public_key.pkcs7.pem \
  -batch
```

Or the Ruby gem: `eyaml createkeys`.

### What this library does NOT support

- **CLI** — use the Ruby gem for command-line usage
- **Plugin system** — only PKCS7 encryption
- **Re-encryption / edit mode** — no `DEC → ENC` conversion
- **Hiera backend** — no Puppet integration
- **Config file loading** — all configuration via function parameters
