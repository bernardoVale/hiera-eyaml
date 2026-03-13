import base64
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def load_key(
    *,
    path: str | Path | None = None,
    env_var: str | None = None,
    b64_env_var: str | None = None,
) -> str:
    """Load a PEM key from file, environment variable, or base64-encoded env var.

    Priority: env_var > b64_env_var > path

    Raises ValueError if no source is configured or the source is missing.
    """
    if path and env_var:
        logger.warning(
            "both key path and env var specified, preferring env var %s", env_var
        )

    if env_var:
        value = os.environ.get(env_var)
        if value is None:
            raise ValueError(f"environment variable {env_var} is not set")
        return value

    if b64_env_var:
        value = os.environ.get(b64_env_var)
        if value is None:
            raise ValueError(f"environment variable {b64_env_var} is not set")
        return base64.b64decode(value).decode("utf-8")

    if path:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"key file {p} does not exist")
        return p.read_text()

    raise ValueError("no key source configured: provide path, env_var, or b64_env_var")
