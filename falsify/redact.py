"""Sanitize text that originates in untrusted execution before it is persisted or shown.

This is a second layer behind `toolpaths.subprocess_env`, which keeps host secrets out of
tool subprocesses in the first place. It applies only at output boundaries (artifacts,
reports), never to data the oracle uses for decisions: exploit success comes from the test
status, not from the revert text.
"""

from __future__ import annotations

import os
import re

#: Default cap for one revert reason. Bounds artifact size and leaves room for a decoded
#: custom error with arguments; the selector, at the start, always survives truncation.
REASON_LIMIT = 512

# Host variables whose values are known not to be secret. Every other value of at least
# _MIN_SECRET_LEN characters is treated as potentially sensitive and redacted on sight.
_PUBLIC_VARS = frozenset({
    "PATH", "HOME", "PWD", "OLDPWD", "SHELL", "USER", "LOGNAME", "TMPDIR", "TERM",
    "TERM_PROGRAM", "LANG", "SOLC_VERSION", "VIRTUAL_ENV", "PYTHONPATH", "SHLVL", "_",
})
_MIN_SECRET_LEN = 8

# Credential formats with distinctive prefixes, so they are redacted even when they were
# never in this process's environment. Bare hex is deliberately excluded: hashes, keys and
# bytes32 arguments of custom errors look identical, and redacting them would destroy the
# information a reader needs to understand a revert.
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
               re.DOTALL),
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}"),          # common API-key format
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}"),  # GitHub tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),               # AWS access key IDs
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),              # Slack tokens
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),  # JWTs
]

# ANSI escape sequences, other C0/C1 controls, and bidirectional overrides that can
# rewrite what a terminal or code review shows.
_ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|[@-Z\\-_])")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
_WHITESPACE = re.compile(r"[\t\n\r]+")


def _sensitive_values() -> list[tuple[str, str]]:
    """(name, value) for host variables that may hold secrets, longest value first."""
    pairs = [(k, v) for k, v in os.environ.items()
             if k not in _PUBLIC_VARS and not k.startswith("LC_") and len(v) >= _MIN_SECRET_LEN]
    return sorted(pairs, key=lambda kv: len(kv[1]), reverse=True)


def redact(text: str) -> str:
    """Replace host secret values (raw or hex-encoded) and known credential formats."""
    for name, value in _sensitive_values():
        marker = f"[redacted:{name}]"
        text = text.replace(value, marker)
        hexed = value.encode().hex()
        text = re.sub(re.escape(hexed), marker, text, flags=re.IGNORECASE)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


def sanitize(text: str, limit: int = REASON_LIMIT) -> str:
    """Redact, strip control characters, redact again, then cap length.

    The second pass catches a secret split by control characters that stripping rejoined.
    """
    if not text:
        return text
    text = redact(text)
    text = _ANSI.sub("", text)
    text = _WHITESPACE.sub(" ", text)
    text = _CONTROL.sub("", text)
    text = redact(text)
    if len(text) > limit:
        text = f"{text[:limit]}...[{len(text) - limit} more chars]"
    return text
