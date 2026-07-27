"""Sanitising command output before it is stored or displayed.

Everything that reaches this module is untrusted. It is the output of a program
that talked to a device on the network, and both the program and the device are
outside our control. Three separate problems are handled here:

* **Size.** A chatty command can produce megabytes. Unbounded capture is a
  memory problem in the process and a growth problem in the database.
* **Control characters.** ANSI escapes and terminal control sequences render as
  garbage at best. Some sequences can rewrite earlier output or manipulate the
  terminal of anyone who later ``cat``s a log.
* **Secrets.** A command may echo a password or a key. Autoescaping does not
  help with that — it has to be removed before the text is written anywhere.
"""

from __future__ import annotations

import re
from typing import Final

# CSI, OSC, and the single-character escapes. Written out rather than using a
# broad \x1b. matcher so the intent stays readable.
_ANSI = re.compile(
    r"""
    \x1B
    (?:
        \[ [0-?]* [ -/]* [@-~]      # CSI ... final byte
      | \] .*? (?: \x07 | \x1B\\ )  # OSC ... BEL or ST
      | [@-Z\\-_]                   # two-character escapes
    )
    """,
    re.VERBOSE | re.DOTALL,
)

# Everything in C0 except tab and newline, plus DEL and the C1 range. Carriage
# return is stripped too: it is what lets output overwrite earlier lines.
_CONTROL = re.compile(r"[\x00-\x08\x0B-\x1F\x7F-\x9F]")

DEFAULT_MAX_BYTES: Final = 256 * 1024
TRUNCATION_NOTICE: Final = "\n\n[output truncated — limit reached]"

# Patterns that look like a secret being echoed. Deliberately broad: a false
# positive costs a masked word in a diagnostic, a false negative writes a
# credential into the audit log permanently.
_SECRET_PATTERNS: Final = [
    # Consume the rest of the line, not just the next whitespace-delimited
    # token. `Authorization: Bearer <token>` would otherwise mask only the word
    # "Bearer" and write the token itself to the audit log, and a passphrase
    # containing a space would be half-masked for the same reason.
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*.+"),
    re.compile(r"(?i)\bauthorization\s*:\s*.+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{40,}"),
]

MASK: Final = "[redacted]"


def strip_control_characters(text: str) -> str:
    """Remove ANSI escapes and control characters, keeping tabs and newlines."""
    return _CONTROL.sub("", _ANSI.sub("", text))


def mask_secrets(text: str) -> str:
    """Mask anything that looks like a credential."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(MASK, text)
    return text


def redact_values(text: str, values: list[str]) -> str:
    """Remove specific known-secret strings.

    Used for parameters flagged ``secret``: we know the exact value, so this is
    exact rather than heuristic. Very short values are skipped — masking every
    occurrence of a two-character password would destroy the output without
    protecting anything meaningful.
    """
    for value in values:
        if value and len(value) >= 4:
            text = text.replace(value, MASK)
    return text


def truncate(text: str, max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[str, bool]:
    """Cap the text at a byte budget. Returns the text and whether it was cut.

    Measured in bytes rather than characters because the limit exists to bound
    memory and stored size, and cut on a character boundary so the result is
    always valid text.
    """
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text, False

    clipped = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return clipped + TRUNCATION_NOTICE, True


def sanitize(
    text: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    secret_values: list[str] | None = None,
) -> tuple[str, bool]:
    """Full pipeline: strip, mask, then truncate.

    Order matters. Stripping control characters first prevents an escape
    sequence from splitting a secret so the patterns miss it, and truncating
    last means the byte budget applies to what is actually stored.
    """
    cleaned = strip_control_characters(text)
    if secret_values:
        cleaned = redact_values(cleaned, secret_values)
    cleaned = mask_secrets(cleaned)
    return truncate(cleaned, max_bytes)
