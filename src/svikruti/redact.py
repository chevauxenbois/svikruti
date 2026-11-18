"""Runtime redaction: strip personal data from text before it leaves the process.

Static analysis can say that a log line or a prompt *may* carry personal data.
This module removes it at runtime, with no dependencies beyond the standard
library, and the scanner recognises it as protection:

    from svikruti.redact import redact, redact_messages, install_logging_redaction

    install_logging_redaction()                     # every stdlib logging record, process-wide
    logger.info("refund for %s", customer.email)    # -> "refund for [EMAIL]"

    client.chat.completions.create(model="gpt-4o", messages=redact_messages(messages))
    redact("Call 9876543210, Aadhaar 2345 6789 0124")  # -> "Call [PHONE], Aadhaar [AADHAAR]"

Detectors are validated, not just shaped: Aadhaar numbers must pass the
Verhoeff checksum, card numbers the Luhn check, IBANs the mod-97 check, PANs
the holder-type letter. A 12-digit order id is left alone.

Styles: ``label`` (default) replaces with ``[EMAIL]``; ``partial`` keeps the
last four characters (``[PHONE ...3210]``); ``hash`` replaces with a keyed
SHA-256 prefix (``[EMAIL:9f2c1a7b]``) so the same value still joins across
log lines without being readable. Set ``SVIKRUTI_REDACT_KEY`` (or pass
``key=``) for the hash style; without a key the hash is unkeyed.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

__all__ = [
    "KINDS",
    "Match",
    "find",
    "redact",
    "redact_value",
    "redact_messages",
    "RedactingFilter",
    "install_logging_redaction",
    "uninstall_logging_redaction",
]


@dataclass(frozen=True)
class Match:
    kind: str
    start: int
    end: int
    value: str


# ------------------------------------------------------------------ checks
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _verhoeff(digits: str) -> bool:
    check = 0
    for index, char in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][int(char)]]
    return check == 0


def _luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _iban(value: str) -> bool:
    compact = value.replace(" ", "").upper()
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    return int(numeric) % 97 == 1


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


# --------------------------------------------------------------- detectors
# Order matters: earlier kinds win where matches overlap (a card number is not also a phone).
_DETECTORS: List[tuple] = [
    ("EMAIL", re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])"), None),
    ("IBAN", re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Z0-9])"), _iban),
    ("CARD", re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"), lambda value: 13 <= len(_digits(value)) <= 19 and _luhn(_digits(value))),
    ("AADHAAR", re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"), lambda value: _verhoeff(_digits(value))),
    ("PAN", re.compile(r"(?<![A-Z0-9])[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z](?![A-Z0-9])"), None),
    ("IFSC", re.compile(r"(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])"), None),
    ("UPI", re.compile(r"(?<![\w.+-])[A-Za-z0-9._-]{2,}@[A-Za-z]{2,}(?![\w.@-])"), None),
    ("SSN", re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)"), None),
    ("PHONE", re.compile(r"(?<![\w+])(?:\+91[ -]?|0091[ -]?|0)?[6-9]\d{4}[ -]?\d{5}(?!\d)|(?<![\w+])\+(?:[1-9]\d{0,2})[ -]?(?:\(?\d{1,4}\)?[ -]?){2,4}\d{2,4}(?!\d)"), lambda value: 10 <= len(_digits(value)) <= 15),
    ("IP", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"), lambda value: not value.startswith(("0.", "127.")) and value != "255.255.255.255"),
]
KINDS = tuple(kind for kind, _, _ in _DETECTORS)


def find(text: str, kinds: Optional[Iterable[str]] = None) -> List[Match]:
    """Personal data in ``text``, non-overlapping, in order of position."""
    if not text:
        return []
    wanted = {kind.upper() for kind in kinds} if kinds else set(KINDS)
    taken: List[Match] = []
    for kind, pattern, check in _DETECTORS:
        if kind not in wanted:
            continue
        for found in pattern.finditer(text):
            value = found.group(0)
            if check is not None and not check(value):
                continue
            if any(found.start() < other.end and other.start < found.end() for other in taken):
                continue
            if kind == "IP" and re.search(r"(?:version|ver|release|build|v)[\s:=]*$", text[max(0, found.start() - 12) : found.start()], re.IGNORECASE):
                continue  # version 1.2.3.4 is a version, not an address
            taken.append(Match(kind, found.start(), found.end(), value))
    return sorted(taken, key=lambda match: match.start)


def _replacement(match: Match, style: str, key: Optional[bytes]) -> str:
    if style == "partial":
        tail = re.sub(r"[\s-]", "", match.value)[-4:]
        return f"[{match.kind} ...{tail}]"
    if style == "hash":
        normalised = re.sub(r"[\s-]", "", match.value).lower().encode("utf-8")
        digest = hmac.new(key, normalised, hashlib.sha256).hexdigest() if key else hashlib.sha256(normalised).hexdigest()
        return f"[{match.kind}:{digest[:8]}]"
    return f"[{match.kind}]"


def redact(text: Any, kinds: Optional[Iterable[str]] = None, style: str = "label", key: Optional[str] = None) -> Any:
    """``text`` with personal data replaced. Non-strings are returned unchanged."""
    if not isinstance(text, str) or not text:
        return text
    if style not in {"label", "partial", "hash"}:
        raise ValueError("style must be 'label', 'partial' or 'hash'")
    secret = (key or os.environ.get("SVIKRUTI_REDACT_KEY") or "").encode("utf-8") or None
    out, cursor = [], 0
    for match in find(text, kinds):
        out.append(text[cursor : match.start])
        out.append(_replacement(match, style, secret))
        cursor = match.end
    out.append(text[cursor:])
    return "".join(out)


def redact_value(value: Any, kinds: Optional[Iterable[str]] = None, style: str = "label", key: Optional[str] = None, _depth: int = 0) -> Any:
    """Redact strings anywhere inside dicts, lists and tuples (JSON payloads, tool arguments)."""
    if _depth > 20:
        return value
    if isinstance(value, str):
        return redact(value, kinds, style, key)
    if isinstance(value, dict):
        return {k: redact_value(v, kinds, style, key, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        items = [redact_value(v, kinds, style, key, _depth + 1) for v in value]
        return type(value)(items) if isinstance(value, tuple) else items
    return value


def redact_messages(messages: Sequence[Any], kinds: Optional[Iterable[str]] = None, style: str = "label", key: Optional[str] = None) -> List[Any]:
    """Chat messages with personal data removed from their content.

    Accepts OpenAI / Anthropic / Gemini shapes: ``{"role", "content": str}``,
    content as a list of parts (``{"type": "text", "text": ...}``), Gemini
    ``{"parts": [{"text": ...}]}``, or plain strings. Images and tool calls
    are passed through; only text is rewritten. The input is not modified.
    """
    out: List[Any] = []
    for message in messages:
        if isinstance(message, str):
            out.append(redact(message, kinds, style, key))
        elif isinstance(message, dict):
            copy = dict(message)
            for field_name in ("content", "parts", "text"):
                if field_name in copy:
                    copy[field_name] = redact_value(copy[field_name], kinds, style, key)
            out.append(copy)
        else:
            content = getattr(message, "content", None)
            out.append(type(message)(**{**vars(message), "content": redact_value(content, kinds, style, key)}) if content is not None and hasattr(message, "__dict__") else message)
    return out


# ----------------------------------------------------------------- logging
class RedactingFilter(logging.Filter):
    """A logging filter that rewrites each record's message with personal data removed.

    Attach it to a handler (``handler.addFilter(RedactingFilter())``) or use
    :func:`install_logging_redaction` to cover every logger in the process.
    """

    def __init__(self, kinds: Optional[Iterable[str]] = None, style: str = "label", key: Optional[str] = None):
        super().__init__()
        self.kinds, self.style, self.key = kinds, style, key

    def filter(self, record: logging.LogRecord) -> bool:
        _scrub_record(record, self.kinds, self.style, self.key)
        return True


def _scrub_record(record: logging.LogRecord, kinds: Optional[Iterable[str]], style: str, key: Optional[str]) -> None:
    if getattr(record, "_svikruti_redacted", False):
        return
    try:
        message = record.getMessage()
    except Exception:  # a bad format string is logging's problem, not ours
        message = str(record.msg)
    record.msg = redact(message, kinds, style, key)
    record.args = ()
    if record.exc_info and not record.exc_text:
        record.exc_text = logging.Formatter().formatException(record.exc_info)
    if record.exc_text:
        record.exc_text = redact(record.exc_text, kinds, style, key)
    record._svikruti_redacted = True  # type: ignore[attr-defined]


_ORIGINAL_FACTORY: Optional[Callable[..., logging.LogRecord]] = None


def install_logging_redaction(kinds: Optional[Iterable[str]] = None, style: str = "label", key: Optional[str] = None) -> None:
    """Redact every stdlib ``logging`` record created anywhere in the process.

    Installs a log-record factory, so it covers loggers and handlers created
    before or after the call, including third-party libraries. Call it once at
    start-up. ``svikruti check`` treats Python logging findings as mitigated
    when this call is present in the repository.
    """
    global _ORIGINAL_FACTORY
    if _ORIGINAL_FACTORY is not None:
        return
    original = logging.getLogRecordFactory()
    _ORIGINAL_FACTORY = original

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = original(*args, **kwargs)
        _scrub_record(record, kinds, style, key)
        return record

    logging.setLogRecordFactory(factory)


def uninstall_logging_redaction() -> None:
    global _ORIGINAL_FACTORY
    if _ORIGINAL_FACTORY is not None:
        logging.setLogRecordFactory(_ORIGINAL_FACTORY)
        _ORIGINAL_FACTORY = None


def summary(text: str) -> Dict[str, int]:
    """How many of each kind ``text`` contains (for tests and audits)."""
    counts: Dict[str, int] = {}
    for match in find(text):
        counts[match.kind] = counts.get(match.kind, 0) + 1
    return counts
