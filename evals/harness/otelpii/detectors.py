"""Load the detector catalog (`detectors.toml`) and match keys and values against it."""

from __future__ import annotations

import base64
import binascii
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DETECTORS_PATH: Path = Path(__file__).resolve().parent.parent / "detectors.toml"

TARGETS = ("key", "value")
KINDS = ("credential", "pii", "quasi")
SEVERITIES = ("critical", "high", "medium")
VALIDATORS = ("none", "luhn", "jwt", "basic")
ACTIONS = ("mask", "hmac", "drop", "truncate_ip")

_ENUM_FIELDS = {
    "target": TARGETS,
    "kind": KINDS,
    "severity": SEVERITIES,
    "validator": VALIDATORS,
    "action": ACTIONS,
}
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


@dataclass(frozen=True)
class Detector:
    id: str
    target: str
    kind: str
    severity: str
    pattern: str
    ignore_case: bool
    validator: str
    action: str
    regex: re.Pattern


def load_detectors(path: Path | None = None) -> list[Detector]:
    """Parse and validate a detector catalog. Invalid entries raise ValueError naming the field."""
    path = Path(path) if path is not None else DEFAULT_DETECTORS_PATH
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    entries = data.get("detector")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path}: no [[detector]] entries")
    detectors: list[Detector] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        detectors.append(_parse_entry(entry, f"{path}: detector[{index}]"))
        det_id = detectors[-1].id
        if det_id in seen:
            raise ValueError(f"{path}: detector[{index}].id duplicate id {det_id!r}")
        seen.add(det_id)
    return detectors


def _parse_entry(entry: dict, where: str) -> Detector:
    for name in ("id", "pattern"):
        value = entry.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{where}.{name} must be a non-empty string")
    for name, allowed in _ENUM_FIELDS.items():
        if entry.get(name) not in allowed:
            raise ValueError(f"{where}.{name} must be one of {', '.join(allowed)}; got {entry.get(name)!r}")
    ignore_case = entry.get("ignore_case")
    if not isinstance(ignore_case, bool):
        raise ValueError(f"{where}.ignore_case must be a boolean")
    if entry["action"] == "drop" and entry["target"] != "key":
        raise ValueError(f"{where}.action 'drop' is only valid for key detectors")
    try:
        regex = re.compile(entry["pattern"], re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        raise ValueError(f"{where}.pattern does not compile: {exc}") from exc
    return Detector(
        id=entry["id"],
        target=entry["target"],
        kind=entry["kind"],
        severity=entry["severity"],
        pattern=entry["pattern"],
        ignore_case=ignore_case,
        validator=entry["validator"],
        action=entry["action"],
        regex=regex,
    )


def match_key(key: str, detectors: list[Detector]) -> Detector | None:
    """Return the first key detector whose pattern matches `key`."""
    for det in detectors:
        if det.target == "key" and det.regex.search(key):
            return det
    return None


def scan_value(text: str, detectors: list[Detector]) -> list[tuple[Detector, str]]:
    """Return (detector, matched text) for every value-detector match that passes its validator."""
    hits: list[tuple[Detector, str]] = []
    for det in detectors:
        if det.target != "value":
            continue
        for match in det.regex.finditer(text):
            matched = match.group(0)
            if _validate(det.validator, matched):
                hits.append((det, matched))
    return hits


def _validate(validator: str, text: str) -> bool:
    if validator == "luhn":
        return luhn_ok(text)
    if validator == "jwt":
        return jwt_ok(text)
    if validator == "basic":
        return basic_ok(text)
    return True


def luhn_ok(digits: str) -> bool:
    """Luhn checksum over the digits in `digits` (spaces and dashes ignored); 13-19 digits required."""
    numbers = [int(c) for c in digits if c.isdigit()]
    if len(numbers) < 13 or len(numbers) > 19 or any(c not in "0123456789 -" for c in digits):
        return False
    total = 0
    for position, digit in enumerate(reversed(numbers)):
        if position % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def jwt_ok(token: str) -> bool:
    """True when `token` is three base64url segments and the header is a JSON object with "alg"."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return False
    if not all(_BASE64URL.fullmatch(part) for part in parts):
        return False
    header_b64 = parts[0]
    try:
        raw = base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4))
        header = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError):
        return False
    return isinstance(header, dict) and "alg" in header


def basic_ok(token: str) -> bool:
    """True when `token` (optionally prefixed "Basic ") base64-decodes, after adding missing
    padding, to printable UTF-8 text containing ':' with a non-empty part before it."""
    parts = token.split()
    if len(parts) == 2 and parts[0].lower() == "basic":
        token = parts[1]
    elif len(parts) != 1:
        return False
    payload = token.rstrip("=")
    try:
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return False
    user, sep, _ = text.partition(":")
    return bool(sep) and bool(user) and text.isprintable()
