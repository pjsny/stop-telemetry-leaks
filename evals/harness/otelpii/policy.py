"""Repo policy file `.otel-pii.toml`: allowlisted keys, extra redact rules, and suppressions."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

POLICY_FILENAME = ".otel-pii.toml"
REDACT_ACTIONS = ("mask", "hmac", "drop", "truncate_ip")

_TOP_LEVEL = {"version", "hash_key_env", "allow_keys", "redact", "suppress"}
_REDACT_FIELDS = {"key_pattern", "action"}
_SUPPRESS_FIELDS = {"fingerprint", "reason"}


@dataclass
class Policy:
    hash_key_env: str = "OTEL_PII_HMAC_KEY"
    allow_keys: frozenset[str] = frozenset()
    redact: list[tuple[str, str]] = field(default_factory=list)  # (key_pattern, action)
    suppress: dict[str, str] = field(default_factory=dict)  # fingerprint -> reason


def load_policy(repo: Path) -> Policy:
    """Read `repo/.otel-pii.toml`. Missing file → Policy(); invalid content → ValueError naming the field."""
    path = Path(repo) / POLICY_FILENAME
    if not path.is_file():
        return Policy()
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{path}: invalid TOML: {exc}") from exc

    def fail(name: str, problem: str) -> ValueError:
        return ValueError(f"{path}: {name} {problem}")

    _reject_unknown(data, _TOP_LEVEL, "", fail)

    if data.get("version") != 1:
        raise fail("version", f"must be 1; got {data.get('version')!r}")

    hash_key_env = data.get("hash_key_env", Policy.hash_key_env)
    if not isinstance(hash_key_env, str) or not hash_key_env:
        raise fail("hash_key_env", "must be a non-empty string")

    allow_keys = data.get("allow_keys", [])
    if not isinstance(allow_keys, list) or not all(isinstance(k, str) and k for k in allow_keys):
        raise fail("allow_keys", "must be a list of non-empty strings")

    redact: list[tuple[str, str]] = []
    for index, entry in enumerate(_table_array(data, "redact", fail)):
        where = f"redact[{index}]"
        _reject_unknown(entry, _REDACT_FIELDS, f"{where}.", fail)
        pattern = entry.get("key_pattern")
        if not isinstance(pattern, str) or not pattern:
            raise fail(f"{where}.key_pattern", "must be a non-empty string")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise fail(f"{where}.key_pattern", f"does not compile: {exc}") from exc
        problem = python_only_syntax(pattern)
        if problem:
            raise fail(f"{where}.key_pattern", f"uses {problem}, which JavaScript RegExp does not support")
        action = entry.get("action")
        if action not in REDACT_ACTIONS:
            raise fail(f"{where}.action", f"must be one of {', '.join(REDACT_ACTIONS)}; got {action!r}")
        redact.append((pattern, action))

    suppress: dict[str, str] = {}
    for index, entry in enumerate(_table_array(data, "suppress", fail)):
        where = f"suppress[{index}]"
        _reject_unknown(entry, _SUPPRESS_FIELDS, f"{where}.", fail)
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise fail(f"{where}.fingerprint", "must be a non-empty string")
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise fail(f"{where}.reason", "must be a non-empty string")
        suppress[fingerprint] = reason

    return Policy(
        hash_key_env=hash_key_env,
        allow_keys=frozenset(allow_keys),
        redact=redact,
        suppress=suppress,
    )


def _table_array(data: dict, name: str, fail) -> list[dict]:
    entries = data.get(name, [])
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise fail(name, "must be an array of tables ([[" + name + "]])")
    return entries


def _reject_unknown(table: dict, allowed: set[str], prefix: str, fail) -> None:
    for name in table:
        if name not in allowed:
            raise fail(f"{prefix}{name}", "is not a known field")


_INLINE_FLAGS = re.compile(r"\?(?:[aiLmsux]+(?:-[imsx]*)?|-[imsx]+)[):]")


def python_only_syntax(pattern: str) -> str | None:
    """Describe the first Python-only regex construct in `pattern`, or None when it is portable.

    Rejects named groups `(?P<`/`(?P=`, inline flags `(?i)`/`(?i:`, atomic groups `(?>`,
    comments `(?#`, conditionals `(?(`, `\\A`/`\\Z`, and possessive quantifiers (`*+`, `++`, `?+`, `}+`).
    """
    i = 0
    in_class = False
    after_quantifier = False
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 < n and pattern[i + 1] in "AZ":
                return f"anchor \\{pattern[i + 1]}"
            i += 2
            after_quantifier = False
            continue
        if in_class:
            if ch == "]":
                in_class = False
            i += 1
            continue
        if ch == "[":
            in_class = True
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            # Python reads a leading `]` as a literal member; JavaScript reads `[]` as an empty class.
            if i < n and pattern[i] == "]":
                return "a literal ] at the start of a character class"
            after_quantifier = False
            continue
        if ch == "(" and i + 1 < n and pattern[i + 1] == "?":
            rest = pattern[i + 1 :]
            if rest.startswith(("?P<", "?P=", "?P>")):
                return "a named group (?P...)"
            if rest.startswith("?>"):
                return "an atomic group (?>...)"
            if rest.startswith("?#"):
                return "a comment group (?#...)"
            if rest.startswith("?("):
                return "a conditional group (?(...)...)"
            if _INLINE_FLAGS.match(rest):
                return "an inline flag group"
            i += 2
            after_quantifier = False
            continue
        if ch in "*+?":
            if after_quantifier and ch == "+":
                return "a possessive quantifier"
            # `?` right after a quantifier makes it lazy; nothing may follow that.
            after_quantifier = not (after_quantifier and ch == "?")
            i += 1
            continue
        if ch == "{":
            close = pattern.find("}", i)
            if close > i + 1 and re.fullmatch(r"\d*(?:,\d*)?", pattern[i + 1 : close]):
                i = close + 1
                after_quantifier = True
                continue
        after_quantifier = False
        i += 1
    return None
