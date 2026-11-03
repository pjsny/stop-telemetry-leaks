"""Finding records: fingerprints, evidence masking, surface naming, policy, merge, and JSON I/O."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path

from .policy import Policy

SEVERITIES = ("critical", "high", "medium")
STATUSES = ("candidate", "confirmed", "fixed", "proposed", "suppressed", "unverified")

_URL_KEYS = frozenset({"url.full", "url.query", "url.path", "http.url", "http.target"})
_KEY_PREFIX_SURFACES = (
    ("http.request.header.", "http.request.header"),
    ("http.response.header.", "http.response.header"),
    ("db.", "db"),
    ("exception.", "exception"),
    ("gen_ai.", "gen_ai"),
)


def fingerprint(surface: str, key: str | None, file: str | None, detector: str) -> str:
    """First 12 hex chars of sha256("surface|key|file|detector"); None parts become ""."""
    raw = "|".join([surface, key or "", file or "", detector])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


@dataclass
class Finding:
    source: str
    status: str
    severity: str
    surface: str
    key: str | None
    file: str | None
    line: int | None
    detector: str
    evidence: str
    hits_before: int = 0
    hits_after: int = 0
    snippet: str | None = None
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"Finding.status must be one of {', '.join(STATUSES)}; got {self.status!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"Finding.severity must be one of {', '.join(SEVERITIES)}; got {self.severity!r}")
        if not self.fingerprint:
            self.fingerprint = fingerprint(self.surface, self.key, self.file, self.detector)


def mask_evidence(value: str) -> str:
    """Keep at most the first 4 characters plus the length; shorter values keep only the length."""
    if len(value) <= 4:
        return f"…({len(value)} chars)"
    return f"{value[:4]}…({len(value)} chars)"


def surface_for(signal: str, key: str | None) -> str:
    """Map a telemetry location to its surface name.

    `signal` is "span", "event", "log", or "resource"; the explicit locations "span.name",
    "span.status", and "log.body" are also accepted. `key` is the attribute key, or None for a
    span name (signal "span") or log body (signal "log"). Key-based surfaces (headers, url, db,
    exception, gen_ai) apply to span, event, and log attributes; resource attributes are always
    "resource".
    """
    if signal == "resource":
        return "resource"
    if signal in ("span.status", "status"):
        return "span.status"
    if signal == "span.name" or (signal == "span" and key is None):
        return "span.name"
    if signal == "log.body" or (signal == "log" and key is None):
        return "log.body"
    if key is not None:
        if key in _URL_KEYS:
            return "url"
        for prefix, surface in _KEY_PREFIX_SURFACES:
            if key.startswith(prefix):
                return surface
    if signal == "log":
        return "log.attribute"
    return "attribute"


def apply_policy(findings: list[Finding], policy: Policy) -> list[Finding]:
    """Return copies with status "suppressed" for fingerprints listed in the policy."""
    return [
        replace(f, status="suppressed") if f.fingerprint in policy.suppress else f
        for f in findings
    ]


def merge(static: list[Finding], runtime: list[Finding]) -> list[Finding]:
    """Fold runtime proof into static candidates that share the same key.

    A static finding whose key matches any runtime finding's key becomes "confirmed" with
    hits_before = total runtime hits for that key and the more severe of the two severities;
    the matched runtime findings are dropped. Unmatched findings of both kinds are kept.
    """
    runtime_by_key: dict[str, list[Finding]] = {}
    for f in runtime:
        if f.key is not None:
            runtime_by_key.setdefault(f.key, []).append(f)

    matched_keys: set[str] = set()
    merged: list[Finding] = []
    for f in static:
        proof = runtime_by_key.get(f.key) if f.key is not None else None
        if not proof:
            merged.append(f)
            continue
        matched_keys.add(f.key)
        severity = min([f.severity, *(r.severity for r in proof)], key=SEVERITIES.index)
        merged.append(
            replace(
                f,
                status="confirmed",
                severity=severity,
                hits_before=sum(r.hits_before for r in proof),
            )
        )
    merged.extend(f for f in runtime if f.key is None or f.key not in matched_keys)
    return merged


def dump(findings: list[Finding], path: Path | str) -> None:
    """Write findings as a JSON list of dicts."""
    Path(path).write_text(
        json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load(path: Path | str) -> list[Finding]:
    """Read a JSON list of finding dicts written by `dump`."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON list of findings")
    names = {f.name for f in fields(Finding)}
    return [Finding(**{k: v for k, v in item.items() if k in names}) for item in data]
