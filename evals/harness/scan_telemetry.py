#!/usr/bin/env python3
"""Eval grading tool: scan a capture JSONL (from otlp_receiver.py) for canaries, credential keys, and PII values.

Usage: scan_telemetry.py --capture CAPTURE.jsonl --seed SEED [--repo .] [--detectors PATH] --out FINDINGS.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from otelpii.canary import canary_values, find_canaries  # noqa: E402
from otelpii.detectors import Detector, load_detectors, match_key, scan_value  # noqa: E402
from otelpii.findings import Finding, apply_policy, load, mask_evidence, merge, surface_for  # noqa: E402
from otelpii.policy import Policy, load_policy  # noqa: E402

CRITICAL_CANARY_KINDS = frozenset({"token", "bearer", "api_key", "cookie"})
SPAN_KIND_SERVER = 2
SPAN_KIND_CLIENT = 3


def _canary_needles(seed: str) -> dict[str, str]:
    values = canary_values(seed)
    return {
        "token": values["api_key"],
        "email": values["email"],
        "card": values["card"],
        "name": values["name"],
    }


def _leaves(value, path: str | None):
    """Yield (dotted path, string form) for every scalar leaf; lists keep the parent path."""
    if value is None:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _leaves(v, f"{path}.{k}" if path else str(k))
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _leaves(item, path)
    else:
        yield path, value if isinstance(value, str) else json.dumps(value)


class _Aggregator:
    def __init__(self) -> None:
        self._by_key: dict[tuple, Finding] = {}

    def hit(self, surface: str, key: str | None, detector: str, severity: str, matched: str) -> None:
        agg = (surface, key, detector)
        found = self._by_key.get(agg)
        if found is None:
            self._by_key[agg] = Finding(
                source="runtime", status="confirmed", severity=severity, surface=surface,
                key=key, file=None, line=None, detector=detector,
                evidence=mask_evidence(matched), hits_before=1,
            )
        else:
            found.hits_before += 1

    def findings(self) -> list[Finding]:
        return list(self._by_key.values())


def _allowed(key: str | None, top_key: str | None, policy: Policy) -> bool:
    """Allowed when the top-level key, the full key, or a nested ancestor path below it is listed."""
    if top_key is not None and top_key in policy.allow_keys:
        return True
    if key is None:
        return False
    parts = key.split(".")
    start = len(top_key.split(".")) if top_key else 1
    return any(".".join(parts[:i]) in policy.allow_keys for i in range(start, len(parts) + 1))


def _check(agg: _Aggregator, surface: str, key: str | None, text: str,
           seed: str, needles: dict[str, str], detectors: list[Detector]) -> None:
    if key is not None:
        det = match_key(key, detectors)
        if det is not None:
            agg.hit(surface, key, det.id, det.severity, text)
    for kind in find_canaries(text, seed):
        severity = "critical" if kind in CRITICAL_CANARY_KINDS else "high"
        agg.hit(surface, key, f"canary:{kind}", severity, needles[kind])
    for det, matched in scan_value(text, detectors):
        if det.action == "truncate_ip" and _is_truncated_ip(matched):
            continue
        agg.hit(surface, key, det.id, det.severity, matched)


def _is_truncated_ip(matched: str) -> bool:
    """truncate_ip redaction output: IPv4 with last octet 0, or IPv6 ending in "::"."""
    if ":" in matched:
        return matched.endswith("::")
    return matched.rsplit(".", 1)[-1] == "0"


def _scan_mapping(agg, signal: str, attrs, seed, needles, detectors, policy) -> None:
    if not isinstance(attrs, dict):
        return
    for top_key, value in attrs.items():
        surface = surface_for(signal, top_key)
        for path, text in _leaves(value, top_key):
            if _allowed(path, top_key, policy):
                continue
            _check(agg, surface, path, text, seed, needles, detectors)


def _has_prefix(attrs, *prefixes: str) -> bool:
    return isinstance(attrs, dict) and any(str(k).startswith(prefixes) for k in attrs)


def scan_records(records, seed: str, detectors: list[Detector], policy: Policy):
    """Return (findings, coverage) for decoded capture records; coverage.skipped_records is 0."""
    needles = _canary_needles(seed)
    agg = _Aggregator()
    surfaces = {"http.server": 0, "http.client": 0, "db": 0, "gen_ai": 0, "exception": 0, "log": 0}
    coverage = {"spans": 0, "logs": 0, "skipped_records": 0, "surfaces": surfaces}

    for rec in records:
        signal = rec.get("signal")
        attrs = rec.get("attributes") or {}
        events = rec.get("events") or []
        if signal == "span":
            coverage["spans"] += 1
            kind = rec.get("kind")
            web = _has_prefix(attrs, "http.", "url.")
            if kind == SPAN_KIND_SERVER and web:
                surfaces["http.server"] += 1
            if kind == SPAN_KIND_CLIENT and web:
                surfaces["http.client"] += 1
            if _has_prefix(attrs, "db."):
                surfaces["db"] += 1
            if _has_prefix(attrs, "gen_ai."):
                surfaces["gen_ai"] += 1
            if any(isinstance(e, dict) and e.get("name") == "exception" for e in events):
                surfaces["exception"] += 1
            if isinstance(rec.get("name"), str):
                _check(agg, "span.name", None, rec["name"], seed, needles, detectors)
            if isinstance(rec.get("status_message"), str) and rec["status_message"]:
                _check(agg, "span.status", None, rec["status_message"], seed, needles, detectors)
        elif signal == "log":
            coverage["logs"] += 1
            surfaces["log"] += 1
            if _has_prefix(attrs, "gen_ai."):
                surfaces["gen_ai"] += 1
            body = rec.get("body")
            for path, text in _leaves(body, "body" if isinstance(body, dict) else None):
                if _allowed(path, "body" if path else None, policy):
                    continue
                _check(agg, "log.body", path, text, seed, needles, detectors)
        else:
            continue
        _scan_mapping(agg, signal, attrs, seed, needles, detectors, policy)
        for event in events:
            if isinstance(event, dict):
                _scan_mapping(agg, "event", event.get("attributes"), seed, needles, detectors, policy)
        _scan_mapping(agg, "resource", rec.get("resource"), seed, needles, detectors, policy)

    return apply_policy(agg.findings(), policy), coverage


def read_capture(path: Path) -> tuple[list[dict], int]:
    """Return (records, skipped) where skipped counts malformed lines and receiver-skipped requests."""
    records: list[dict] = []
    skipped = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if isinstance(rec, dict):
            records.append(rec)
        else:
            skipped += 1
    stats_path = Path(str(path) + ".stats.json")
    if stats_path.is_file():
        try:
            skipped += int(json.loads(stats_path.read_text()).get("skipped_records", 0))
        except (ValueError, AttributeError, TypeError):
            pass
    return records, skipped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--capture", required=True, type=Path)
    ap.add_argument("--seed", required=True)
    ap.add_argument("--repo", default=Path("."), type=Path)
    ap.add_argument("--detectors", type=Path)
    ap.add_argument("--static", type=Path, help="findings JSON (static candidates) to merge runtime proof into")
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)

    if not args.capture.is_file():
        print(f"error: capture file not found: {args.capture}", file=sys.stderr)
        return 2
    try:
        canary_values(args.seed)
        detectors = load_detectors(args.detectors)
        policy = load_policy(args.repo)
        static = load(args.static) if args.static is not None else None
    except (ValueError, OSError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    records, skipped = read_capture(args.capture)
    runtime, coverage = scan_records(records, args.seed, detectors, policy)
    merged = None if static is None else merge(static, runtime)
    findings = runtime if merged is None else apply_policy(merged, policy)
    coverage["skipped_records"] = skipped
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps({"findings": [asdict(f) for f in findings], "coverage": coverage},
                   indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    active = [f for f in findings if f.status != "suppressed"]
    by_sev = {s: sum(1 for f in active if f.severity == s) for s in ("critical", "high", "medium")}
    canary_hits = sum(1 for f in runtime if f.status != "suppressed" and f.detector.startswith("canary:"))
    merged_note = ""
    if merged is not None:
        static_ids = {id(f) for f in static}
        runtime_ids = {id(f) for f in runtime}
        static_only = sum(1 for f in merged if id(f) in static_ids)
        runtime_only = sum(1 for f in merged if id(f) in runtime_ids)
        confirmed = len(merged) - static_only - runtime_only
        merged_note = (
            f"Merged {len(static)} static findings: {confirmed} confirmed by runtime, "
            f"{static_only} static-only, {runtime_only} runtime-only. "
        )
    print(
        f"Scanned {coverage['spans']} spans and {coverage['logs']} logs "
        f"({skipped} skipped records): {len(active)} findings "
        f"({by_sev['critical']} critical, {by_sev['high']} high, {by_sev['medium']} medium), "
        f"{canary_hits} runtime findings with canary proof, {len(findings) - len(active)} suppressed. "
        f"{merged_note}Wrote {args.out}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
