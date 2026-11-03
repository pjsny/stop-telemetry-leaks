#!/usr/bin/env python3
"""Eval grading tool: run a test command while a local OTLP receiver captures what the app's exporters send.

Writes OUT_DIR/capture.jsonl and OUT_DIR/run.json. Exit 0 even when the tests fail, 2 on usage
error, 3 when nothing was captured.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from otelpii.canary import canary_values  # noqa: E402
from otlp_receiver import start_receiver, stop_receiver  # noqa: E402

CANARY_DIR = SCRIPTS_DIR / "canary"
FLUSH_MJS = CANARY_DIR / "otel-pii-flush.mjs"
PLUGIN_NAME = "otel_pii_canary"
SETTLE_SECONDS = 1.5

_SCRUB_RE = re.compile(r"OTEL_EXPORTER_OTLP_.*(ENDPOINT|HEADERS|PROTOCOL)")
_CJS_EXTS = {".cjs", ".cts"}
_ESM_EXTS = {".mjs", ".mts"}

NO_RECORDS_HINT = (
    "No spans or logs reached the receiver. Likely causes: no OTel bootstrap was loaded during the "
    "tests (pass --bootstrap with the app's instrumentation file or entry point); the app's exporter "
    "is not OTLP (console, in-memory, or a vendor exporter); or, in Node, the exporter is OTLP gRPC "
    "(including a gRPC exporter with a hardcoded `url:`), which this harness cannot capture. Node "
    "OTLP/HTTP exporters with a hardcoded `url:` are redirected to the receiver (see the "
    "'otel-pii: redirected' lines on stderr)."
)
VITEST_HINT = (
    "vitest's threads/vmThreads pools terminate workers without beforeExit, so the last export batch "
    "of each worker is lost; rerun with `--pool=forks`."
)
_SIGNALS = ("traces", "logs", "metrics")
_EXPORTER_SELECTORS = ("OTEL_TRACES_EXPORTER", "OTEL_LOGS_EXPORTER")


def preserved_none_exporters(base: dict[str, str]) -> list[str]:
    """Exporter selectors the caller set to exactly "none"; scrubbed_env keeps them.

    With `none`, the zero-code (opentelemetry-instrument) route still builds the SDK providers but
    adds no exporter; the app attaches its own wrapped (redacting) exporter. Forcing `otlp` there
    would add a second, unwrapped exporter and capture raw values the app never sends.
    """
    return [name for name in _EXPORTER_SELECTORS if base.get(name) == "none"]


class UsageError(Exception):
    pass


def scrubbed_env(base: dict[str, str], endpoint: str) -> dict[str, str]:
    """Copy of `base` with every OTLP endpoint/header/protocol variable pointed at `endpoint`.

    Signal-specific variables are overridden (headers set to ""), not merely removed, so .env loaders
    that do not override existing variables cannot reintroduce real endpoints or credentials.
    """
    env = {k: v for k, v in base.items() if not _SCRUB_RE.fullmatch(k)}
    for name in ("OTEL_SDK_DISABLED", "OTEL_TRACES_SAMPLER_ARG"):
        env.pop(name, None)
    env.update(
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
            "OTEL_EXPORTER_OTLP_HEADERS": "",
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            "OTEL_TRACES_EXPORTER": "otlp",
            "OTEL_LOGS_EXPORTER": "otlp",
            "OTEL_METRICS_EXPORTER": "none",
            "OTEL_TRACES_SAMPLER": "always_on",
            "OTEL_BSP_SCHEDULE_DELAY": "100",
            "OTEL_BLRP_SCHEDULE_DELAY": "100",
            "OTEL_PII_RECEIVER_ENDPOINT": endpoint,
        }
    )
    for name in preserved_none_exporters(base):
        env[name] = "none"
    for signal in _SIGNALS:
        prefix = f"OTEL_EXPORTER_OTLP_{signal.upper()}"
        env[f"{prefix}_ENDPOINT"] = f"{endpoint}/v1/{signal}"
        env[f"{prefix}_HEADERS"] = ""
        env[f"{prefix}_PROTOCOL"] = "http/protobuf"
    return env


def _append_option(existing: str | None, extra: str) -> str:
    return f"{existing} {extra}" if existing and existing.strip() else extra


def _node_quote(value: str) -> str:
    """Quote a value for NODE_OPTIONS when it contains whitespace or quotes."""
    if not re.search(r'[\s"\\]', value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _nearest_package_type(path: Path) -> str | None:
    for directory in path.parents:
        pkg = directory / "package.json"
        if pkg.is_file():
            try:
                return json.loads(pkg.read_text(encoding="utf-8")).get("type")
            except (OSError, ValueError, AttributeError):
                return None
    return None


def _is_path_spec(spec: str, cwd: Path) -> bool:
    if spec.startswith(("./", "../", "/", ".\\", "..\\")) or Path(spec).is_absolute():
        return True
    return (cwd / spec).is_file()


def node_bootstrap_option(spec: str, cwd: Path) -> str:
    """NODE_OPTIONS fragment that preloads the bootstrap `spec` (path or package specifier)."""
    if spec.startswith("file:") or not _is_path_spec(spec, cwd):
        return f"--import {_node_quote(spec)}"
    path = Path(spec)
    if not path.is_absolute():
        path = cwd / path
    path = path.resolve()
    if not path.is_file():
        raise UsageError(f"--bootstrap file not found: {path}")
    ext = path.suffix.lower()
    if ext in _CJS_EXTS or (ext == ".js" and _nearest_package_type(path) != "module"):
        return f"--require {_node_quote(str(path))}"
    return f"--import {path.as_uri()}"


def build_env(lang: str, base: dict[str, str], endpoint: str, bootstrap: str | None, cwd: Path,
              seed: str) -> dict[str, str]:
    env = scrubbed_env(base, endpoint)
    env["OTEL_PII_CANARY_SEED"] = seed  # canary tests read their values from this
    if lang == "python":
        env["PYTHONPATH"] = os.pathsep.join(p for p in (str(CANARY_DIR), env.get("PYTHONPATH", "")) if p)
        env["PYTEST_ADDOPTS"] = _append_option(env.get("PYTEST_ADDOPTS"), f"-p {PLUGIN_NAME}")
        if bootstrap:
            env["OTEL_PII_BOOTSTRAP"] = bootstrap
        else:
            env.pop("OTEL_PII_BOOTSTRAP", None)
    else:
        # The preload goes before the bootstrap so its OTLP export redirect is installed first. (Node
        # runs --require preloads before --import ones; that is fine because exporters look up
        # http.request at send time.)
        options = _append_option(env.get("NODE_OPTIONS"), f"--import {FLUSH_MJS.as_uri()}")
        if bootstrap:
            options = _append_option(options, node_bootstrap_option(bootstrap, cwd))
        env["NODE_OPTIONS"] = options
    return env


def count_records(capture: Path) -> dict[str, int]:
    counts = {"span": 0, "log": 0}
    if not capture.exists():
        return counts
    with capture.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                signal = json.loads(line).get("signal")
            except ValueError:
                continue
            if signal in counts:
                counts[signal] += 1
    return counts


def _parse(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="canary_run.py",
        description=__doc__,
        usage="%(prog)s --lang python|node --out-dir DIR [--seed SEED] [--bootstrap SPEC] [--cwd DIR] -- CMD...",
    )
    ap.add_argument("--lang", required=True, choices=("python", "node"))
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--seed", default=None)
    ap.add_argument("--bootstrap", default=None)
    ap.add_argument("--cwd", default=".", type=Path)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)
    if args.cmd and args.cmd[0] == "--":
        args.cmd = args.cmd[1:]
    if not args.cmd:
        ap.error("missing test command after --")
    if not args.cwd.is_dir():
        ap.error(f"--cwd is not a directory: {args.cwd}")
    args.seed = args.seed or uuid.uuid4().hex
    try:
        canary_values(args.seed)
    except ValueError as exc:
        ap.error(str(exc))
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv)
    cwd = args.cwd.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.jsonl"
    capture.unlink(missing_ok=True)

    preserved = preserved_none_exporters(dict(os.environ))
    if preserved:
        print(
            f"Keeping {', '.join(f'{name}=none' for name in preserved)} from the environment: the SDK's own "
            "exporter stays off for those signals, so only exporters the app attaches itself are captured."
        )
    server, port = start_receiver(capture)
    try:
        try:
            env = build_env(args.lang, dict(os.environ), f"http://127.0.0.1:{port}", args.bootstrap, cwd, args.seed)
        except UsageError as exc:
            print(f"canary_run.py: error: {exc}", file=sys.stderr)
            return 2
        try:
            exit_code = subprocess.run(args.cmd, cwd=cwd, env=env).returncode
        except FileNotFoundError as exc:
            print(f"canary_run.py: error: command not found: {exc.filename or args.cmd[0]}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            exit_code = 130
        time.sleep(SETTLE_SECONDS)
    finally:
        stop_receiver(server)

    records = count_records(capture)
    run = {"exit_code": exit_code, "seed": args.seed, "records": records, "command": args.cmd}
    (out_dir / "run.json").write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")

    total = records["span"] + records["log"]
    print(
        f"Ran {' '.join(args.cmd)!r} ({args.lang}) in {cwd}: test command exited {exit_code}; "
        f"captured {records['span']} spans and {records['log']} logs to {capture} with seed {args.seed}."
    )
    if total == 0:
        print(NO_RECORDS_HINT)
        if any("vitest" in part for part in args.cmd):
            print(VITEST_HINT)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
