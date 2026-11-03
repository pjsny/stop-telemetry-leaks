"""pytest plugin loaded by canary_run.py (`-p otel_pii_canary`).

Runs inside the target app's environment. It redirects every OTLP exporter the app builds to the
local receiver named by OTEL_PII_RECEIVER_ENDPOINT (falling back to OTEL_EXPORTER_OTLP_ENDPOINT),
optionally runs the app's OTel bootstrap (OTEL_PII_BOOTSTRAP), and flushes the global providers at
session end. No repo files are edited. Every `opentelemetry` import is guarded: when the SDK or an
exporter package is missing, the corresponding step is skipped.
"""

from __future__ import annotations

import contextlib
import importlib
import importlib.metadata
import os
import runpy
import sys
import urllib.request
from pathlib import Path

import pytest

_POST_TIMEOUT_S = 5
_FLUSH_TIMEOUT_MS = 5000

# module -> (class attribute, signal)
_EXPORTER_MODULES = {
    "opentelemetry.exporter.otlp.proto.grpc.trace_exporter": ("OTLPSpanExporter", "span"),
    "opentelemetry.exporter.otlp.proto.http.trace_exporter": ("OTLPSpanExporter", "span"),
    "opentelemetry.exporter.otlp.proto.grpc._log_exporter": ("OTLPLogExporter", "log"),
    "opentelemetry.exporter.otlp.proto.http._log_exporter": ("OTLPLogExporter", "log"),
    "opentelemetry.exporter.otlp.proto.grpc.metric_exporter": ("OTLPMetricExporter", "metric"),
    "opentelemetry.exporter.otlp.proto.http.metric_exporter": ("OTLPMetricExporter", "metric"),
}

# Ignore proxy settings: the receiver is on 127.0.0.1 and nothing may leave the machine.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_ENDPOINT = (
    os.environ.get("OTEL_PII_RECEIVER_ENDPOINT") or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or ""
).rstrip("/")

_originals: dict[str, type] = {}  # module name -> original exporter class
_bootstrapped = False
# The plugin is imported before pytest starts capturing; keep a handle on the real stderr so
# warnings emitted while conftests load are not swallowed by fd capture.
try:
    _STDERR_FD = os.dup(2)
except OSError:
    _STDERR_FD = None


def _warn(msg: str) -> None:
    data = f"otel-pii-canary: {msg}\n".encode("utf-8", "replace")
    if _STDERR_FD is not None:
        try:
            os.write(_STDERR_FD, data)
            return
        except OSError:
            pass
    sys.stderr.write(data.decode("utf-8"))


def _post(path: str, body: bytes) -> bool:
    if not _ENDPOINT:
        return False
    req = urllib.request.Request(
        _ENDPOINT + path,
        data=body,
        headers={"Content-Type": "application/x-protobuf"},
        method="POST",
    )
    try:
        with _OPENER.open(req, timeout=_POST_TIMEOUT_S) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _build_shims() -> dict[str, type]:
    """Shim exporter classes by signal; a signal whose SDK classes do not import is left out."""
    shims: dict[str, type] = {}
    try:
        from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
    except Exception:
        SpanExporter = None
    if SpanExporter is not None:

        class _ShimSpanExporter(SpanExporter):
            def __init__(self, *args, **kwargs):
                self._shutdown = False

            def export(self, spans):
                if self._shutdown:
                    return SpanExportResult.FAILURE
                try:
                    from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans

                    body = encode_spans(spans).SerializeToString()
                except Exception:
                    return SpanExportResult.FAILURE
                return SpanExportResult.SUCCESS if _post("/v1/traces", body) else SpanExportResult.FAILURE

            def shutdown(self):
                self._shutdown = True

            def force_flush(self, timeout_millis: int = 30000) -> bool:
                return True

        shims["span"] = _ShimSpanExporter

    try:
        from opentelemetry.sdk._logs import export as logs_export
    except Exception:
        logs_export = None
    base = getattr(logs_export, "LogRecordExporter", None) or getattr(logs_export, "LogExporter", None)
    result = getattr(logs_export, "LogRecordExportResult", None) or getattr(logs_export, "LogExportResult", None)
    if base is not None and result is not None:

        class _ShimLogExporter(base):
            def __init__(self, *args, **kwargs):
                self._shutdown = False

            def export(self, batch):
                if self._shutdown:
                    return result.FAILURE
                try:
                    from opentelemetry.exporter.otlp.proto.common._log_encoder import encode_logs

                    body = encode_logs(batch).SerializeToString()
                except Exception:
                    return result.FAILURE
                return result.SUCCESS if _post("/v1/logs", body) else result.FAILURE

            def shutdown(self):
                self._shutdown = True

            def force_flush(self, timeout_millis: int = 30000) -> bool:
                return True

        shims["log"] = _ShimLogExporter

    try:
        from opentelemetry.sdk.metrics.export import MetricExporter, MetricExportResult
    except Exception:
        MetricExporter = None
    if MetricExporter is not None:

        class _ShimMetricExporter(MetricExporter):
            """Metrics are not captured (static-only surface); this only keeps them off the network."""

            def __init__(self, *args, **kwargs):
                # The metric reader reads _preferred_temporality/_preferred_aggregation set here.
                super().__init__()

            def export(self, metrics_data, timeout_millis: float = 10_000, **kwargs):
                return MetricExportResult.SUCCESS

            def force_flush(self, timeout_millis: float = 10_000) -> bool:
                return True

            def shutdown(self, timeout_millis: float = 30_000, **kwargs) -> None:
                return None

        shims["metric"] = _ShimMetricExporter
    return shims


_SHIMS = _build_shims()
_ShimSpanExporter = _SHIMS.get("span")
_ShimLogExporter = _SHIMS.get("log")
_ShimMetricExporter = _SHIMS.get("metric")


def _patch_exporter_modules() -> None:
    """Replace the exporter class on every OTLP exporter module that imports (ImportError -> skip)."""
    for mod_name, (attr, signal) in _EXPORTER_MODULES.items():
        shim = _SHIMS.get(signal)
        if shim is None:
            continue
        try:
            mod = importlib.import_module(mod_name)
        except Exception:
            continue
        current = getattr(mod, attr, None)
        if current is None or current is shim:
            continue
        _originals.setdefault(mod_name, current)
        setattr(mod, attr, shim)


def _rebind_imported_names() -> None:
    """Rebind names bound to an original exporter class in modules imported before this plugin."""
    replacements = {
        id(original): _SHIMS[_EXPORTER_MODULES[mod_name][1]] for mod_name, original in _originals.items()
    }
    if not replacements:
        return
    for mod in list(sys.modules.values()):
        try:
            namespace = vars(mod)
        except TypeError:
            continue
        for name, value in list(namespace.items()):
            shim = replacements.get(id(value))
            if shim is not None and isinstance(value, type):
                try:
                    setattr(mod, name, shim)
                except Exception:
                    pass


@contextlib.contextmanager
def _root_on_path(root: Path):
    """Make the repo root importable while the bootstrap runs (the bare `pytest` script does not)."""
    added = str(root) not in sys.path
    if added:
        sys.path.insert(0, str(root))
    try:
        yield
    finally:
        if added and str(root) in sys.path:
            sys.path.remove(str(root))


def _run_bootstrap(spec: str, root: Path) -> None:
    if spec == "auto":
        from opentelemetry.instrumentation.auto_instrumentation import initialize

        # initialize() only instruments libraries; providers and exporters come from a configurator
        # (opentelemetry-distro). Exporter entry points resolve to the patched module attributes.
        if not list(importlib.metadata.entry_points(group="opentelemetry_configurator")):
            _warn(
                "OTEL_PII_BOOTSTRAP=auto: no OpenTelemetry configurator is installed, so no tracer/logger "
                "provider or exporter will be set up and nothing will be exported. Install "
                "opentelemetry-distro in the app's environment, or pass the app's own setup as "
                "--bootstrap pkg.module:func or a .py file."
            )
        initialize()
        return
    if spec.endswith(".py"):
        path = Path(spec)
        if not path.is_absolute():
            path = root / path
        with _root_on_path(root):
            runpy.run_path(str(path), run_name="__otel_pii_bootstrap__")
        return
    mod_name, sep, func_name = spec.partition(":")
    if not sep or not mod_name or not func_name:
        raise ValueError(f"expected 'auto', 'pkg.module:func', or a .py path; got {spec!r}")
    with _root_on_path(root):
        # func() runs with root still importable: setup functions often import lazily.
        getattr(importlib.import_module(mod_name), func_name)()


def _maybe_bootstrap(root: Path) -> None:
    global _bootstrapped
    spec = os.environ.get("OTEL_PII_BOOTSTRAP", "").strip()
    if _bootstrapped or not spec:
        return
    _bootstrapped = True
    try:
        _run_bootstrap(spec, root)
    except Exception as exc:  # report and keep running the tests; canary_run flags empty captures
        _warn(f"bootstrap {spec!r} failed: {type(exc).__name__}: {exc}")


_patch_exporter_modules()


# No tryfirst: pytest 7 applies the `pythonpath` ini option in its own tryfirst implementation of
# this hook, and the bootstrap may need it. Conftest loading is trylast, so this still runs before
# any conftest is imported.
def pytest_load_initial_conftests(early_config, parser, args):
    _patch_exporter_modules()
    _rebind_imported_names()
    _maybe_bootstrap(Path(early_config.invocation_params.dir))


def pytest_unconfigure(config):
    providers = []
    try:
        from opentelemetry import trace

        providers.append(trace.get_tracer_provider())
    except Exception:
        pass
    try:
        from opentelemetry import _logs

        providers.append(_logs.get_logger_provider())
    except Exception:
        pass
    for provider in providers:
        flush = getattr(provider, "force_flush", None)
        if callable(flush):
            try:
                flush(_FLUSH_TIMEOUT_MS)
            except Exception as exc:
                _warn(f"force_flush failed: {type(exc).__name__}: {exc}")
