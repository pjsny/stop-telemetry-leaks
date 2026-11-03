#!/usr/bin/env python3
"""Local OTLP/HTTP receiver that appends decoded spans and logs to a JSONL file."""

from __future__ import annotations

import argparse
import gzip
import json
import signal
import sys
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from otelpii.otlp import DecodeError, decode_logs, decode_traces  # noqa: E402

_DECODERS = {"/v1/traces": decode_traces, "/v1/logs": decode_logs}
MAX_BODY = 64 * 1024 * 1024


class _BadRequest(Exception):
    """Malformed HTTP framing."""


class _TooLarge(Exception):
    """Body exceeds MAX_BODY (compressed or decompressed)."""


def _decompress(body: bytes, encoding: str) -> bytes:
    """Inflate gzip/deflate bodies, refusing output larger than MAX_BODY."""
    if encoding not in ("gzip", "deflate"):
        return body
    d = zlib.decompressobj(wbits=31 if encoding == "gzip" else 15)
    out = d.decompress(body, MAX_BODY + 1)
    if len(out) > MAX_BODY or d.unconsumed_tail:
        raise _TooLarge
    if not d.eof:
        raise DecodeError(f"truncated {encoding} body")
    return out


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, out: Path):
        super().__init__(addr, _Handler)
        self.out = Path(out)
        self.stats_path = Path(str(self.out) + ".stats.json")
        self.lock = threading.Lock()
        self.stats = {"skipped_records": 0, "requests": 0}
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.out.touch()
        self._write_stats()

    def _write_stats(self) -> None:
        self.stats_path.write_text(json.dumps(self.stats))

    def record(self, records: list[dict] | None) -> None:
        with self.lock:
            self.stats["requests"] += 1
            if records is None:
                self.stats["skipped_records"] += 1
            elif records:
                with self.out.open("a", encoding="utf-8") as fh:
                    for r in records:
                        fh.write(json.dumps(r, ensure_ascii=False) + "\n")
                    fh.flush()
            self._write_stats()


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, format, *args):  # silence default stderr logging
        pass

    def _reply(self, code: int, content_type: str) -> None:
        is_json = "json" in content_type.lower()
        payload = b"{}" if is_json and code == 200 else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json" if is_json else "application/x-protobuf")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> bytes | None:
        """Read the request body; return None when it exceeds MAX_BODY."""
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            parts: list[bytes] = []
            total = 0
            while True:
                line = self.rfile.readline(65537)
                if not line:
                    raise _BadRequest("truncated chunked body")
                try:
                    size = int(line.split(b";", 1)[0].strip(), 16)
                except ValueError as exc:
                    raise _BadRequest("bad chunk size") from exc
                if size == 0:
                    break
                total += size
                if total > MAX_BODY:
                    return None
                chunk = self.rfile.read(size)
                if len(chunk) != size:
                    raise _BadRequest("truncated chunk")
                parts.append(chunk)
                self.rfile.readline(65537)  # CRLF after chunk data
            while True:  # trailers, terminated by an empty line
                line = self.rfile.readline(65537)
                if not line or line in (b"\r\n", b"\n"):
                    break
            return b"".join(parts)
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return None
        return self.rfile.read(length) if length > 0 else b""

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        content_type = self.headers.get("Content-Type", "application/x-protobuf")
        try:
            body = self._read_body()
        except (_BadRequest, ValueError):
            self.close_connection = True
            self.server.record(None)
            self._reply(400, content_type)
            return
        if body is None:
            self.close_connection = True
            self.server.record(None)
            self._reply(413, content_type)
            return
        if path == "/v1/metrics":
            self._reply(200, content_type)
            return
        decoder = _DECODERS.get(path)
        if decoder is None:
            self.send_error(404)
            return
        try:
            enc = (self.headers.get("Content-Encoding") or "").lower()
            records = decoder(_decompress(body, enc), content_type)
        except _TooLarge:
            self.server.record(None)
            self._reply(413, content_type)
            return
        except (DecodeError, zlib.error, ValueError):
            self.server.record(None)
            self._reply(400, content_type)
            return
        self.server.record(records)
        self._reply(200, content_type)


def start_receiver(out: Path, host: str = "127.0.0.1", port: int = 0):
    """Start the receiver in a background thread; return (server, bound_port)."""
    server = _Server((host, port), Path(out))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def stop_receiver(server) -> None:
    server.shutdown()
    server.server_close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--ready-file", type=Path)
    args = ap.parse_args(argv)

    server = _Server((args.host, args.port), args.out)
    port = server.server_address[1]
    if args.ready_file:
        args.ready_file.write_text(str(port))
    print(f"OTLP receiver listening on http://{args.host}:{port} "
          f"(POST /v1/traces, /v1/logs); appending records to {args.out}.", flush=True)

    def _stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    stats = server.stats
    print(f"OTLP receiver stopped after {stats['requests']} requests; "
          f"{stats['skipped_records']} undecodable requests skipped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
