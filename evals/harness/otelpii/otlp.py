"""Decode OTLP trace/log export requests (protobuf or JSON) into capture records.

Standard library only. Records follow the capture JSONL contract (C3).
"""

from __future__ import annotations

import base64
import json
import struct

# Field numbers from opentelemetry-proto (verified by tests against descriptors).
EXPORT_TRACE_RESOURCE_SPANS = 1
RESOURCE_SPANS_RESOURCE = 1
RESOURCE_SPANS_SCOPE_SPANS = 2
RESOURCE_ATTRIBUTES = 1
SCOPE_SPANS_SCOPE = 1
SCOPE_SPANS_SPANS = 2
SCOPE_NAME = 1
SCOPE_VERSION = 2
SPAN_NAME = 5
SPAN_KIND = 6
SPAN_ATTRIBUTES = 9
SPAN_EVENTS = 11
SPAN_STATUS = 15
EVENT_NAME = 2
EVENT_ATTRIBUTES = 3
STATUS_MESSAGE = 2
EXPORT_LOGS_RESOURCE_LOGS = 1
RESOURCE_LOGS_RESOURCE = 1
RESOURCE_LOGS_SCOPE_LOGS = 2
SCOPE_LOGS_SCOPE = 1
SCOPE_LOGS_LOG_RECORDS = 2
LOG_BODY = 5
LOG_ATTRIBUTES = 6
LOG_EVENT_NAME = 12
KV_KEY = 1
KV_VALUE = 2
ANY_STRING = 1
ANY_BOOL = 2
ANY_INT = 3
ANY_DOUBLE = 4
ANY_ARRAY = 5
ANY_KVLIST = 6
ANY_BYTES = 7
ARRAY_VALUES = 1
KVLIST_VALUES = 1


class DecodeError(ValueError):
    """Raised when a payload cannot be decoded."""


# ---------------------------------------------------------------- wire format

def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise DecodeError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift >= 70:
            raise DecodeError("varint too long")


def _fields(buf: bytes) -> list[tuple[int, int, object]]:
    """Parse a message into (field_number, wire_type, value) triples.

    Varint → int, fixed64/fixed32 → raw bytes, length-delimited → bytes.
    """
    out: list[tuple[int, int, object]] = []
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = _varint(buf, pos)
        field, wt = tag >> 3, tag & 7
        if field == 0:
            raise DecodeError("field number 0")
        if wt == 0:
            val, pos = _varint(buf, pos)
        elif wt == 1:
            if pos + 8 > n:
                raise DecodeError("truncated fixed64")
            val, pos = buf[pos:pos + 8], pos + 8
        elif wt == 2:
            ln, pos = _varint(buf, pos)
            if pos + ln > n:
                raise DecodeError("truncated length-delimited field")
            val, pos = buf[pos:pos + ln], pos + ln
        elif wt == 5:
            if pos + 4 > n:
                raise DecodeError("truncated fixed32")
            val, pos = buf[pos:pos + 4], pos + 4
        else:
            raise DecodeError(f"unsupported wire type {wt}")
        out.append((field, wt, val))
    return out


def _str(val: object) -> str:
    if not isinstance(val, bytes):
        raise DecodeError("expected length-delimited string")
    return val.decode("utf-8", errors="replace")


def _sub(val: object) -> bytes:
    if not isinstance(val, bytes):
        raise DecodeError("expected embedded message")
    return val


def _pb_any(buf: bytes):
    value = None
    for f, wt, v in _fields(buf):
        if f == ANY_STRING and wt == 2:
            value = _str(v)
        elif f == ANY_BOOL and wt == 0:
            value = bool(v)
        elif f == ANY_INT and wt == 0:
            value = v - (1 << 64) if v >= 1 << 63 else v
        elif f == ANY_DOUBLE and wt == 1:
            value = struct.unpack("<d", v)[0]
        elif f == ANY_ARRAY and wt == 2:
            value = [_pb_any(_sub(x)) for af, awt, x in _fields(_sub(v))
                     if af == ARRAY_VALUES and awt == 2]
        elif f == ANY_KVLIST and wt == 2:
            value = _pb_kvs(_sub(v), KVLIST_VALUES)
        elif f == ANY_BYTES and wt == 2:
            value = base64.b64encode(_sub(v)).decode("ascii")
    return value


def _pb_kv(buf: bytes) -> tuple[str, object]:
    key, value = "", None
    for f, wt, v in _fields(buf):
        if f == KV_KEY and wt == 2:
            key = _str(v)
        elif f == KV_VALUE and wt == 2:
            value = _pb_any(_sub(v))
    return key, value


def _pb_kvs(buf: bytes, field: int) -> dict:
    out: dict = {}
    for f, wt, v in _fields(buf):
        if f == field and wt == 2:
            k, val = _pb_kv(_sub(v))
            out[k] = val
    return out


def _pb_resource(buf: bytes) -> dict:
    return _pb_kvs(buf, RESOURCE_ATTRIBUTES)


def _pb_scope(buf: bytes) -> dict:
    scope = {"name": None, "version": None}
    for f, wt, v in _fields(buf):
        if f == SCOPE_NAME and wt == 2:
            scope["name"] = _str(v)
        elif f == SCOPE_VERSION and wt == 2:
            scope["version"] = _str(v)
    return scope


def _empty_scope() -> dict:
    return {"name": None, "version": None}


def _pb_span(buf: bytes, resource: dict, scope: dict) -> dict:
    rec = {"signal": "span", "name": None, "kind": 0, "attributes": {}, "events": [],
           "status_message": None, "resource": resource, "scope": scope, "body": None}
    for f, wt, v in _fields(buf):
        if f == SPAN_NAME and wt == 2:
            rec["name"] = _str(v)
        elif f == SPAN_KIND and wt == 0:
            rec["kind"] = v
        elif f == SPAN_ATTRIBUTES and wt == 2:
            k, val = _pb_kv(_sub(v))
            rec["attributes"][k] = val
        elif f == SPAN_EVENTS and wt == 2:
            ev = {"name": None, "attributes": {}}
            for ef, ewt, ev_v in _fields(_sub(v)):
                if ef == EVENT_NAME and ewt == 2:
                    ev["name"] = _str(ev_v)
                elif ef == EVENT_ATTRIBUTES and ewt == 2:
                    k, val = _pb_kv(_sub(ev_v))
                    ev["attributes"][k] = val
            rec["events"].append(ev)
        elif f == SPAN_STATUS and wt == 2:
            for sf, swt, sv in _fields(_sub(v)):
                if sf == STATUS_MESSAGE and swt == 2:
                    rec["status_message"] = _str(sv) or None
    return rec


def _pb_log(buf: bytes, resource: dict, scope: dict) -> dict:
    rec = {"signal": "log", "name": None, "kind": None, "attributes": {}, "events": [],
           "status_message": None, "resource": resource, "scope": scope, "body": None}
    for f, wt, v in _fields(buf):
        if f == LOG_BODY and wt == 2:
            rec["body"] = _pb_any(_sub(v))
        elif f == LOG_ATTRIBUTES and wt == 2:
            k, val = _pb_kv(_sub(v))
            rec["attributes"][k] = val
        elif f == LOG_EVENT_NAME and wt == 2:
            rec["name"] = _str(v) or None
    return rec


def _pb_request(body: bytes, top: int, res_f: int, scopes_f: int, scope_f: int,
                items_f: int, item_fn) -> list[dict]:
    records: list[dict] = []
    for f, wt, v in _fields(body):
        if f != top or wt != 2:
            continue
        resource: dict = {}
        scope_blobs: list[bytes] = []
        for rf, rwt, rv in _fields(_sub(v)):
            if rf == res_f and rwt == 2:
                resource = _pb_resource(_sub(rv))
            elif rf == scopes_f and rwt == 2:
                scope_blobs.append(_sub(rv))
        for blob in scope_blobs:
            scope = _empty_scope()
            items: list[bytes] = []
            for sf, swt, sv in _fields(blob):
                if sf == scope_f and swt == 2:
                    scope = _pb_scope(_sub(sv))
                elif sf == items_f and swt == 2:
                    items.append(_sub(sv))
            records.extend(item_fn(i, resource, scope) for i in items)
    return records


# ---------------------------------------------------------------- JSON

def _json_any(v):
    if not isinstance(v, dict):
        return v
    if "stringValue" in v:
        return v["stringValue"]
    if "boolValue" in v:
        return v["boolValue"]
    if "intValue" in v:
        return v["intValue"]
    if "doubleValue" in v:
        return v["doubleValue"]
    if "arrayValue" in v:
        return [_json_any(x) for x in (v["arrayValue"] or {}).get("values", []) or []]
    if "kvlistValue" in v:
        return _json_kvs((v["kvlistValue"] or {}).get("values"))
    if "bytesValue" in v:
        return v["bytesValue"]
    return None


def _json_kvs(items) -> dict:
    out: dict = {}
    for kv in items or []:
        if not isinstance(kv, dict):
            raise DecodeError("attribute is not an object")
        out[str(kv.get("key", ""))] = _json_any(kv.get("value"))
    return out


def _json_scope(s) -> dict:
    s = s or {}
    return {"name": s.get("name"), "version": s.get("version")}


def _json_span(s: dict, resource: dict, scope: dict) -> dict:
    status = s.get("status") or {}
    kind = s.get("kind", 0)
    if isinstance(kind, str):
        kind = {"SPAN_KIND_UNSPECIFIED": 0, "SPAN_KIND_INTERNAL": 1, "SPAN_KIND_SERVER": 2,
                "SPAN_KIND_CLIENT": 3, "SPAN_KIND_PRODUCER": 4,
                "SPAN_KIND_CONSUMER": 5}.get(kind, 0)
    return {"signal": "span", "name": s.get("name"), "kind": kind,
            "attributes": _json_kvs(s.get("attributes")),
            "events": [{"name": e.get("name"), "attributes": _json_kvs(e.get("attributes"))}
                       for e in s.get("events") or []],
            "status_message": status.get("message") or None,
            "resource": resource, "scope": scope, "body": None}


def _json_log(r: dict, resource: dict, scope: dict) -> dict:
    return {"signal": "log", "name": r.get("eventName") or None, "kind": None,
            "attributes": _json_kvs(r.get("attributes")), "events": [],
            "status_message": None, "resource": resource, "scope": scope,
            "body": _json_any(r["body"]) if r.get("body") is not None else None}


def _json_request(body: bytes, top: str, scopes: str, items: str, item_fn) -> list[dict]:
    try:
        doc = json.loads(body.decode("utf-8")) if body.strip() else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"invalid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise DecodeError("top-level JSON is not an object")
    records: list[dict] = []
    try:
        for rs in doc.get(top) or []:
            resource = _json_kvs((rs.get("resource") or {}).get("attributes"))
            for ss in rs.get(scopes) or []:
                scope = _json_scope(ss.get("scope"))
                records.extend(item_fn(i, resource, scope) for i in ss.get(items) or [])
    except (AttributeError, TypeError) as exc:
        raise DecodeError(f"malformed OTLP JSON: {exc}") from exc
    return records


def _is_json(content_type: str) -> bool:
    return "json" in (content_type or "").lower()


# ---------------------------------------------------------------- public API

def decode_traces(body: bytes, content_type: str) -> list[dict]:
    """Decode an ExportTraceServiceRequest into span capture records."""
    if _is_json(content_type):
        return _json_request(body, "resourceSpans", "scopeSpans", "spans", _json_span)
    return _pb_request(body, EXPORT_TRACE_RESOURCE_SPANS, RESOURCE_SPANS_RESOURCE,
                       RESOURCE_SPANS_SCOPE_SPANS, SCOPE_SPANS_SCOPE, SCOPE_SPANS_SPANS,
                       _pb_span)


def decode_logs(body: bytes, content_type: str) -> list[dict]:
    """Decode an ExportLogsServiceRequest into log capture records."""
    if _is_json(content_type):
        return _json_request(body, "resourceLogs", "scopeLogs", "logRecords", _json_log)
    return _pb_request(body, EXPORT_LOGS_RESOURCE_LOGS, RESOURCE_LOGS_RESOURCE,
                       RESOURCE_LOGS_SCOPE_LOGS, SCOPE_LOGS_SCOPE, SCOPE_LOGS_LOG_RECORDS,
                       _pb_log)
