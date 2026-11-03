"""Canary values derived from one per-run seed, and detection of those values in captured text."""

from __future__ import annotations

import re
from urllib.parse import unquote, unquote_plus

TEST_CARD = "4111111111111111"  # documented test PAN; passes Luhn
_SEED_RE = re.compile(r"[A-Za-z0-9_-]+")


def _check_seed(seed: str) -> None:
    if not isinstance(seed, str) or not _SEED_RE.fullmatch(seed):
        raise ValueError(f"canary seed must match [A-Za-z0-9_-]+; got {seed!r}")


def canary_values(seed: str) -> dict[str, str]:
    """Canary values to send through the app's tests (header, query, cookie, body, exception input)."""
    _check_seed(seed)
    token = f"otelcanary_{seed}"
    return {
        "bearer": f"Bearer {token}",
        "api_key": token,
        "cookie": f"session={token}",
        "email": f"canary+{seed}@example.invalid",
        "card": TEST_CARD,
        "name": f"Canary Person {seed}",
    }


def find_canaries(text: str, seed: str) -> list[str]:
    """Kinds whose distinctive token appears in `text`, in order token, email, card, name.

    The bearer, api_key, and cookie canaries share `otelcanary_<seed>` and report as "token".
    Percent- and form-encoded forms (as found in url.query or http.target) are also recognized.
    """
    _check_seed(seed)
    tokens = (
        ("token", f"otelcanary_{seed}"),
        ("email", f"canary+{seed}@example.invalid"),
        ("card", TEST_CARD),
        ("name", f"Canary Person {seed}"),
    )
    variants = {text}
    if "%" in text or "+" in text:
        variants.add(unquote(text))
        variants.add(unquote_plus(text))
    return [kind for kind, needle in tokens if any(needle in v for v in variants)]
