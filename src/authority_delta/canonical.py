"""Canonical JSON and content identity helpers."""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented by the approved JCS encoder."""


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785 JSON bytes for a JSON-compatible value."""

    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonicalize(value))
