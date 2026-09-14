"""Shared judgments and human-decision vocabulary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping


class ContractError(ValueError):
    pass


class Judgment(StrEnum):
    ALLOW = "ALLOW"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    DO_NOT_DELEGATE = "DO_NOT_DELEGATE"
    UNKNOWN = "UNKNOWN"


class Decision(StrEnum):
    MAINTAIN = "MAINTAIN"
    NARROW = "NARROW"
    REJECT = "REJECT"


class GatewayExpectation(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


