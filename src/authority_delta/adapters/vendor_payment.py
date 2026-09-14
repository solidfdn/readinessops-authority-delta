"""VendorPayment sample rules, isolated from shared ReadinessOps decisions."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping
from ..decisions import ContractError, Judgment

@dataclass(frozen=True)
class ReleaseDefinition:
    release_id: str
    max_amount_minor: int
    currency: str
    verified_changed_bank_methods: tuple[str, ...]
    description_change_only: bool = False

    @classmethod
    def from_mapping(cls, release_id: str, value: Mapping[str, Any]) -> "ReleaseDefinition":
        required = {"max_amount_minor", "currency", "verified_changed_bank_methods"}
        allowed = required | {"description_change_only"}
        if set(value) - allowed or not required <= set(value):
            raise ContractError(f"Invalid release fields for {release_id}")
        methods = value["verified_changed_bank_methods"]
        if not isinstance(methods, list) or not all(isinstance(item, str) and item for item in methods):
            raise ContractError(f"Invalid verification methods for {release_id}")
        if methods != sorted(set(methods)):
            raise ContractError(f"Verification methods must be unique and sorted for {release_id}")
        if not isinstance(value["max_amount_minor"], int) or value["max_amount_minor"] < 0:
            raise ContractError(f"Invalid amount limit for {release_id}")
        if not isinstance(value["currency"], str) or not value["currency"]:
            raise ContractError(f"Invalid currency for {release_id}")
        return cls(
            release_id=release_id,
            max_amount_minor=value["max_amount_minor"],
            currency=value["currency"],
            verified_changed_bank_methods=tuple(methods),
            description_change_only=value.get("description_change_only", False),
        )

    def as_contract(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "release_id": self.release_id,
            "max_amount_minor": self.max_amount_minor,
            "currency": self.currency,
            "verified_changed_bank_methods": list(self.verified_changed_bank_methods),
        }
        if self.description_change_only:
            result["description_change_only"] = True
        return result


@dataclass(frozen=True)
class BoundaryDefinition:
    max_amount_minor: int
    currency: str
    require_known_vendor: bool
    require_po_match: bool
    verified_changed_bank_methods: tuple[str, ...]
    forbidden_actions: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "BoundaryDefinition":
        required = {
            "max_amount_minor",
            "currency",
            "require_known_vendor",
            "require_po_match",
            "verified_changed_bank_methods",
            "forbidden_actions",
        }
        if set(value) != required:
            raise ContractError("Invalid boundary fields")
        methods = value["verified_changed_bank_methods"]
        forbidden = value["forbidden_actions"]
        for label, items in (("verification methods", methods), ("forbidden actions", forbidden)):
            if not isinstance(items, list) or not all(isinstance(item, str) and item for item in items):
                raise ContractError(f"Invalid {label}")
            if items != sorted(set(items)):
                raise ContractError(f"{label.capitalize()} must be unique and sorted")
        if not isinstance(value["max_amount_minor"], int) or value["max_amount_minor"] < 0:
            raise ContractError("Invalid boundary amount")
        if type(value["require_known_vendor"]) is not bool or type(value["require_po_match"]) is not bool:
            raise ContractError("Boundary requirements must be booleans")
        return cls(
            max_amount_minor=value["max_amount_minor"],
            currency=value["currency"],
            require_known_vendor=value["require_known_vendor"],
            require_po_match=value["require_po_match"],
            verified_changed_bank_methods=tuple(methods),
            forbidden_actions=tuple(forbidden),
        )

    def as_contract(self) -> dict[str, Any]:
        return {
            "max_amount_minor": self.max_amount_minor,
            "currency": self.currency,
            "require_known_vendor": self.require_known_vendor,
            "require_po_match": self.require_po_match,
            "verified_changed_bank_methods": list(self.verified_changed_bank_methods),
            "forbidden_actions": list(self.forbidden_actions),
        }


def _payment_is_well_formed(request: Mapping[str, Any]) -> bool:
    required = {
        "fixture_dataset_id",
        "action",
        "vendor_id",
        "vendor_is_known",
        "amount_minor",
        "currency",
        "po_matches",
        "bank_changed",
        "verification",
        "destination_account_ref",
    }
    return (
        set(request) == required
        and request.get("action") == "prepare_vendor_payment"
        and isinstance(request.get("fixture_dataset_id"), str)
        and isinstance(request.get("vendor_id"), str)
        and type(request.get("vendor_is_known")) is bool
        and isinstance(request.get("amount_minor"), int)
        and request.get("amount_minor") >= 0
        and isinstance(request.get("currency"), str)
        and type(request.get("po_matches")) is bool
        and type(request.get("bank_changed")) is bool
        and isinstance(request.get("verification"), str)
        and isinstance(request.get("destination_account_ref"), str)
    )


def judge_release(release: ReleaseDefinition, request: Mapping[str, Any]) -> Judgment:
    """Execute one release's business judgment without writing a ledger."""

    action = request.get("action")
    if action in {"update_vendor_bank", "export_credentials"}:
        return Judgment.DO_NOT_DELEGATE
    if action != "prepare_vendor_payment" or not _payment_is_well_formed(request):
        return Judgment.UNKNOWN
    if request["currency"] != release.currency:
        return Judgment.HUMAN_REVIEW
    if not request["vendor_is_known"]:
        return Judgment.HUMAN_REVIEW
    if request["amount_minor"] > release.max_amount_minor:
        return Judgment.HUMAN_REVIEW
    if not request["po_matches"]:
        return Judgment.HUMAN_REVIEW
    if request["bank_changed"] and request["verification"] not in release.verified_changed_bank_methods:
        return Judgment.HUMAN_REVIEW
    return Judgment.ALLOW


def boundary_allows(boundary: BoundaryDefinition, request: Mapping[str, Any]) -> bool:
    """Evaluate a trusted immutable request against an approved authority boundary."""

    action = request.get("action")
    if action in boundary.forbidden_actions or action != "prepare_vendor_payment":
        return False
    if not _payment_is_well_formed(request):
        return False
    if request["currency"] != boundary.currency:
        return False
    if boundary.require_known_vendor and not request["vendor_is_known"]:
        return False
    if request["amount_minor"] > boundary.max_amount_minor:
        return False
    if boundary.require_po_match and not request["po_matches"]:
        return False
    if request["bank_changed"] and request["verification"] not in boundary.verified_changed_bank_methods:
        return False
    return True
