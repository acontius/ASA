"""Shared CPE identity comparisons for benchmark predictions and Gold labels."""
from __future__ import annotations

from app.cpe.parser import parse_cpe23
from app.cpe.resolver import product_key, version_key

_CPE_FIELDS = {"product_name": "product", "product": "product", "vendor": "vendor", "version": "version", "update": "update", "part": "part"}


def _key(field: str, value: str) -> str:
    if field in {"product", "product_name", "vendor"}:
        return product_key(value)
    if field in {"version", "update"}:
        return version_key(value)
    return value.casefold().strip()


def identity_value_matches(field: str, actual: str | None, expected: str | None) -> bool | None:
    """Compare an extracted identity component; None/'*' Gold values are unscored."""
    if expected is None or not isinstance(expected, str) or not expected.strip() or expected.strip() == "*":
        return None
    if not isinstance(actual, str) or not actual.strip():
        return False
    if expected.strip() == "-":
        return actual.strip() == "-"
    if actual.strip() == "*":
        return False
    return _key(field, actual) == _key(field, expected)


def compare_cpe_identity(cpe_name: str, identity: dict) -> dict:
    """Compare every specified identity field; null and '*' expectations are unconstrained.

    A CPE wildcard cannot establish a concrete expected identity. CPE '-' is the
    explicit not-applicable value and only matches an expected '-'. Product is
    required for a runtime identity result; other fields are optional unless
    the supplied identity specifies them.
    """
    parsed = parse_cpe23(cpe_name)
    checks: dict[str, bool | None] = {}
    for identity_field, cpe_field in _CPE_FIELDS.items():
        if identity_field == "product" and "product_name" in identity:
            continue
        expected = identity.get(identity_field)
        if expected is None or not isinstance(expected, str) or not expected.strip() or expected.strip() == "*":
            checks[identity_field] = None
            continue
        actual = getattr(parsed, cpe_field)
        if expected.strip() == "-":
            checks[identity_field] = actual == "-"
            continue
        checks[identity_field] = parsed.is_concrete(cpe_field) and identity_value_matches(identity_field, actual, expected)

    # Gold uses expected_product while runtime predictions use product_name.
    product_value = identity.get("product_name", identity.get("product"))
    if product_value is None or not isinstance(product_value, str) or not product_value.strip() or product_value.strip() == "*":
        checks["product_name"] = None
    elif product_value.strip() == "-":
        checks["product_name"] = False
    else:
        checks["product_name"] = parsed.is_concrete("product") and identity_value_matches("product_name", parsed.product, product_value)

    specified = [result for result in checks.values() if result is not None]
    return {"valid": bool(checks.get("product_name")) and all(specified), "fields": checks}


def gold_identity(gold: dict) -> dict:
    return {
        "product_name": gold.get("expected_product"),
        "vendor": gold.get("expected_vendor"),
        "version": gold.get("expected_version"),
        "update": gold.get("expected_update"),
        "part": gold.get("expected_part"),
    }
