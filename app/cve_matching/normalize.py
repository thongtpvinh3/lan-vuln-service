"""Bước này chuẩn hóa thông tin phần mềm thành định dạng thống nhất"""
import re
import logging

from app.cve_matching.repository import (find_product_by_cpe, find_products)

logger = logging.getLogger(__name__)

MIN_MATCH_SCORE = 80


def _parse_cpe(cpe: str) -> dict | None:
    """Read concrete part, vendor, product, and version fields from CPE 2.2 or 2.3.

    Args:
        cpe (str): Candidate CPE identifier.

    Returns:
        dict | None: Parsed identity fields, or None for unsupported or incomplete
            identifiers.
    """

    if not isinstance(cpe, str): return None
    if cpe.startswith("cpe:2.3:"):
        fields = re.split(r"(?<!\\):", cpe)
        if len(fields) != 13: return None

        part, vendor, product, version = fields[2:6]

    elif cpe.startswith("cpe:/"):
        fields = re.split(r"(?<!\\):", cpe[5:])
        if len(fields) < 3: return None

        part, vendor, product = fields[:3]
        version = fields[3] if len(fields) > 3 else "*"
    else:
        return None

    if (
            part not in ("a", "o", "h")
            or not vendor
            or not product
            or vendor in ("*", "-")
            or product in ("*", "-")
    ):
        return None

    return {
        "part": part,
        "vendor": vendor,
        "product": product,
        "version": version
    }


def normalize(service: dict) -> dict | None:
    """Resolve an observation to an unambiguous dictionary product and observed version.

    Args:
        service (dict): Extracted software observation with product, version, and
            optional CPE hints.

    Returns:
        dict | None: Software identity, service, version, and resolution method; None
            for missing version, ambiguity, or insufficient match score.
    """
    raw_product = service.get("product") or ""
    raw_version = service.get("version")

    # OS fingerprint chưa được xác minh phiên bản
    # if service.get("source") == "OS_FINGERPRINT":
    #     logger.info("Skipping unverified OS fingerprint: %s", raw_product)
    #     return None

    product_name = " ".join(str(raw_product).lower().split())

    if raw_version is None: return None

    version = str(raw_version).strip()
    if not version: return None

    # 1. Ưu tiên CPE do Nmap cung cấp
    hints = service.get("cpe_hint") or []

    if isinstance(hints, str): hints = [hints]

    confirmed = {}

    for hint in hints:
        parsed = _parse_cpe(hint)
        if parsed is None: continue

        # # Không chấp nhận CPE có version mâu thuẫn với version mà Discovery đã xác định.
        # cpe_version = parsed["version"]
        #
        # if cpe_version not in ("*", "-") and cpe_version != version:
        #     logger.warning("CPE version mismatch: %s, version=%s", hint, version)
        #     return None

        product = find_product_by_cpe(parsed["part"], parsed["vendor"], parsed["product"])

        if product is not None:
            key = (
                product["part"],
                product["vendor"],
                product["product"]
            )
            confirmed[key] = product

    if len(confirmed) == 1:
        product = next(iter(confirmed.values()))
        return {
            "service": service,
            "part": product["part"],
            "vendor": product["vendor"],
            "product": product["product"],
            "version": version,
            "resolution_method": "NMAP_CPE"
        }

    if len(confirmed) > 1:
        logger.warning("Ambiguous Nmap CPE: %s", list(confirmed))
        return None

    # 2. Fallback: tìm trực tiếp theo tên phần mềm
    if not product_name: return None
    candidates = find_products(product_name)
    if not candidates:
        logger.info("Product not found: %s", product_name)
        return None

    best_score = max(item["score"] for item in candidates)
    if best_score < MIN_MATCH_SCORE: return None

    best_matches = [item for item in candidates if item["score"] == best_score]

    if len(best_matches) != 1:
        logger.warning("Ambiguous product: %s", product_name)
        return None

    product = best_matches[0]

    return {
        "service": service,
        "part": product["part"],
        "vendor": product["vendor"],
        "product": product["product"],
        "version": version,
        "resolution_method": "PRODUCT_NAME"
    }
