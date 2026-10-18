import logging

from app.cve_matching.repository import find_cpe_names

logger = logging.getLogger(__name__)


def resolve_cpes(normalized):
    """Resolve software to official CPE names or versioned virtual targets, deduplicated by
    endpoint.

    Args:
        normalized (list[dict]): Normalized software records with part, vendor, product,
            version, and service.

    Returns:
        list[tuple[dict, str]]: Software records with resolution metadata paired with
            evaluated CPE names.
    """
    resolved = []
    seen = set()

    for software in normalized:
        part = software["part"]
        vendor = software["vendor"]
        product = software["product"]
        version = software["version"]
        service = software["service"]

        # 1. Tìm CPE chính thức từ PostgreSQL
        official_names = find_cpe_names(part=part, vendor=vendor, product=product, version=version)

        if official_names:
            candidates = [(name, "OFFICIAL") for name in official_names]
        else:
            # 2. Fallback: Match Criteria theo sản phẩm
            # Không coi đây là Official CPE Name.
            virtual_match = f"cpe:2.3:{part}:{vendor}:{product}:""*:*:*:*:*:*:*:*"
            # Chỉ dùng để kiểm tra version range nội bộ.
            target = (
                f"cpe:2.3:{part}:{vendor}:{product}:"
                f"{version}:*:*:*:*:*:*:*"
            )
            candidates = [(target, "VIRTUAL_MATCH")]
            logger.info("CPE fallback: product=%s version=%s query=%s", product, version, virtual_match)

        for cpe_name, method in candidates:
            key = (
                service.get("host"),
                service.get("port"),
                service.get("protocol"),
                cpe_name
            )
            if key in seen: continue
            seen.add(key)
            item = {**software, "cpe_resolution": method}

            if method == "VIRTUAL_MATCH":
                item["virtual_match_string"] = (
                    f"cpe:2.3:{part}:{vendor}:{product}:"
                    "*:*:*:*:*:*:*:*"
                )
            resolved.append((item, cpe_name))

    logger.info("Resolved %d official CPE records", len(resolved))

    return resolved
