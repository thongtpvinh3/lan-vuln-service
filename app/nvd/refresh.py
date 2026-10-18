import logging

from sqlalchemy import text

from app.common.database import db
from app.nvd.catalog import NvdCatalog

logger = logging.getLogger(__name__)


def refresh():
    """Force refresh recognized CPE and official-CVE cache keys, logging per-key failures.

    Returns:
        None: No return value.
    """
    catalog = NvdCatalog()

    with db.connect() as conn:
        keys = conn.execute(text("SELECT cache_key FROM vuln_nvd_cache ORDER BY cache_key")).scalars().all()

    for key in keys:
        try:
            if key.startswith("cpe|"):
                parts = key.split("|")

                if len(parts) != 5:
                    logger.warning("Invalid CPE cache key: %s", key)
                    continue

                _, part, vendor, product, version = parts

                catalog.cpes(
                    {
                        "part": part,
                        "vendor": vendor,
                        "product": product,
                        "version": version
                    },
                    force=True
                )

            elif key.startswith("cves|"):
                cpe_name = key.removeprefix("cves|")

                if not cpe_name:
                    logger.warning("Invalid CVE cache key: %s", key)
                    continue

                catalog.cves(cpe_name, force=True)

            else:
                logger.warning("Unknown NVD cache key: %s", key)
                continue

            logger.info("Refreshed NVD cache: %s", key)

        except Exception:
            logger.exception("Cannot refresh NVD cache: %s", key)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    refresh()
