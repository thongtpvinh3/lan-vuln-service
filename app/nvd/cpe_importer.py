import json
import logging
import time

import requests
from sqlalchemy import text

from app.common.database import db
from app.common.config import ServiceConfig

logger = logging.getLogger(__name__)

NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def parse_cpe(cpe_name: str) -> dict:
    # Split dấu ':' nhưng bỏ qua ':' đã được escape bằng '\'
    """Split a CPE 2.3 name while respecting escaped colons; reject malformed names.

    Args:
        cpe_name (str): Complete CPE 2.3 formatted name with thirteen fields.

    Returns:
        dict: Parsed part, vendor, product, and version fields.
    """
    fields = []
    current = []
    backslashes = 0

    for char in cpe_name:
        if char == ":" and backslashes % 2 == 0:
            fields.append("".join(current))
            current = []
        else:
            current.append(char)

        backslashes = backslashes + 1 if char == "\\" else 0

    fields.append("".join(current))

    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]: raise ValueError(f"Invalid CPE: {cpe_name}")

    return {
        "part": fields[2],
        "vendor": fields[3],
        "product": fields[4],
        "version": fields[5],
    }


def save_cpes(products: list):
    """Insert NVD CPE products into the local dictionary, skipping existing IDs.

    Args:
        products (list[dict]): NVD product objects containing a cpe record and its
            metadata.

    Returns:
        int: Number of inserted rows reported by the database, or zero for empty input.
    """
    sql = text("""
               INSERT INTO vuln_cpe_dictionary (
                    cpe_name_id,
                    cpe_name,
                    part,
                    vendor,
                    product,
                    version,
                    display_name,
                    deprecated,
                    titles,
                    refs,
                    deprecated_by,
                    raw_data,
                    nvd_created_at,
                    nvd_modified_at,
                    synced_at
               )
               VALUES (
                    CAST(:cpe_name_id AS UUID),
                    :cpe_name,
                    :part,
                    :vendor,
                    :product,
                    :version,
                    :display_name,
                    :deprecated,
                    CAST(:titles AS JSONB),
                    CAST(:refs AS JSONB),
                    CAST(:deprecated_by AS JSONB),
                    CAST(:raw_data AS JSONB),
                    CAST(:nvd_created_at AS TIMESTAMPTZ),
                    CAST(:nvd_modified_at AS TIMESTAMPTZ),
                    NOW()
              )
               ON CONFLICT (cpe_name_id) DO NOTHING
               """)

    rows = []

    for item in products:
        cpe = item["cpe"]
        fields = parse_cpe(cpe["cpeName"])

        titles = cpe.get("titles", [])
        display_name = next(
            (title["title"] for title in titles
             if title.get("lang") == "en"),
            None
        )

        rows.append({
            "cpe_name_id": cpe["cpeNameId"],
            "cpe_name": cpe["cpeName"],
            **fields,
            "display_name": display_name,
            "deprecated": cpe.get("deprecated", False),
            "titles": json.dumps(titles),
            "refs": json.dumps(cpe.get("refs", [])),
            "deprecated_by": json.dumps(cpe.get("deprecatedBy", [])),
            "raw_data": json.dumps(cpe),
            "nvd_created_at": cpe.get("created"),
            "nvd_modified_at": cpe.get("lastModified"),
        })

    if not rows: return 0
    with db.transaction() as conn: result = conn.execute(sql, rows)
    return result.rowcount


def fetch_cpes(keyword: str | None = None, limit: int | None = 100, start_index: int = 0):
    """Page through NVD CPE products with retries and save new dictionary entries.

    Args:
        keyword (str | None): Optional NVD keywordSearch filter.
        limit (int | None): Target maximum new-row count; None fetches until results are
            exhausted. Defaults to 100.
        start_index (int): Initial NVD result offset; defaults to 0.

    Returns:
        int: Total newly inserted rows reported across fetched pages.
    """
    config = ServiceConfig.from_env()
    headers = {"Accept": "application/json"}
    if config.nvd_api_key: headers["apiKey"] = config.nvd_api_key

    session = requests.Session()
    session.headers.update(headers)

    total_saved = 0
    index = start_index
    interval = max(config.nvd_request_interval, 0)

    try:
        while True:
            page_size = 500

            if limit is not None:
                remaining = limit - total_saved
                if remaining <= 0: break
                page_size = min(page_size, remaining)

            params = {"startIndex": index, "resultsPerPage": page_size}

            if keyword: params["keywordSearch"] = keyword

            for attempt in range(5):
                try:
                    response = session.get(NVD_CPE_URL, headers=headers, params=params, timeout=90)
                    response.raise_for_status()
                    data = response.json()

                    if not isinstance(data.get("products"), list):
                        raise ValueError("Invalid NVD products response")

                    break

                except (requests.RequestException, ValueError):
                    if attempt == 4:
                        raise

                    time.sleep(min(60, 5 * (2 ** attempt)))

            products = data["products"]
            total_results = data["totalResults"]

            if not products: break

            saved = save_cpes(products)

            total_saved += saved
            index += len(products)

            logger.info("Saved=%s, Total=%s, NextIndex=%s, NVDTotal=%s", saved, total_saved, index, total_results)

            if index >= total_results: break
            if limit is not None and total_saved >= limit: break
            time.sleep(interval)

    finally:
        session.close()

    return total_saved


# def main():
#     logging.basicConfig(
#         level=logging.INFO,
#         format="%(asctime)s [%(levelname)s] %(message)s"
#     )
#
#     popular_products = [
#         # Operating Systems
#         "Microsoft Windows",
#         "Ubuntu Linux",
#         "Debian Linux",
#         "OpenWrt",
#
#         # Web Servers
#         "Apache HTTP Server",
#         "Nginx",
#         "Microsoft IIS",
#
#         # Remote Access
#         "OpenSSH",
#         "Dropbear SSH",
#
#         # Security Libraries
#         "OpenSSL",
#
#         # Database Servers
#         "MySQL",
#         "PostgreSQL",
#         "MariaDB",
#
#         # Network Services
#         "Samba",
#         "vsftpd",
#         "ProFTPD",
#         "BIND DNS",
#         "ISC DHCP",
#
#         # Application Servers
#         "Apache Tomcat",
#         "Redis"
#     ]
#
#     total = 0
#
#     for product in popular_products:
#         try:
#             logger.info("Fetching CPE: %s", product)
#
#             count = fetch_cpes(
#                 keyword=product,
#                 limit=500
#             )
#
#             total += count
#
#             logger.info(
#                 "Completed: %s | Imported: %d",
#                 product,
#                 count
#             )
#
#         except Exception:
#             logger.exception(
#                 "Failed to fetch CPE: %s",
#                 product
#             )
#
#     logger.info(
#         "Finished importing popular CPEs. Total processed: %d",
#         total
#     )
#
#
# if __name__ == "__main__":
#     main()
