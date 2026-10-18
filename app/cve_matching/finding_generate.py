"""Chịu trách nhiệm tập hợp thông tin phần mềm, CVE, CVSS, phương thức CPE Resolution và bằng chứng thành một Finding thống nhất"""
from app.cve_matching.matching import get_cvss


def build_finding(software: dict, cpe_name: str, cve: dict, status: str) -> dict:
    """Combine software, CVE severity, resolution details, and evidence into a finding.

    Args:
        software (dict): Normalized software record containing service, product,
            version, and resolution metadata.
        cpe_name (str): Official or virtual CPE evaluated for the observed software.
        cve (dict): NVD CVE record with id and optional metrics.
        status (str): Applicability classification, normally POTENTIAL or NEEDS_REVIEW.

    Returns:
        dict: CVE finding with endpoint identity, score, status, and NVD reference
            evidence.
    """
    service = software["service"]
    cve_id = cve["id"]
    cvss = get_cvss(cve)
    method = software.get("cpe_resolution", "OFFICIAL")

    return {
        "host": service["host"],
        "port": service.get("port"),
        "protocol": service.get("protocol"),
        "product": software["product"],
        "version": software["version"],
        "cpe": cpe_name,
        "cve_id": cve_id,
        "cvss_score": cvss["score"],
        "severity": cvss["severity"],
        "status": status,
        "evidence": {
            "source": "NVD",
            "detection_source": service.get("source"),
            "banner": service.get("banner"),
            "state": service.get("state"),
            "service": service.get("product"),
            "metadata": service.get("metadata") or {},
            "cpe_hint": service.get("cpe_hint"),
            "cpe_resolution": method,
            "official_cpe_name": (cpe_name if method == "OFFICIAL" else None),
            "evaluated_cpe": cpe_name,
            "virtual_match_string": software.get("virtual_match_string"),
            "cvss": {
                "version": cvss["version"],
                "vector": cvss["vector"],
                "source": cvss["source"],
                "type": cvss["type"]
            },
            "patch_status": "UNKNOWN",
            "reference": ("https://nvd.nist.gov/vuln/detail/" + cve_id)
        }
    }
