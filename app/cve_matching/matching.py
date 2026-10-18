"""
Bước này Lấy mức độ nghiêm trọng và tạo Finding chứa thông tin thiết bị, phần mềm, phiên bản, CPE, mã CVE, điểm CVSS,
trạng thái đánh giá và bằng chứng như HTTP Banner cùng đường dẫn tham chiếu NVD.


"""
import re
from itertools import zip_longest

from packaging.version import Version, InvalidVersion


def compare_versions(a, b):
    """Compare numeric or OpenSSH-style versions, falling back to packaging.version.

    Args:
        a (str): First version string.
        b (str): Second version string.

    Returns:
        int | None: -1, 0, or 1 when a is lower, equal, or higher; None if parsing
            fails.
    """
    pattern = r"(\d+(?:\.\d+)*)(?:p(\d+))?"

    ma = re.fullmatch(pattern, a, re.IGNORECASE)
    mb = re.fullmatch(pattern, b, re.IGNORECASE)

    if ma and mb:
        va = [int(x) for x in ma.group(1).split(".")]
        vb = [int(x) for x in mb.group(1).split(".")]

        for x, y in zip_longest(va, vb, fillvalue=0):
            if x != y:
                return (x > y) - (x < y)

        pa = int(ma.group(2) or 0)
        pb = int(mb.group(2) or 0)

        return (pa > pb) - (pa < pb)

    try:
        va = Version(a)
        vb = Version(b)
        return (va > vb) - (va < vb)
    except InvalidVersion:
        return None


def check_criterion(criterion, cpe_name):
    """Check product identity, version bounds, and remaining CPE fields.

    Args:
        criterion (dict): NVD criteria string with optional inclusive or exclusive
            version bounds.
        cpe_name (str): Evaluated CPE 2.3 name with the observed version.

    Returns:
        bool | None: True for a match, False for a definite mismatch, or None when
            applicability cannot be determined.
    """
    expected = criterion["criteria"].split(":")
    actual = cpe_name.split(":")

    if len(expected) != 13 or len(actual) != 13:
        return None

    # Part, vendor, product
    for index in (2, 3, 4):
        if expected[index] not in ("*", actual[index]):
            return False

    # Exact version
    if expected[5] not in ("*", actual[5]):
        return False

    version = actual[5]

    bounds = (
        ("versionStartIncluding", -1, True),
        ("versionStartExcluding", -1, False),
        ("versionEndIncluding", 1, True),
        ("versionEndExcluding", 1, False)
    )

    for field, invalid_side, inclusive in bounds:
        bound = criterion.get(field)

        if not bound:
            continue

        result = compare_versions(version, bound)

        if result is None:
            return None

        if result == invalid_side:
            return False

        if result == 0 and not inclusive:
            return False

    # Các thành phần CPE khác chưa biết chính xác
    # thì không được khẳng định match hoàn toàn.
    for index in range(6, 13):
        if expected[index] not in ("*", actual[index]):
            return None

    return True


def match_cve(cve, cpe_name):
    """Evaluate direct vulnerable criteria, marking complex or uncertain configurations for
    review.

    Nested nodes, AND operators, and negation are not fully verified by this helper.

    Args:
        cve (dict): NVD CVE record containing configurations.
        cpe_name (str): Evaluated CPE 2.3 name.

    Returns:
        str | None: POTENTIAL, NEEDS_REVIEW, or None if no direct vulnerable criterion
            matches.
    """
    results = []

    for config in cve.get("configurations", []):
        config_complex = (config.get("operator") == "AND" or config.get("negate", False))

        for node in config.get("nodes", []):
            criteria = node.get("cpeMatch", [])

            node_complex = (
                    config_complex
                    or node.get("operator") == "AND"
                    or node.get("negate", False)
                    or bool(node.get("nodes"))
                    or any(not item.get("vulnerable", False) for item in criteria)
            )

            for item in criteria:
                if not item.get("vulnerable", False):
                    continue

                result = check_criterion(item, cpe_name)

                if result is False:
                    continue

                status = ("NEEDS_REVIEW" if result is None or node_complex else "POTENTIAL")
                results.append(status)

    if not results:
        return None

    if "POTENTIAL" in results:
        return "POTENTIAL"

    return "NEEDS_REVIEW"


def _severity_from_score(score):
    """Map a CVSS base score to its severity label.

    Args:
        score (float | None): CVSS base score; None means no score is available.

    Returns:
        str: UNKNOWN, NONE, LOW, MEDIUM, HIGH, or CRITICAL.
    """

    if score is None: return "UNKNOWN"
    if score == 0: return "NONE"
    if score < 4: return "LOW"
    if score < 7: return "MEDIUM"
    if score < 9: return "HIGH"
    return "CRITICAL"


def get_cvss(cve: dict) -> dict:
    """Select the newest valid CVSS metric, preferring NVD and primary records.

    Args:
        cve (dict): NVD CVE record with optional metrics for CVSS 4.0, 3.1, 3.0, or 2.0.

    Returns:
        dict: Score, severity, version, vector, source, and type; missing metrics
            produce an unknown score.
    """

    metrics = cve.get("metrics") or {}

    versions = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))

    for field, version in versions:
        records = metrics.get(field) or []
        if not records: continue

        valid_records = [
            record
            for record in records
            if isinstance(record, dict)
               and isinstance(record.get("cvssData"), dict)
               and record["cvssData"].get("baseScore") is not None
        ]

        if not valid_records: continue

        # Ưu tiên NVD đầu tiên khớp
        metric = min(
            valid_records,
            key=lambda record: (
                record.get("source") != "nvd@nist.gov",
                record.get("type", "").lower() != "primary",
            )
        )

        data = metric["cvssData"]

        try:
            score = float(data["baseScore"])
        except (ValueError, TypeError):
            continue

        if not 0 <= score <= 10: continue

        severity = (data.get("baseSeverity") or metric.get("baseSeverity"))

        severity = (str(severity).upper() if severity else _severity_from_score(score))

        if severity not in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            severity = _severity_from_score(score)

        return {
            "score": score,
            "severity": severity,
            "version": version,
            "vector": data.get("vectorString"),
            "source": metric.get("source"),
            "type": metric.get("type"),
        }

    return {
        "score": None,
        "severity": "UNKNOWN",
        "version": None,
        "vector": None,
        "source": None,
        "type": None,
    }