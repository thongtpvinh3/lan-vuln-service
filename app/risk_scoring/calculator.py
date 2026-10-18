
"""Calculate aggregate risk score for one host."""

from typing import Any


MISCONFIG_SCORES = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 2.5,
    "INFO": 0.0,
}

ADDITIONAL_FINDING_WEIGHT = 0.2
POLICY_VERSION = "mvp-1"
MANAGEMENT_PORTS = {22, 23, 3389, 5985, 5986}


def calculate_finding(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Calculate one finding score with the management-port bonus and explanation.

    Args:
        finding (dict[str, Any]): Finding with finding_id, type, base score or severity,
            and optional endpoint evidence.

    Returns:
        dict[str, Any] | None: Finding ID, capped risk score, and explanation; None if
            no valid base score exists.
    """
    base = get_finding_score(finding)
    if base is None:
        return None

    contributions = []
    reasons = []
    evidence = finding.get("evidence") or {}
    if (finding.get("protocol") == "tcp"
            and type(finding.get("port")) is int
            and finding["port"] in MANAGEMENT_PORTS
            and evidence.get("state") == "open"):
        contributions.append({"factor": "management_port_exposed", "delta": 1.0})
        reasons.append("Management service exposed")

    score = min(10.0, max(0.0, base + sum(item["delta"] for item in contributions)))
    return {
        "finding_id": finding["finding_id"],
        "risk_score": round(score, 1),
        "explanation": {
            "policy_version": POLICY_VERSION,
            "base": base,
            "base_source": "cvss" if str(finding.get("type")).upper() == "CVE" else "severity",
            "contributions": contributions,
            "reasons": reasons,
        },
    }


def get_finding_score(finding: dict[str, Any]) -> float | None:
    """Read a valid CVSS score or map misconfiguration severity to a base score.

    Args:
        finding (dict[str, Any]): Finding containing type and either score or severity.

    Returns:
        float | None: Base score from 0 to 10, or None for unsupported or unscoreable
            findings.
    """
    finding_type = str(finding.get("type") or "").upper()

    if finding_type == "CVE":
        score = finding.get("score")
        if score is None: return None

        try:
            score = float(score)
        except (TypeError, ValueError):
            return None

        if not 0.0 <= score <= 10.0: return None

        return score

    if finding_type == "MISCONFIG":
        severity = str(finding.get("severity") or "").upper()
        return MISCONFIG_SCORES.get(severity)

    return None


def get_risk_level(score: float) -> str:
    """Classify a numeric risk score using the configured severity thresholds.

    Args:
        score (float): Aggregate risk score to classify.

    Returns:
        str: CRITICAL, HIGH, MEDIUM, LOW, or NONE.
    """
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0: return "LOW"
    return "NONE"


def calculate(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Deduplicate host findings and aggregate the highest base score with a finding-count
    increment.

    Args:
        findings (list[dict[str, Any]]): Findings for one host with type, identifier,
            and score or severity.

    Returns:
        dict[str, Any]: Aggregate score, level, finding_count, and scored_count; no
            valid scores yields zero risk.
    """
    unique_findings = {}

    for finding in findings:
        key = (str(finding.get("type") or "").upper(), str(finding.get("identifier") or ""))

        # Ignore malformed records with missing identity
        if not key[0] or not key[1]: continue

        score = get_finding_score(finding)
        existing = unique_findings.get(key)

        # Keep the record with the highest valid score
        if existing is None:
            unique_findings[key] = (finding, score)
        elif score is not None and (existing[1] is None or score > existing[1]):
            unique_findings[key] = (finding, score)

    # 2. Collect valid scores
    scores = [
        score
        for _, score in unique_findings.values()
        if score is not None
    ]

    finding_count = len(unique_findings)
    scored_count = len(scores)

    # 3. No scoreable findings
    if not scores:
        return {
            "score": 0.0,
            "level": "NONE",
            "finding_count": finding_count,
            "scored_count": 0,
        }

    # 4. Calculate aggregate risk
    max_score = max(scores)

    if max_score == 0.0:
        risk_score = 0.0
    else:
        risk_score = min(10.0, max_score + ADDITIONAL_FINDING_WEIGHT * (scored_count - 1))

    risk_score = round(risk_score, 2)

    # 5. Classify result
    return {
        "score": risk_score,
        "level": get_risk_level(risk_score),
        "finding_count": finding_count,
        "scored_count": scored_count,
    }
