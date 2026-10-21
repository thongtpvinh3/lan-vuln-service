
"""Calculate aggregate risk score for one host."""

from typing import Any
from math import fsum


MISCONFIG_SCORES = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 2.5,
    "INFO": 0.0,
}

POLICY_VERSION = "mvp-1"
MANAGEMENT_PORTS = {22, 23, 3389, 5985, 5986}


def calculate_finding(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Tính điểm từng finding và ghi rõ các yếu tố cộng điểm."""
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
    """Classify the uncapped sum of finding risk scores for one host."""
    if score >= 60.0: return "CRITICAL"
    if score >= 30.0: return "HIGH"
    if score >= 10.0: return "MEDIUM"
    if score > 0.0: return "LOW"
    return "NONE"


def calculate(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Sum each distinct finding's published risk score, without a host cap."""
    unique_findings = {}

    for finding in findings:
        finding_id = finding.get("finding_id")
        if not finding_id or finding_id == "None":
            continue
        unique_findings.setdefault(finding_id, finding)

    scores = [
        result["risk_score"]
        for finding in unique_findings.values()
        if (result := calculate_finding(finding)) is not None
    ]

    finding_count = len(unique_findings)
    scored_count = len(scores)
    risk_score = round(fsum(scores), 2)
    return {
        "score": risk_score,
        "level": get_risk_level(risk_score),
        "finding_count": finding_count,
        "scored_count": scored_count,
    }
