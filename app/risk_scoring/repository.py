import json
import logging

from sqlalchemy import text
from app.common.database import db


logger = logging.getLogger(__name__)

def load_findings(scan_id: str, stage_run_id: str) -> list[dict]:

    # 1. Lấy CVE findings từ F1
    """Load candidate CVE findings and MATCH misconfigurations in a shared scoring format.

    Args:
        scan_id (str): Identifier of the scan whose records are being processed.
        stage_run_id (str): Identifier of the assessment stage execution.

    Returns:
        list[dict]: Findings with stable IDs, host, type, identifier, score, severity,
            and evidence.
    """
    with db.connect() as conn:
        cve_rows = conn.execute(
            text("""
                SELECT
                    finding_id,
                    host,
                    port, protocol, product, version, status, evidence,
                    cve_id,
                    cvss_score,
                    severity
                FROM vuln_finding
                WHERE scan_id = :scan_id
                  AND stage_run_id = :stage_run_id
                  AND status IN ('LIKELY_AFFECTED', 'POTENTIAL', 'NEEDS_REVIEW')
            """),
            {
                "scan_id": scan_id,
                "stage_run_id": stage_run_id
            }
        ).mappings().all()

        # 2. Lấy Misconfig findings từ F2
        misconfig_rows = conn.execute(
            text("""
                SELECT finding_id, device_ip, normalized_rule_id, external_rule_id, severity, evidence
                FROM vuln_misconfig_finding
                WHERE scan_id = :scan_id AND stage_run_id = :stage_run_id
                  AND evaluation_status = 'MATCH'
            """),
            {
                "scan_id": scan_id,
                "stage_run_id": stage_run_id
            }
        ).mappings().all()

    # 3. Chuẩn hóa tất cả findings
    findings = []

    for row in cve_rows:
        findings.append({
            "finding_id": str(row["finding_id"]),
            "type": "CVE",
            "host": row["host"],
            "port": row["port"],
            "protocol": row["protocol"],
            "product": row["product"],
            "version": row["version"],
            "status": row["status"],
            "evidence": row["evidence"] or {},
            "identifier": row["cve_id"],
            "score": (
                float(row["cvss_score"])
                if row["cvss_score"] is not None
                else None
            ),
            "severity": row["severity"]
        })

    for row in misconfig_rows:
        evidence = row["evidence"] or {}
        findings.append({
            "finding_id": str(row["finding_id"]),
            "type": "MISCONFIG",
            "host": row["device_ip"],
            "identifier": row["normalized_rule_id"],
            "external_rule_id": row["external_rule_id"],
            "port": evidence.get("port"),
            "protocol": evidence.get("protocol"),
            "evidence": evidence,
            "score": None,
            "severity": row["severity"]
        })

    return findings


def save_results(scan_id: str, stage_run_id: str, results: list[dict]):
    """Replace host risk summaries for one scan and stage, setting review status to
    PENDING.

    Args:
        scan_id (str): Identifier of the scan whose records are being processed.
        stage_run_id (str): Identifier of the assessment stage execution.
        results (list[dict]): Host scores, levels, counts, and recommendations; an empty
            list clears prior results.

    Returns:
        None: No return value.
    """
    with db.transaction() as conn:
        # Xóa kết quả cũ của cùng lần chạy stage
        conn.execute(
            text("""
                DELETE FROM vuln_risk_result
                WHERE scan_id = :scan_id AND stage_run_id = :stage_run_id
            """),
            {"scan_id": scan_id, "stage_run_id": stage_run_id}
        )

        if not results:
            logger.info("No risk scoring results to save scan=%s", scan_id)
            return

        # Lưu kết quả rủi ro của từng thiết bị
        sql = text("""
            INSERT INTO vuln_risk_result (
                scan_id, stage_run_id, host, risk_score, risk_level,
                finding_count, scored_count, recommendations, review_status
            )
            VALUES (
                :scan_id, :stage_run_id, :host, :risk_score, :risk_level,
                :finding_count, :scored_count,
                CAST(:recommendations AS jsonb), :review_status
            )
        """)

        params = [
            {
                **result,
                "scan_id": scan_id,
                "stage_run_id": stage_run_id,
                "recommendations": json.dumps(result["recommendations"]),
                "review_status": "PENDING"
            }
            for result in results
        ]

        conn.execute(sql, params)

    logger.info("Risk scoring results saved scan=%s hosts=%d", scan_id, len(results))
