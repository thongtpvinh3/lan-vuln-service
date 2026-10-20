"""Lưu trữ Misconfiguration Findings trong PostgreSQL."""

import logging

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB

from app.common.database import db

logger = logging.getLogger(__name__)


class MisconfigFindingRepository:

    INSERT_SQL = text("""
        INSERT INTO vuln_misconfig_finding (
            finding_id, scan_id, stage_run_id, device_ip, normalized_rule_id,
            external_rule_id, title, severity, evaluation_status,
            reason, evidence
        )
        VALUES (
            :finding_id, :scan_id, :stage_run_id, :ip, :normalized_rule_id,
            :external_rule_id, :title, :severity, :evaluation_status,
            :reason, :evidence
        )
        ON CONFLICT (stage_run_id, device_ip, normalized_rule_id)
        DO UPDATE SET
            finding_id = EXCLUDED.finding_id,
            external_rule_id = EXCLUDED.external_rule_id,
            title = EXCLUDED.title,
            severity = EXCLUDED.severity,
            reason = EXCLUDED.reason,
            evidence = EXCLUDED.evidence
    """).bindparams(bindparam("evidence", type_=JSONB))

    def save(self, findings: list[dict]) -> int:
        """Lưu danh sách Finding vào PostgreSQL."""
        if not findings:
            return 0

        with db.transaction() as conn:
            for finding in findings:
                conn.execute(self.INSERT_SQL, finding)

        logger.info("Saved misconfiguration findings: count=%d", len(findings))
        return len(findings)

    @staticmethod
    def get_by_scan(scan_id: str) -> list[dict]:
        """Lấy tất cả Finding thuộc một lần quét."""
        sql = text("""
            SELECT *
            FROM vuln_misconfig_finding
            WHERE scan_id = :scan_id
            ORDER BY id
        """)

        with db.connect() as conn:
            rows = conn.execute(sql, {"scan_id": scan_id}).mappings().all()

        return [dict(row) for row in rows]

    @staticmethod
    def get_by_stage(stage_run_id: str) -> list[dict]:
        """Lấy Finding thuộc một lần thực thi Assessment Stage."""
        sql = text("""
            SELECT *
            FROM vuln_misconfig_finding
            WHERE stage_run_id = :stage_run_id
            ORDER BY id
        """)

        with db.connect() as conn:
            rows = conn.execute(sql, {"stage_run_id": stage_run_id}).mappings().all()

        return [dict(row) for row in rows]
