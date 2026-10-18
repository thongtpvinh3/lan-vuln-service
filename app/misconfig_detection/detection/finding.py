"""Tạo Misconfiguration Finding từ kết quả Rule Engine."""

from copy import deepcopy
from app.common.finding_id import create_finding_id


class MisconfigFindingFactory:
    """Chuyển kết quả đánh giá MATCH thành Finding."""

    @staticmethod
    def create(scan_id: str, stage_run_id: str, evaluation: dict, rule: dict, device: dict) -> dict:
        """Create a stable misconfiguration finding from a consistent MATCH evaluation.

        Raise ValueError if IDs disagree, scan or stage IDs are missing, or evidence is
        empty.

        Args:
            scan_id (str): Identifier of the scan whose records are being processed.
            stage_run_id (str): Identifier of the assessment stage execution.
            evaluation (dict): MATCH result with device_ip, normalized_rule_id, and
                nonempty evidence.
            rule (dict): Rule record with identifiers and a normalized_rule
                specification.
            device (dict): Normalized device evidence containing ip, os, and ports.

        Returns:
            dict: Persistable finding with deterministic ID, severity, reason, and
                copied supporting evidence.
        """
        if evaluation.get("status") != "MATCH":
            raise ValueError("Only MATCH evaluations can create findings")

        if not scan_id or not stage_run_id:
            raise ValueError("Scan ID and stage run ID are required")

        if evaluation.get("device_ip") != device.get("ip"):
            raise ValueError("Evaluation device IP does not match")

        if evaluation.get("normalized_rule_id") != rule.get("id"):
            raise ValueError("Evaluation rule ID does not match")

        if not isinstance(evaluation.get("evidence"), dict) or not evaluation["evidence"]:
            raise ValueError("Finding must contain supporting evidence")

        return {
            "finding_id": create_finding_id("MISCONFIG", scan_id, stage_run_id, device["ip"], rule["id"]),
            "scan_id": scan_id,
            "stage_run_id": stage_run_id,
            "device_ip": device["ip"],
            "normalized_rule_id": rule["id"],
            "external_rule_id": rule.get("external_rule_id"),
            "title": rule.get("title") or rule.get("external_rule_id") or "Misconfiguration detected",
            "severity": rule.get("severity") or "UNKNOWN",
            "evaluation_status": "MATCH",
            "reason": evaluation.get("reason"),
            "evidence": deepcopy(evaluation["evidence"])
        }
