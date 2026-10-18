"""Truy vấn bảng `vuln_misconfig_rule_normalized` sau đó lựa chọn rule để áp dụng cho các thiết bị"""
import logging

from app.misconfig_detection.repository import MisconfigRuleRepository

logger = logging.getLogger(__name__)


class MisconfigRuleLoader:

    def __init__(self, repository: MisconfigRuleRepository | None = None):
        """Choose the repository used to load normalized rules.

        Args:
            repository (MisconfigRuleRepository | None): Injected repository; None
                creates the default database repository.

        Returns:
            None: No return value.
        """
        self.repository = repository or MisconfigRuleRepository()

    def load_enabled_rules(self) -> list[dict]:
        """Load structurally valid normalized rules without filtering enabled or execution
        status.

        Returns:
            list[dict]: Rules with dictionary specifications and conditions plus
                list-shaped evidence requirements.
        """

        records = self.repository.get_enabled_normalized_rules()
        rules = []

        for record in records:
            normalized = record.get("normalized_rule")

            if not isinstance(normalized, dict):
                logger.warning("Skipping invalid normalized rule: id=%s", record["id"])
                continue

            if not isinstance(normalized.get("condition"), dict):
                logger.warning("Skipping rule without condition: id=%s", record["id"])
                continue

            if not isinstance(normalized.get("required_evidence"), list):
                logger.warning("Skipping rule without evidence requirements: id=%s", record["id"])
                continue

            rules.append(record)

        logger.info("Rule loading completed: total=%d valid=%d", len(records), len(rules))
        return rules
