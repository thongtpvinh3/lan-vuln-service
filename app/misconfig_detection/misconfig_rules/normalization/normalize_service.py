"""điều phối đọc Catalog -> Normalize -> Save"""
import logging
from collections import Counter

from app.misconfig_detection.misconfig_rules.normalization.mapping_rule_normalizer import MisconfigRuleNormalizer
from app.misconfig_detection.repository import MisconfigRuleRepository

logger = logging.getLogger(__name__)


class MisconfigRuleNormalizationService:
    """
    Normalizer service thực hiện:
        1. Load Raw Rules
        2. Load Reviewed Mappings
        3. Ghép Rule với Mapping theo: source_id + source_file + content_sha256
        4. Validate Mapping
        5. Generate normalized_rule
        6. Update vuln_misconfig_rule
    """

    def __init__(self):
        """Create the rule repository and mapping-based normalizer.

        Returns:
            None: No return value.
        """
        self.repository = MisconfigRuleRepository()
        self.normalizer = MisconfigRuleNormalizer()

    @staticmethod
    def _empty_result() -> dict:
        """Build a zero-count normalization summary for empty work.

        Returns:
            dict: Zeroed input, mapping, normalization, persistence, and status counts.
        """
        return {
            "total": 0,
            "mapped": 0,
            "without_mapping": 0,
            "normalized": 0,
            "updated": 0,
            "supported": 0,
            "unsupported": 0,
            "needs_review": 0,
        }

    @staticmethod
    def _mapping_key(record: dict) -> tuple:
        """Identify the exact source content shared by a rule and reviewed mapping.

        Args:
            record (dict): Rule or mapping containing source_id, source_file, and
                content_sha256.

        Returns:
            tuple: source_id, source_file, and content_sha256 identity.
        """
        return (
            record["source_id"],
            record["source_file"],
            record["content_sha256"],
        )

    def run(self, revision: str, source_files: list[str]) -> dict:
        """Load committed rules, match reviewed mappings, normalize, and persist generated
        specifications.

        Require every requested source file to exist and reject duplicate reviewed
        mappings.

        Args:
            revision (str): Git revision of the committed source rules.
            source_files (list[str]): Repository-relative paths to normalize,
                deduplicated before loading.

        Returns:
            dict: Input and saved normalization counts; empty input returns a zero-count
                summary.
        """
        summary = self._empty_result()
        if not source_files:
            return summary

        source_files = list(dict.fromkeys(source_files))
        logger.info("Starting normalization: revision=%s, files=%d", revision, len(source_files))

        rules = self.repository.get_raw_normalized_rules(revision=revision, source_files=source_files)

        summary["total"] = len(rules)

        if len(rules) != len(source_files):
            raise RuntimeError(f"Incomplete committed rule batch: expected={len(source_files)}, loaded={len(rules)}")

        # Lấy mapping đã review, không lọc enabled.
        mappings = self.repository.get_mappings_for_rules(rules)

        # Step 3: Create mapping lookup index.
        mapping_index = {}
        for mapping in mappings:
            key = self._mapping_key(mapping)

            if key in mapping_index:
                raise RuntimeError(f"Multiple reviewed mappings for source_file={mapping['source_file']}")

            mapping_index[key] = mapping

        normalized_records = []
        statuses = Counter()

        # Step 4: Normalize individual rules.
        for rule in rules:
            key = self._mapping_key(rule)
            mapping = mapping_index.get(key)

            if mapping is None:
                summary["without_mapping"] += 1
                statuses["UNSUPPORTED"] += 1
                continue

            summary["mapped"] += 1
            result = self.normalizer.normalize(rule, mapping)
            status = result["execution_status"]

            if status not in {"SUPPORTED", "UNSUPPORTED", "NEEDS_REVIEW"}:
                raise ValueError(f"Invalid normalization status: {status}")

            statuses[status] += 1
            normalized_rule = result.get("normalized_rule")

            if normalized_rule is None:
                logger.debug(
                    "Rule cannot be normalized: rule=%s, status=%s, reason=%s",
                    rule["external_rule_id"],
                    status,
                    result.get("validation_error"),
                )
                continue

            # Defensive validation.
            if not isinstance(normalized_rule, dict):
                raise TypeError("normalized_rule must be a dictionary")

            required_evidence = result.get("required_evidence", [])

            if not isinstance(required_evidence, list):
                raise TypeError("required_evidence must be a list")

            normalized_records.append({
                "rule_id": rule["id"],
                "mapping_id": mapping["id"],
                "source_revision": rule["source_revision"],
                "content_sha256": rule["content_sha256"],
                "external_rule_id": rule["external_rule_id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "evaluation_type": mapping["evaluation_type"],
                "target": mapping["target"],
                "applicability": mapping["applicability"],
                "condition": mapping["condition"],
                "required_evidence": required_evidence,
                "result_mapping": normalized_rule.get("result_mapping", {}),
                "normalized_rule": normalized_rule,
                "execution_status": status,
                "validation_error": result.get("validation_error"),
            })

        persistence = self.repository.save_normalized_rules_with_mapping(normalized_records)
        statuses = [record["execution_status"] for record in normalized_records]

        return {
            "total": len(rules),
            "updated": persistence["updated"],
            "supported": statuses.count("SUPPORTED"),
            "unsupported": statuses.count("UNSUPPORTED"),
            "needs_review": statuses.count("NEEDS_REVIEW"),
        }
