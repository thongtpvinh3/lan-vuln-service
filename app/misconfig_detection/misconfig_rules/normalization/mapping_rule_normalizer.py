"""Normalize ComplianceAsCode rules using database mappings."""
import logging
from copy import deepcopy

logger = logging.getLogger(__name__)


class MisconfigRuleNormalizer:
    SCHEMA_VERSION = "1.0"

    # Dữ liệu mà Discovery hiện có khả năng cung cấp.
    DISCOVERY_FIELDS = {
        "devices[].ip",
        "devices[].os.name",
        "devices[].ports[].port",
        "devices[].ports[].protocol",
        "devices[].ports[].service.name",
        "devices[].ports[].service.product",
        "snapshots[].source",
        "snapshots[].raw_config",
    }

    # Những toán tử Rule Engine V1 có thể hỗ trợ.
    SUPPORTED_OPERATORS = {"SERVICE_PRESENT"}

    @staticmethod
    def _result(
        status: str,
        normalized_rule: dict | None = None,
        required_evidence: list | None = None,
        error: str | None = None,
    ) -> dict:
        """Build a normalized-rule outcome, including review or support diagnostics.

        Args:
            status (str): SUPPORTED, UNSUPPORTED, or NEEDS_REVIEW.
            normalized_rule (dict | None): Generated specification, if one can be built.
            required_evidence (list | None): Required Discovery field paths; None
                becomes an empty list.
            error (str | None): Validation or support diagnostic; defaults to None.

        Returns:
            dict: execution_status, normalized_rule, required_evidence, and
                validation_error.
        """
        return {
            "execution_status": status,
            "normalized_rule": normalized_rule,
            "required_evidence": required_evidence or [],
            "validation_error": error,
        }

    def normalize(self, rule: dict, mapping: dict | None) -> dict:
        """Validate a source rule and reviewed mapping, then classify its generated
        specification.

        Args:
            rule (dict): Source rule metadata with parse state, identity, revision, and
                checksum.
            mapping (dict | None): Reviewed mapping for the exact source content, or
                None if unavailable.

        Returns:
            dict: Normalization outcome with support status, optional specification,
                evidence requirements, and validation error.
        """

        # 1. Check source rule.
        if rule.get("deprecated"):
            return self._result("UNSUPPORTED",error="Deprecated source rule")

        if rule.get("parse_status") not in {"PARSED", "PROVISIONAL"}:
            return self._result("NEEDS_REVIEW", error="Source rule metadata is incomplete")

        # 2. Check mapping.
        if mapping is None:
            return self._result("UNSUPPORTED", error="No mapping found")

        if mapping.get("verification_status") != "REVIEWED":
            return self._result("NEEDS_REVIEW", error="Mapping is not approved")

        for field in ("source_id", "source_file", "content_sha256"):
            if rule.get(field) != mapping.get(field):
                return self._result("NEEDS_REVIEW", error=f"Mapping mismatch: {field}")

        # 3. Validate mapping structure.
        target = mapping.get("target")
        applicability = mapping.get("applicability")
        condition = mapping.get("condition")
        required = mapping.get("required_evidence")

        if (
            not isinstance(target, dict)
            or not isinstance(applicability, dict)
            or not isinstance(condition, dict)
            or not isinstance(required, list)
            or not all(isinstance(x, str) for x in required)
        ):
            return self._result("NEEDS_REVIEW", error="Invalid mapping structure")

        operator = condition.get("operator")

        # 4. Generate normalized specification.
        normalized = {
            "schema_version": self.SCHEMA_VERSION,
            "source": {
                "provider": "COMPLIANCE_AS_CODE",
                "rule_id": rule["external_rule_id"],
                "source_file": rule["source_file"],
                "source_revision": rule["source_revision"],
                "content_sha256": rule["content_sha256"],
            },
            "mapping_id": mapping["id"],
            "evaluation_type": mapping["evaluation_type"],
            "target": deepcopy(target),
            "applicability": deepcopy(applicability),
            "condition": deepcopy(condition),
            "required_evidence": list(required),
            "result_mapping": {
                "positive": "MATCH",
                "negative": "UNKNOWN",
                "missing": "UNKNOWN",
            },
        }

        # 5. Check whether engine can evaluate the rule.
        if operator not in self.SUPPORTED_OPERATORS:
            return self._result("UNSUPPORTED", normalized, required, f"Rule Engine does not support: {operator}")

        if (
            mapping.get("evaluation_type") != "SERVICE_EXPOSURE"
            or operator != "SERVICE_PRESENT"
            or condition.get("protocol") not in {"tcp", "udp"}
            or not isinstance(condition.get("service_names"), list)
            or not condition["service_names"]
            or not all(isinstance(name, str) and name.strip() for name in condition["service_names"])
            or "product_names" in condition
            or target.get("type") != "HOST"
        ):
            return self._result(
                "NEEDS_REVIEW",
                normalized,
                required,
                "Invalid or unimplemented SERVICE_PRESENT mapping",
            )

        mandatory_fields = {
            "devices[].ip",
            "devices[].os.name",
            "devices[].ports[].protocol",
            "devices[].ports[].service.name",
        }

        if not mandatory_fields.issubset(set(required)):
            return self._result(
                "NEEDS_REVIEW",
                normalized,
                required,
                "Mapping is missing mandatory evidence fields",
            )

        missing = sorted(set(required) - self.DISCOVERY_FIELDS)

        if missing:
            return self._result(
                "UNSUPPORTED",
                normalized,
                required,
                f"Discovery cannot provide: {missing}",
            )

        # Require explicit confirmation that the original check is truly a remote service exposure policy.
        if (
            condition.get("source_semantics_verified") is not True
            or applicability.get("verified") is not True
            or not isinstance(applicability.get("os_families"), list)
            or not applicability["os_families"]
        ):
            return self._result(
                "NEEDS_REVIEW",
                normalized,
                required,
                "Source semantics or OS applicability not verified",
            )

        logger.info("Supported misconfig rule: %s", rule["external_rule_id"])

        return self._result("SUPPORTED", normalized, required)
