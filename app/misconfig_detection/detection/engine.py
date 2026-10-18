"""Đánh giá rule misconfiguration dựa trên bằng chứng Discovery."""
import logging
from copy import deepcopy

logger = logging.getLogger(__name__)


class MisconfigRuleEngine:
    """Đối chiếu từng rule với dữ liệu của một thiết bị."""

    def evaluate(self, device: dict, rule: dict) -> dict:
        """Check OS applicability and evaluate a supported network service rule.

        Args:
            device (dict): Normalized device evidence containing ip, os, and ports.
            rule (dict): Rule record with identifiers and a normalized_rule
                specification.

        Returns:
            dict: Evaluation with device and rule IDs, status, reason, and optional
                evidence.
        """
        spec = rule.get("normalized_rule")
        if not isinstance(spec, dict):
            return self._result(device, rule, "UNKNOWN", "Invalid normalized rule")

        applicability = spec.get("applicability")
        condition = spec.get("condition")

        if not isinstance(applicability, dict) or not isinstance(condition, dict):
            return self._result(device, rule, "UNKNOWN", "Invalid rule specification")

        applicable = self._check_applicability(device, applicability)
        if applicable is False:
            return self._result(device, rule, "NOT_APPLICABLE", "Rule does not apply to this OS")
        if applicable is None:
            return self._result(device, rule, "UNKNOWN", "OS applicability cannot be determined")

        evaluation_type = spec.get("evaluation_type")
        if evaluation_type in {"SERVICE_ENABLED", "SERVICE_STATE"}:
            if condition.get("operator") != "SERVICE_ENABLED":
                return self._result(device, rule, "UNKNOWN", "Unsupported rule operator")
            return self._evaluate_service_enabled(device, rule, condition)

        if evaluation_type != "SERVICE_EXPOSURE":
            return self._result(device, rule, "UNKNOWN", "Unsupported evaluation type")

        if condition.get("operator") != "SERVICE_PRESENT":
            return self._result(device, rule, "UNKNOWN", "Unsupported rule operator")

        return self._evaluate_service_present(device, rule, condition)

    def _evaluate_service_enabled(self, device: dict, rule: dict, condition: dict) -> dict:
        """Compare confirmed open services with the required enabled state.

        Missing matching exposure yields UNKNOWN because it cannot prove a service is
        disabled.

        Args:
            device (dict): Normalized device evidence containing ip, os, and ports.
            rule (dict): Rule record with identifiers and a normalized_rule
                specification.
            condition (dict): Service name, expected boolean enabled state, and optional
                protocol.

        Returns:
            dict: Evaluation with device and rule IDs, status, reason, and optional
                evidence.
        """
        name = condition.get("service")
        expected = condition.get("expected")
        if not isinstance(name, str) or not name.strip():
            return self._result(device, rule, "UNKNOWN", "Invalid service name")
        if not isinstance(expected, bool):
            return self._result(device, rule, "UNKNOWN", "Invalid expected service state")

        protocol = condition.get("protocol")
        if protocol is not None and protocol not in {"tcp", "udp"}:
            return self._result(device, rule, "UNKNOWN", "Invalid service protocol")
        ports = device.get("ports")
        if not isinstance(ports, list):
            return self._result(device, rule, "UNKNOWN", "Network service evidence is missing")

        names = {name.strip().lower()}
        if names.intersection({"sshd", "ssh", "openssh"}):
            names.update({"sshd", "ssh", "openssh"})

        for port in ports:
            if not isinstance(port, dict) or port.get("state") != "open":
                continue
            if port.get("protocol") not in {"tcp", "udp"}:
                continue
            if protocol is not None and port.get("protocol") != protocol:
                continue
            service = port.get("service")
            if not isinstance(service, dict):
                continue
            identities = {
                value.strip().lower() for field in ("name", "software", "product")
                if isinstance(value := service.get(field), str) and value.strip()
            }
            if not names.intersection(identities):
                continue

            evidence = {
                "port": port.get("port"), "protocol": port["protocol"], "state": "open",
                "service": name.strip(), "software": service.get("software") or service.get("product"),
                "expected": expected, "metadata": deepcopy(port.get("metadata") or {}),
            }
            if expected:
                return self._result(device, rule, "NO_MATCH", "Required network service detected", evidence)
            return self._result(device, rule, "MATCH", "Forbidden network service detected", evidence)

        # Thiếu bằng chứng mở chưa đủ kết luận service đã tắt.
        return self._result(device, rule, "UNKNOWN", "No confirmed matching service exposure")

    @staticmethod
    def _check_applicability(device: dict, applicability: dict) -> bool | None:
        """Check whether the observed OS family is allowed by the rule.

        Args:
            device (dict): Normalized device evidence containing ip, os, and ports.
            applicability (dict): Rule applicability with a nonempty os_families list.

        Returns:
            bool | None: True for an allowed family, False for a different family, or
                None for missing or invalid applicability evidence.
        """
        # if applicability.get("verified"):
        #     return None

        families = applicability.get("os_families")
        if not isinstance(families, list) or not families:
            return None

        if any(not isinstance(name, str) or not name.strip() for name in families):
            return None

        os_info = device.get("os")
        if not isinstance(os_info, dict):
            return None

        family = os_info.get("family")
        if not isinstance(family, str) or not family.strip():
            return None

        allowed = {name.strip().lower() for name in families}
        return family.strip().lower() in allowed

    def _evaluate_service_present(self, device: dict, rule: dict, condition: dict) -> dict:
        """Detect forbidden open services by protocol and service name.

        Return UNKNOWN when no exposure is confirmed or the condition is unsupported.

        Args:
            device (dict): Normalized device evidence containing ip, os, and ports.
            rule (dict): Rule record with identifiers and a normalized_rule
                specification.
            condition (dict): SERVICE_PRESENT condition with protocol and service_names;
                product_names is unsupported.

        Returns:
            dict: Evaluation with device and rule IDs, status, reason, and optional
                evidence.
        """
        protocol = condition.get("protocol")
        service_names = condition.get("service_names")

        if protocol not in {"tcp", "udp"}:
            return self._result(device, rule, "UNKNOWN", "Invalid service protocol")

        if not isinstance(service_names, list) or not service_names:
            return self._result(device, rule, "UNKNOWN", "Invalid service names")

        if any(not isinstance(name, str) or not name.strip() for name in service_names):
            return self._result(device, rule, "UNKNOWN", "Invalid service names")

        if "product_names" in condition:
            return self._result(device, rule, "UNKNOWN", "Product matching is not supported")

        ports = device.get("ports")
        if not isinstance(ports, list):
            return self._result(device, rule, "UNKNOWN", "Network service evidence is missing")

        expected_names = {name.strip().lower() for name in service_names}

        for port in ports:
            if not isinstance(port, dict):
                continue

            if port.get("protocol") != protocol or port.get("state") != "open":
                continue

            service = port.get("service")
            if not isinstance(service, dict):
                continue

            name = service.get("name")
            if not isinstance(name, str) or name.strip().lower() not in expected_names:
                continue

            evidence = {
                "port": port.get("port"),
                "protocol": port["protocol"],
                "state": port["state"],
                "service": name,
                "metadata": deepcopy(port.get("metadata") or {}),
            }

            logger.info("Misconfiguration detected: host=%s rule=%s", device.get("ip"), rule.get("external_rule_id"))
            return self._result(device, rule, "MATCH", "Forbidden network service detected", evidence)

        # Không tìm thấy dịch vụ không đồng nghĩa dịch vụ đã bị vô hiệu hóa.
        return self._result(device, rule, "UNKNOWN", "No confirmed matching service exposure")

    @staticmethod
    def _result(
        device: dict,
        rule: dict,
        status: str,
        reason: str,
        evidence: dict | None = None
    ) -> dict:
        """Build a consistent device-rule evaluation result.

        Args:
            device (dict): Normalized device evidence containing ip, os, and ports.
            rule (dict): Rule record with identifiers and a normalized_rule
                specification.
            status (str): MATCH, NO_MATCH, UNKNOWN, or NOT_APPLICABLE.
            reason (str): Explanation of the evaluation outcome.
            evidence (dict | None): Supporting endpoint evidence; defaults to None.

        Returns:
            dict: Evaluation with device and rule IDs, status, reason, and optional
                evidence.
        """
        return {
            "device_ip": device.get("ip"),
            "normalized_rule_id": rule.get("id"),
            "external_rule_id": rule.get("external_rule_id"),
            "status": status,
            "reason": reason,
            "evidence": evidence
        }
