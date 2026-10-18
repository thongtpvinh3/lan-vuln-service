"""Chuẩn hóa tên và kiểu dữ liệu để Rule Engine xử lý nhất quán"""

"""Chuẩn hóa bằng chứng Discovery cho Rule Engine."""

import logging
from copy import deepcopy

logger = logging.getLogger(__name__)


class MisconfigEvidenceNormalizer:
    SERVICE_ALIASES = {
        "microsoft-ds": "smb",
        "netbios-ssn": "smb",
        "www": "http",
        "www-http": "http",
        "ssl/http": "https",
    }

    OS_FAMILIES = {
        "windows": ("windows", "microsoft windows"),
        "linux": ("linux", "ubuntu", "debian", "fedora", "centos", "red hat", "rhel", "rocky", "alma", "openwrt", "oracle linux"),
        "macos": ("macos", "mac os", "darwin"),
        "freebsd": ("freebsd",),
    }

    def normalize(self, evidence: dict) -> dict:
        """Deep-copy extracted evidence and normalize each device for rule evaluation.

        Args:
            evidence (dict): Extracted evidence containing a devices list.

        Returns:
            dict: Evidence with normalized devices and preserved scan and snapshot
                metadata.
        """
        if not isinstance(evidence, dict):
            raise ValueError("Evidence must be a dictionary")

        devices = evidence.get("devices", [])
        if not isinstance(devices, list):
            raise ValueError("Evidence devices must be a list")

        result = deepcopy(evidence)
        result["devices"] = [self._normalize_device(device) for device in devices]

        logger.info("Normalized Discovery evidence: devices=%d", len(result["devices"]))
        return result

    def _normalize_device(self, device: dict) -> dict:
        """Deep-copy a device and normalize its OS and port evidence.

        Args:
            device (dict): Extracted device with optional OS and a ports list.

        Returns:
            dict: Device with normalized OS and ports.
        """
        if not isinstance(device, dict):
            raise ValueError("Device must be a dictionary")

        ports = device.get("ports", [])
        if not isinstance(ports, list):
            raise ValueError("Device ports must be a list")

        result = deepcopy(device)
        result["os"] = self._normalize_os(device.get("os"))
        result["ports"] = [self._normalize_port(port) for port in ports]
        return result

    def _normalize_os(self, os_info: dict | None) -> dict | None:
        """Normalize OS labels and infer a family from known name keywords.

        Args:
            os_info (dict | None): Discovery OS fingerprint information.

        Returns:
            dict | None: Copied OS fields with normalized name, version, and inferred
                family, or None for empty input.
        """
        if not os_info:
            return None
        if not isinstance(os_info, dict):
            raise ValueError("OS information must be a dictionary")

        result = deepcopy(os_info)
        name = self._string(os_info.get("name"))
        version = self._string(os_info.get("version"))
        family = None

        if name:
            name_lower = name.lower()
            for os_family, keywords in self.OS_FAMILIES.items():
                if any(keyword in name_lower for keyword in keywords):
                    family = os_family
                    break

        result["name"] = name
        result["version"] = version
        result["family"] = family
        return result

    def _normalize_port(self, port: dict) -> dict:
        """Normalize port number, protocol, state, and service without losing metadata.

        Args:
            port (dict): Extracted network port evidence.

        Returns:
            dict: Copied port evidence with normalized fields.
        """
        if not isinstance(port, dict):
            raise ValueError("Port must be a dictionary")

        result = deepcopy(port)
        result["port"] = self._port_number(port.get("port"))
        result["protocol"] = self._lower(port.get("protocol"))
        result["state"] = self._lower(port.get("state"))
        result["service"] = self._normalize_service(port.get("service"))
        return result

    def _normalize_service(self, service: dict | None) -> dict | None:
        """Canonicalize the service name while preserving fingerprint fields.

        Args:
            service (dict | None): Extracted service fingerprint.

        Returns:
            dict | None: Copied service with its normalized alias, or None for absent
                service evidence.
        """
        if service is None:
            return None
        if not isinstance(service, dict):
            raise ValueError("Service must be a dictionary")

        result = deepcopy(service)
        name = self._lower(service.get("name"))
        result["name"] = self.SERVICE_ALIASES.get(name, name)
        return result

    @staticmethod
    def _port_number(value) -> int | None:
        """Convert a port-like value to an integer, rejecting booleans and invalid ranges.

        Args:
            value (Any): Raw port value, usually an integer or numeric string.

        Returns:
            int | None: Port number from 1 through 65535, or None if conversion fails.
        """
        try:
            if isinstance(value, bool):
                return None
            number = int(value)
            return number if 1 <= number <= 65535 else None
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _string(value) -> str | None:
        """Convert a non-null value to trimmed text.

        Args:
            value (Any): Raw value to stringify.

        Returns:
            str | None: Nonempty string, or None for null or blank values.
        """
        if value is None: return None
        return str(value).strip() or None

    @staticmethod
    def _lower(value) -> str | None:
        """Trim and lowercase text, rejecting non-string input.

        Args:
            value (Any): Raw value to normalize.

        Returns:
            str | None: Nonempty lowercase text, or None.
        """
        return value.strip().lower() or None if isinstance(value, str) else None

