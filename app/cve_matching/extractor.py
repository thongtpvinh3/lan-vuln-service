"""Bước này trích xuất thông tin phần mềm, duyệt qua các snapshot mà discovery quét được"""
import logging
import json

logger = logging.getLogger(__name__)


def _text(value):
    """Trim a string and discard empty or non-string values.

    Args:
        value (Any): Raw value to inspect.

    Returns:
        str | None: Nonempty trimmed text, or None.
    """
    if isinstance(value, str):
        return value.strip() or None
    return None


def _cpe_hints(value):
    """Normalize one CPE hint or a list of hints into nonempty strings.

    Args:
        value (Any): CPE hint string, list, or unsupported raw value.

    Returns:
        list[str]: Trimmed string hints; unsupported input becomes an empty list.
    """
    if isinstance(value, str): value = [value]
    if not isinstance(value, list): return []
    return [
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    ]


def _parse_raw_config(raw):
    """Decode object-shaped JSON evidence while preserving unparsed text.

    Args:
        raw (Any): Raw configuration dictionary, JSON string, or unsupported value.

    Returns:
        dict: Original dictionary, decoded JSON object, raw text wrapper, or an empty
            dictionary.
    """
    if isinstance(raw, dict): return raw
    if not isinstance(raw, str): return {}

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}

    return result if isinstance(result, dict) else {"raw": raw}


def _extract_snapshots(snapshots):
    """Index raw snapshot evidence by host without inferring software identities.

    Args:
        snapshots (list[dict]): Discovery snapshots; malformed entries and missing IPs
            are skipped.

    Returns:
        dict[str, list[dict]]: Host-to-evidence index containing source, port, and
            raw_config.
    """

    evidence_by_host = {}

    for snapshot in snapshots:
        if not isinstance(snapshot, dict): continue

        host = _text(snapshot.get("ip"))
        if not host: continue

        raw = _parse_raw_config(snapshot.get("raw_config"))

        evidence_by_host.setdefault(host, []).append({
            "source": snapshot.get("source"),
            "port": snapshot.get("port"),
            "raw_config": raw,
        })

    return evidence_by_host


def _extract_services(devices, evidence_by_host):
    """Build service observations from device ports and attach evidence for the same
    endpoint.

    Args:
        devices (list[dict]): Discovery devices with IP addresses and port records.
        evidence_by_host (dict[str, list[dict]]): Parsed snapshot evidence indexed by
            host IP.

    Returns:
        list[dict]: Service fingerprint observations with host, product, version, and
            supporting evidence.
    """
    observations = []

    for device in devices:
        if not isinstance(device, dict): continue

        host = _text(device.get("ip"))
        if not host: continue

        for port_data in device.get("ports") or []:
            if not isinstance(port_data, dict): continue

            service = port_data.get("service")
            if not isinstance(service, dict): service = {}

            port = port_data.get("port")
            if type(port) is not int or not 1 <= port <= 65535: port = None

            product = (_text(service.get("software")) or _text(service.get("product")))

            version = _text(service.get("version"))

            observations.append({
                "host": host,
                "port": port,
                "protocol": (_text(port_data.get("protocol")) or "tcp").lower(),
                "product": product,
                "version": version,
                "cpe_hint": _cpe_hints(service.get("cpe_hint") or service.get("cpes")),
                "source": "SERVICE_FINGERPRINT",
                "banner": _text(service.get("banner")),
                "raw_version": version,
                "state": _text(port_data.get("state")),
                "metadata": port_data.get("metadata") if isinstance(port_data.get("metadata"), dict) else {},
                "product_identified": product is not None,
                "evidence": [
                    item
                    for item in evidence_by_host.get(host, [])
                    if item.get("port") == port
                       and port is not None
                ],
            })

    return observations


def _extract_os(devices):
    """Build OS fingerprint observations without treating labels as verified releases.

    Args:
        devices (list[dict]): Discovery devices with optional OS fingerprint
            dictionaries.

    Returns:
        list[dict]: OS observations with no verified version and no network port.
    """
    observations = []

    for device in devices:
        if not isinstance(device, dict): continue

        host = _text(device.get("ip"))
        os_info = device.get("os")

        if not host or not isinstance(os_info, dict): continue

        name = _text(os_info.get("name"))
        if not name: continue

        # A fingerprint label is not a verified OS release.
        observations.append({
            "host": host,
            "port": None,
            "protocol": None,
            "product": name,
            "version": None,
            "cpe_hint": _cpe_hints(os_info.get("cpe") or os_info.get("cpes")),
            "source": "OS_FINGERPRINT",
            "os_raw": name,
            "os_version_raw": _text(os_info.get("version")),
            "version_verified": False,
        })

    return observations


def extract_software(request: dict) -> list[dict]:
    """Extract distinct service and OS observations from Discovery devices.

    Snapshots enrich observed endpoints; snapshots alone do not create software records.

    Args:
        request (dict): Assessment envelope containing scan_id and
            data.stage_run_id/inputs.

    Returns:
        list[dict]: Observations deduplicated by host, port, protocol, product, version,
            and source.
    """
    inputs = request["data"]["inputs"]

    devices = inputs.get("devices") or []
    snapshots = inputs.get("snapshots") or []

    evidence_by_host = _extract_snapshots(snapshots)

    results = _extract_services(devices, evidence_by_host)
    results.extend(_extract_os(devices))

    # Preserve all distinct endpoint/OS observations.
    unique = []
    seen = set()

    for item in results:
        key = (
            item["host"],
            item["port"],
            item["protocol"],
            item["product"],
            item["version"],
            item["source"],
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    logger.info("Extracted %d observations, %d with identified product",
                len(unique), sum(1 for item in unique if item.get("product_identified")))

    return unique
