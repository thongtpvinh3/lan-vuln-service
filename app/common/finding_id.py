import json
from uuid import NAMESPACE_URL, uuid5


def create_finding_id(kind: str, scan_id: str, stage_run_id: str, *identity) -> str:
    """Create a stable UUID for the same finding identity within a stage execution.

    Args:
        kind (str): Finding category, such as CVE or MISCONFIG.
        scan_id (str): Identifier of the scan whose records are being processed.
        stage_run_id (str): Identifier of the assessment stage execution.
        *identity (Any): JSON-serializable identity components, such as host, port,
            protocol, and rule or CVE ID.

    Returns:
        str: Deterministic UUID5 formatted as a string.
    """
    key = json.dumps(["lan-vuln-service", kind, scan_id, stage_run_id, *identity], separators=(",", ":"))
    return str(uuid5(NAMESPACE_URL, key))
