import logging
from time import perf_counter

from app.cve_matching.extractor import extract_software
from app.nvd.catalog import NvdCatalog

from app.cve_matching.normalize import normalize
from app.cve_matching.cpe import resolve_cpes
from app.cve_matching.cve import match_cves
from app.cve_matching.repository import save_findings

logger = logging.getLogger(__name__)


def run(request, completed):
    """Extract software, resolve CPEs, match CVEs, persist findings, and report completion.

    Args:
        request (dict): Assessment envelope containing scan_id and
            data.stage_run_id/inputs.
        completed (Callable[..., None]): Callback receiving the step name, result
            dictionary, and timing or warning keywords.

    Returns:
        None: No return value.
    """
    started_at = perf_counter()
    catalog = NvdCatalog()

    # STEP 1: NORMALIZE SOFTWARE
    services = extract_software(request)

    normalized = [
        result
        for service in services
        if (result := normalize(service)) is not None
    ]

    # STEP 2: RESOLVE CPE
    resolved = resolve_cpes(normalized)

    # STEP 3: MATCH CVE
    findings = match_cves(resolved, catalog=catalog)

    # STEP 4: SAVE FINDINGS
    save_findings(request, findings)

    logger.info("cve matching finished scan=%s software=%d findings=%d",
                request["scan_id"], len(normalized), len(findings))

    completed("cve_matching", {"findings": findings}, duration_ms=int((perf_counter() - started_at) * 1000))
