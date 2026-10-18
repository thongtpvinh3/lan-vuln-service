import logging
from collections import defaultdict
from time import perf_counter

from app.risk_scoring.repository import load_findings, save_results
from app.risk_scoring.calculator import calculate, calculate_finding
from app.risk_scoring.recommendation import recommend

logger = logging.getLogger(__name__)


def run(request, completed):
    """Score findings, persist host risk summaries, and report finding scores and warnings.

    Args:
        request (dict): Assessment envelope containing scan_id and
            data.stage_run_id/inputs.
        completed (Callable[..., None]): Callback receiving the step name, result
            dictionary, and timing or warning keywords.

    Returns:
        None: No return value.
    """
    started_at = perf_counter()

    # STEP 1: ĐỌC DANH SÁCH LỖ HỔNG
    scan_id = request["scan_id"]
    stage_run_id = request["data"]["stage_run_id"]
    findings = load_findings(scan_id, stage_run_id)

    # Tính điểm từng finding để gửi Platform.
    scores = []
    warnings = []
    seen = set()
    for finding in findings:
        finding_id = finding.get("finding_id")
        if not finding_id or finding_id == "None":
            warnings.append("Finding is missing finding_id")
            continue
        if finding_id in seen:
            continue
        seen.add(finding_id)
        score = calculate_finding(finding)
        if score is None:
            warnings.append(f"Finding {finding_id} has no valid base score")
            continue
        scores.append(score)

    # STEP 2: NHÓM LỖ HỔNG THEO THIẾT BỊ
    findings_by_host = defaultdict(list)
    for finding in findings:
        findings_by_host[finding["host"]].append(finding)

    # STEP 3: TÍNH ĐIỂM VÀ TẠO KHUYẾN NGHỊ
    results = []
    for host, host_findings in findings_by_host.items():
        risk = calculate(host_findings)
        recommendations = recommend(host_findings)

        results.append({
            "host": host,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "finding_count": risk["finding_count"],
            "scored_count": risk["scored_count"],
            "recommendations": recommendations,
            "review_status": "PENDING"
        })

    # STEP 4: LƯU KẾT QUẢ
    save_results(scan_id, stage_run_id, results)

    logger.info("risk scoring finished scan=%s hosts=%d findings=%d", scan_id, len(results), len(findings))

    completed("risk_scoring", {"scores": scores}, seq=3,
              duration_ms=int((perf_counter() - started_at) * 1000), warnings=warnings)
