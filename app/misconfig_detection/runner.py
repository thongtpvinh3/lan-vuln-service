import logging
from time import perf_counter

from app.misconfig_detection.detection.extractor import MisconfigEvidenceExtractor
from app.misconfig_detection.detection.evidence_normalizer import MisconfigEvidenceNormalizer
from app.misconfig_detection.detection.rule_loader import MisconfigRuleLoader
from app.misconfig_detection.detection.engine import MisconfigRuleEngine
from app.misconfig_detection.detection.finding import MisconfigFindingFactory
from app.misconfig_detection.detection.finding_repository import MisconfigFindingRepository

logger = logging.getLogger(__name__)


def run(request, completed):
    """Normalize Discovery evidence, evaluate rules, save MATCH findings, and report
    completion.

    Args:
        request (dict): Assessment envelope containing scan_id and
            data.stage_run_id/inputs.
        completed (Callable[..., None]): Callback receiving the step name, result
            dictionary, and timing or warning keywords.

    Returns:
        None: No return value.
    """
    started_at = perf_counter()

    # STEP 1: Trích xuất bằng chứng Discovery
    evidence = MisconfigEvidenceExtractor().extract(request)

    # STEP 2: Chuẩn hóa bằng chứng
    normalized = MisconfigEvidenceNormalizer().normalize(evidence)

    # STEP 3: Lấy các rule đã chuẩn hóa và kích hoạt
    rules = MisconfigRuleLoader().load_enabled_rules()

    # STEP 4: Đánh giá rule trên từng thiết bị
    engine = MisconfigRuleEngine()
    evaluations = [
        engine.evaluate(device, rule)
        for device in normalized["devices"]
        for rule in rules
    ]

    # STEP 5: Tạo Finding từ các kết quả MATCH
    factory = MisconfigFindingFactory()
    devices = {device["ip"]: device for device in normalized["devices"]}
    rule_index = {rule["id"]: rule for rule in rules}

    findings = [
        factory.create(
            scan_id=request["scan_id"],
            stage_run_id=request["data"]["stage_run_id"],
            evaluation=result,
            rule=rule_index[result["normalized_rule_id"]],
            device=devices[result["device_ip"]]
        )
        for result in evaluations
        if result["status"] == "MATCH"
    ]

    # STEP 6: Lưu Findings vào PostgreSQL
    MisconfigFindingRepository().save(findings)

    logger.info("misconfig detection finished scan=%s devices=%d rules=%d findings=%d",
                request["scan_id"], len(normalized["devices"]), len(rules), len(findings))

    completed("misconfig_detection", {"findings": findings}, duration_ms=int((perf_counter() - started_at) * 1000))
