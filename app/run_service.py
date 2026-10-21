import logging

from app.common.config import RabbitMQConfig
from app.common.logging_config import setup_logging
from app.common.messaging.assessment_events import publish_step_completed, publish_stage_completed
from app.common.messaging.rabbitmq import RabbitEventBus
from app.common.messaging.event_keys import EventKeys

from app.cve_matching.runner import run as run_cve_matching
from app.misconfig_detection.misconfig_rules.auto_fetch_rule.auto_fetch import MisconfigRuleAutoFetcher
from app.misconfig_detection.runner import run as run_misconfig_detection
from app.risk_scoring.runner import run as run_risk_scoring
from app.validate import validate_request

from app.common.thread import ScanCancelled, thread_manager

from app.nvd.auto_fetch_cpe import CpeAutoFetcher

logger = logging.getLogger(__name__)

bus = RabbitEventBus(RabbitMQConfig.from_env())

setup_logging()


def handle_assessment(event):
    validate_request(event)
    scan_id = event["scan_id"]
    task = thread_manager.register(scan_id)

    def completed(step, result, **details):
        task.check_cancelled()
        publish_step_completed(event, step, result, **details)

    try:
        logger.info("Assessment started: scan_id=%s thread_id=%s", scan_id, task.thread_id)
        for runner in (run_cve_matching, run_misconfig_detection, run_risk_scoring):
            task.check_cancelled()
            runner(event, completed)
            task.check_cancelled()

        publish_stage_completed(event)
    except ScanCancelled:
        logger.info("Assessment cancelled: scan_id=%s thread_id=%s", scan_id, task.thread_id)
    finally:
        thread_manager.unregister(task)


def handle_scan_cancelled(event):
    scan_id = event["scan_id"]
    cancelled = thread_manager.cancel(scan_id)
    logger.info("Scan cancellation: scan_id=%s running=%s", scan_id, cancelled)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", )
    cpe_fetcher = CpeAutoFetcher()
    cpe_fetcher.start()
    misconfig_auto_fetcher = MisconfigRuleAutoFetcher()
    misconfig_auto_fetcher.start()
    bus.subscribe(EventKeys.ASSESSMENT_REQUESTED, handle_assessment)
    bus.subscribe(EventKeys.SCAN_CANCELLED, handle_scan_cancelled)

    try:
        bus.start()
    finally:
        cpe_fetcher.stop()
        misconfig_auto_fetcher.stop()


if __name__ == "__main__":
    main()
