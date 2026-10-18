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

from app.nvd.auto_fetch_cpe import CpeAutoFetcher

logger = logging.getLogger(__name__)

bus = RabbitEventBus(RabbitMQConfig.from_env())

setup_logging()

def handle_assessment(event):
    """Validate a request, run the three assessment steps, and publish completion.

    Args:
        event (dict): Assessment envelope containing scan_id and
            data.stage_run_id/inputs.

    Returns:
        None: No return value.
    """
    validate_request(event)
    context = {"step": "cve_matching"}

    def completed(step, result, **details):
        """Publish a successful step report for the enclosing request.

        Args:
            step (str): Assessment step name.
            result (dict): Step output to include in the report.
            **details (Any): Additional report keywords such as seq, duration_ms, and
                warnings.

        Returns:
            None: No return value.
        """
        publish_step_completed(event, step, result, **details)

    run_cve_matching(event, completed)

    context["step"] = "misconfig_detection"
    run_misconfig_detection(event, completed)

    context["step"] = "risk_scoring"
    run_risk_scoring(event, completed)

    publish_stage_completed(event)


def handle_scan_cancelled(event):
    """Log a scan cancellation request; cancellation state is not yet persisted.

    Args:
        event (dict): Cancellation envelope containing scan_id.

    Returns:
        None: No return value.
    """
    scan_id = event["scan_id"]
    logger.info("Received scan cancellation: scan_id=%s", scan_id)

    # TODO: Đánh dấu scan đã bị hủy trong database.


def main():
    """Start background catalog fetchers and consume assessment events until stopped.

    Returns:
        None: No return value.
    """
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
