"""Lập lịch fetch misconfig rule định kỳ"""
import logging
import os
import threading

from app.misconfig_detection.misconfig_rules.auto_fetch_rule.sync import MisconfigRuleSync

logger = logging.getLogger(__name__)


class MisconfigRuleAutoFetcher:

    def __init__(self):
        """Read synchronization settings and create the sync service and thread stop state.

        Returns:
            None: No return value.
        """
        self.enabled = (os.getenv("MISCONFIG_RULE_FETCH_ENABLED", "false").lower() == "true")
        self.interval_hours = float(os.getenv("MISCONFIG_RULE_SYNC_INTERVAL_HOURS", "24"))

        if self.interval_hours <= 0:
            raise ValueError("MISCONFIG_RULE_SYNC_INTERVAL_HOURS must be positive")

        self.sync_service = MisconfigRuleSync(batch_size=int(os.getenv("MISCONFIG_RULE_BATCH_SIZE", "200")))
        self._stop_event = threading.Event()
        self._thread = None

    def _worker(self):
        """Synchronize rules repeatedly until the stop event is set, logging failures.

        Returns:
            None: No return value.
        """
        while not self._stop_event.is_set():
            try:
                logger.info("Starting scheduled ComplianceAsCode sync")

                # Bắt đầu sync data
                result = self.sync_service.sync()
                if result["status"] == "FAILED":
                    logger.error("ComplianceAsCode sync failed: %s", result.get("error"))

                logger.info("ComplianceAsCode sync completed: %s", result)
            except Exception:
                logger.exception("Scheduled ComplianceAsCode sync failed")

            if self._stop_event.wait(self.interval_hours * 3600): break

        logger.info("ComplianceAsCode auto fetcher stopped")

    def start(self):
        """Start background synchronization if enabled and not already running.

        Returns:
            None: No return value.
        """
        if not self.enabled:
            logger.info("ComplianceAsCode auto fetcher disabled")
            return

        if self._thread and self._thread.is_alive(): return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker, name="misconfig-rule-auto-fetcher", daemon=True)
        self._thread.start()
        logger.info("ComplianceAsCode auto fetcher started")

    def stop(self):
        """Stop future scheduled runs and wait up to five seconds for the thread.

        Returns:
            None: No return value.
        """
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
