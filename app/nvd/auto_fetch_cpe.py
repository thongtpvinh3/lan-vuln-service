import logging
import threading
from app.common.config import ServiceConfig
from app.nvd.cpe_importer import fetch_cpes

logger = logging.getLogger(__name__)

POPULAR_PRODUCTS = [
    "Apache HTTP Server",
    "Nginx",
    "OpenSSH",
    "OpenSSL",
    "Microsoft Windows",
    "Ubuntu Linux",
    "OpenWrt",
    "PostgreSQL",
    "MySQL",
    "Samba",
]


class CpeAutoFetcher:

    # Khởi tạo cấu hình và quản lý thread
    def __init__(self):
        """Load CPE fetch configuration and initialize thread stop state.

        Returns:
            None: No return value.
        """
        self.config = ServiceConfig.from_env()
        self.stop_event = threading.Event()
        self.thread = None

    # Fetch các CPE phổ biến từ NVD
    def _fetch(self):
        """Import popular product CPEs with stop checks and pauses between products.

        Returns:
            None: No return value.
        """
        for product in POPULAR_PRODUCTS:
            if self.stop_event.is_set(): return

            try:
                logger.info("Fetching CPE: %s", product)
                fetch_cpes(keyword=product, limit=self.config.cpe_fetch_limit_per_product)
                logger.info("Finished fetching: %s", product)
            except Exception:
                logger.exception("Cannot fetch CPE for: %s", product)

            # Tránh gửi request NVD quá nhanh
            if self.stop_event.wait(max(self.config.nvd_request_interval, 6)): return

    # Lặp lại việc fetch theo thời gian trong file .env
    def _run(self):
        """Repeat CPE fetch cycles until the stop event is set.

        Returns:
            None: No return value.
        """
        interval = self.config.cpe_fetch_interval_hours * 3600
        while not self.stop_event.is_set():
            try:
                self._fetch()
            except Exception:
                logger.exception("CPE auto fetch failed")

            logger.info("Next CPE fetch cycle after %s hours", self.config.cpe_fetch_interval_hours)

            if self.stop_event.wait(interval): break

    # Khởi chạy background thread
    def start(self):
        """Start the daemon fetch loop if enabled and not already running.

        Returns:
            None: No return value.
        """
        if not self.config.cpe_auto_fetch_enabled:
            logger.info("CPE Auto Fetch disabled")
            return

        if self.config.cpe_fetch_interval_hours <= 0:
            raise ValueError("CPE_FETCH_INTERVAL_HOURS must be positive")

        if self.thread and self.thread.is_alive():
            return

        self.stop_event.clear()

        self.thread = threading.Thread(target=self._run, name="cpe-auto-fetch", daemon=True)
        self.thread.start()
        logger.info("CPE Auto Fetch thread started")

    # Dừng thread
    def stop(self):
        """Signal the fetch loop to stop and wait up to five seconds for its thread.

        Returns:
            None: No return value.
        """
        self.stop_event.set()
        if self.thread and self.thread.is_alive(): self.thread.join(timeout=5)
