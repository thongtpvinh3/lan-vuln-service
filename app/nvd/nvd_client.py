import logging
import time
import requests

from app.nvd import service_config

logger = logging.getLogger(__name__)


class NvdClient:
    def __init__(self):
        """Create a reusable HTTP session with the configured NVD API key and rate state.

        Returns:
            None: No return value.
        """
        self.session = requests.Session()
        self.last_request = 0.0

        if service_config.nvd_api_key:
            self.session.headers["apiKey"] = service_config.nvd_api_key

    def get(self, endpoint, params):
        """Request one NVD JSON page with rate spacing and bounded retries.

        Args:
            endpoint (str): Endpoint path relative to the configured NVD base URL.
            params (dict): Query parameters for the request.

        Returns:
            dict: Decoded NVD JSON response; request or retry exhaustion errors
                propagate.
        """
        url = f"{service_config.nvd_client_url}/{endpoint}"

        for attempt in range(4):
            delay = service_config.nvd_request_interval - (time.monotonic() - self.last_request)
            if delay > 0:
                time.sleep(delay)

            self.last_request = time.monotonic()

            try:
                response = self.session.get(url, params=params, timeout=(10, 45))

                if response.status_code in (429, 500, 502, 503, 504):
                    retry_after = response.headers.get("Retry-After")
                    try:
                        wait = float(retry_after)
                    except (TypeError, ValueError):
                        wait = 10 * (attempt + 1)

                    logger.warning("NVD HTTP %s, retrying after %ss", response.status_code, wait)
                    time.sleep(max(wait, 1))
                    continue

                response.raise_for_status()
                return response.json()

            except (requests.Timeout, requests.ConnectionError):
                if attempt == 3:
                    raise
                time.sleep(5 * (attempt + 1))

        raise RuntimeError("NVD API failed after retries")

    def get_all(self, endpoint, params, result_key):
        """Collect all items from a paginated NVD endpoint.

        Args:
            endpoint (str): Endpoint path relative to the configured NVD base URL.
            params (dict): Base query parameters; pagination offsets and page size are
                supplied internally.
            result_key (str): Response field containing page items, such as products or
                vulnerabilities.

        Returns:
            list[dict]: Items combined from every response page.
        """
        results = []
        start = 0

        while True:
            page = self.get(endpoint, {**params, "startIndex": start, "resultsPerPage": 2000})

            items = page.get(result_key, [])
            results.extend(items)
            start += len(items)
            if start >= page.get("totalResults", 0):
                break

            if not items:
                raise RuntimeError("Unexpected empty NVD pagination page")

        return results
