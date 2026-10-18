"""Background consumer for committed misconfig rules."""
import logging
import queue
import threading
from dataclasses import dataclass, field

from app.misconfig_detection.misconfig_rules.normalization.normalize_service import MisconfigRuleNormalizationService

logger = logging.getLogger(__name__)


@dataclass
class NormalizationSummary:
    batches: int = 0
    processed: int = 0
    normalized: int = 0
    supported: int = 0
    unsupported: int = 0
    needs_review: int = 0
    failed_batches: int = 0
    errors: list[str] = field(default_factory=list)


class MisconfigNormalizationWorker:
    _STOP = object()

    def __init__(self, revision: str, service: MisconfigRuleNormalizationService | None = None):
        """Initialize a bounded batch queue, normalization service, summary, and worker
        thread.

        Args:
            revision (str): Git revision of the committed source batches.
            service (MisconfigRuleNormalizationService | None): Batch normalizer; None
                creates the default service.

        Returns:
            None: No return value.
        """
        self.revision = revision
        self.service = service or MisconfigRuleNormalizationService()
        self.queue = queue.Queue(maxsize=4)
        self.summary = NormalizationSummary()
        self.thread = threading.Thread(target=self._run, name="misconfig-normalization-worker", daemon=False)
        self.started = False
        self.closed = False

    def start(self):
        """Start the normalization thread once; repeated starts raise RuntimeError.

        Returns:
            None: No return value.
        """
        if self.started: raise RuntimeError("Worker already started")
        self.started = True
        self.thread.start()

    def submit(self, source_files: list[str]):
        """Queue a copied source-file batch, waiting for capacity if necessary.

        Args:
            source_files (list[str]): Committed repository-relative paths; an empty
                batch is ignored.

        Returns:
            None: No return value.
        """
        if not self.started or self.closed: raise RuntimeError("Worker is not accepting batches")
        if source_files: self.queue.put(list(source_files))

    def _run(self):
        """Normalize queued batches until the stop sentinel, accumulating counts and
        errors.

        Returns:
            None: No return value.
        """
        logger.info("Normalization worker started: revision=%s", self.revision)

        while True:
            item = self.queue.get()
            try:
                if item is self._STOP: return
                self.summary.batches += 1
                try:
                    result = self.service.run(revision=self.revision, source_files=item)

                    self.summary.processed += result.get("total", 0)
                    self.summary.normalized += result.get("updated", 0)
                    self.summary.supported += result.get("supported", 0)
                    self.summary.unsupported += result.get("unsupported", 0)
                    self.summary.needs_review += result.get("needs_review", 0)

                    logger.info("Normalized batch: revision=%s files=%d result=%s", self.revision, len(item), result)

                except Exception as exc:
                    self.summary.failed_batches += 1
                    self.summary.errors.append(str(exc))
                    logger.exception("Rule normalization batch failed: ""revision=%s files=%d", self.revision, len(item))
            finally:
                self.queue.task_done()

    def finish(self) -> dict:
        """Close submissions and wait until all queued batches and the worker finish.

        Returns:
            dict: Copy of aggregate batch counts, normalization counts, failed_batches,
                and errors.
        """
        if not self.started: raise RuntimeError("Worker not started")

        if not self.closed:
            self.closed = True
            self.queue.put(self._STOP)

        self.queue.join()
        self.thread.join()

        return vars(self.summary).copy()
