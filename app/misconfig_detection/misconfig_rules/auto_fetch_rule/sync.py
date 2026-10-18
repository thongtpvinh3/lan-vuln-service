"""Điều phối toàn bộ quá trình đồng bộ"""
import logging
import time
from collections import Counter
from datetime import datetime, timezone

from app.misconfig_detection.misconfig_rules.auto_fetch_rule.fetcher import MisconfigRuleFetcher
from app.misconfig_detection.misconfig_rules.auto_fetch_rule.worker import MisconfigNormalizationWorker
from app.misconfig_detection.misconfig_rules.auto_fetch_rule.parser import MisconfigRuleParser
from app.misconfig_detection.repository import MisconfigRuleRepository

logger = logging.getLogger(__name__)


class MisconfigRuleSync:

    def __init__(
            self,
            fetcher: MisconfigRuleFetcher | None = None,
            repository: MisconfigRuleRepository | None = None,
            batch_size: int = 200,
    ):
        """Configure the repository fetcher, persistence repository, and positive batch
        size.

        Args:
            fetcher (MisconfigRuleFetcher | None): Source checkout manager; None creates
                the default fetcher.
            repository (MisconfigRuleRepository | None): Rule persistence repository;
                None creates the default repository.
            batch_size (int): Positive number of source records per committed batch;
                defaults to 200.

        Returns:
            None: No return value.
        """
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")

        self.fetcher = fetcher or MisconfigRuleFetcher()
        self.repository = repository or MisconfigRuleRepository()
        self.batch_size = batch_size

    @staticmethod
    def _validate_records(rule_paths: list, records: list[dict]) -> None:
        """Require a complete, unique, disabled catalog with raw source and checksums.

        Args:
            rule_paths (list[Path]): Discovered source files expected in the prepared
                catalog.
            records (list[dict]): Parsed or raw-only records to validate.

        Returns:
            None: Validation succeeded; invalid or incomplete catalogs raise
                RuntimeError.
        """

        if not rule_paths:
            raise RuntimeError("No ComplianceAsCode rules discovered")

        if len(records) != len(rule_paths):
            raise RuntimeError(f"Incomplete rule catalog: discovered={len(rule_paths)}, records={len(records)}")

        source_files = [record["source_file"] for record in records]

        if len(set(source_files)) != len(source_files):
            raise RuntimeError("Duplicate source_file detected")

        for record in records:
            if not record.get("raw_content"):
                raise RuntimeError(f"Missing raw content for {record.get('source_file')}")

            if not record.get("content_sha256"):
                raise RuntimeError(f"Missing SHA-256 for {record.get('source_file')}")

            if record.get("enabled") is not False:
                raise RuntimeError(f"Imported rule cannot be enabled: {record.get('source_file')}")

    @staticmethod
    def _parse_statistics(records: list[dict], errors: list[dict]) -> dict:
        """Count catalog parse states and metadata errors.

        Args:
            records (list[dict]): Prepared rule records containing parse_status.
            errors (list[dict]): Per-file metadata parsing errors.

        Returns:
            dict: Counts for parsed, provisional, raw_only, not_processed, and
                metadata_errors.
        """
        statuses = Counter(record["parse_status"] for record in records)

        return {
            "parsed": statuses["PARSED"],
            "provisional": statuses["PROVISIONAL"],
            "raw_only": statuses["RAW_ONLY"],
            "not_processed": statuses["NOT_PROCESSED"],
            "metadata_errors": len(errors),
        }

    def sync(self) -> dict:
        """Fetch source rules, preserve metadata and raw content, and normalize committed
        batches.

        Wait for normalization, verify catalog completeness, and persist synchronization
        status. Failures are logged and returned in the summary.

        Returns:
            dict: Source revision, import counts, optional normalization summary,
                SUCCESS/PARTIAL/FAILED catalog sync status, timing, and error details.
        """

        started = time.perf_counter()

        summary = {
            "source": "COMPLIANCE_AS_CODE",
            "revision": None,
            "status": "FAILED",
            "discovered": 0,
            "prepared": 0,
            "parsed": 0,
            "provisional": 0,
            "raw_only": 0,
            "metadata_errors": 0,
            "inserted": 0,
            "skipped": 0,
            "failed": 0,
            "duration_ms": 0,
            "completed_at": None,
            "error": None,
        }

        worker = None

        try:
            logger.info("Starting ComplianceAsCode rule synchronization")

            # Step 1: Ensure source exists.
            source_id = self.repository.get_or_create_source()
            summary["source_id"] = source_id

            # Step 2: Download or update Git repository.
            repository_path = self.fetcher.fetch_repository()

            # Step 3: Resolve the exact Git revision.
            revision = self.fetcher.get_revision()
            summary["revision"] = revision

            logger.info("ComplianceAsCode repository=%s revision=%s", repository_path, revision)

            # Step 4: Discover rule.yml files.
            rule_paths = self.fetcher.discover_rules()
            summary["discovered"] = len(rule_paths)

            if not rule_paths:
                raise RuntimeError("ComplianceAsCode repository contains no discovered rule.yml files")

            # Step 5: Parse rule metadata and preserve raw source.
            parser = MisconfigRuleParser(repository_root=repository_path)
            records, errors = parser.parse_many(rule_paths=rule_paths, revision=revision)
            summary["prepared"] = len(records)

            # Step 6: Validate catalog completeness.
            self._validate_records(rule_paths=rule_paths, records=records)

            statistics = self._parse_statistics(records=records, errors=errors)
            summary.update(statistics)

            logger.info(
                "Rule parsing: discovered=%d prepared=%d parsed=%d provisional=%d raw_only=%d metadata_errors=%d",
                summary["discovered"],
                summary["prepared"],
                summary["parsed"],
                summary["provisional"],
                summary["raw_only"],
                summary["metadata_errors"],
            )

            # Step 6: Start normalization consumer.
            worker = MisconfigNormalizationWorker(revision=revision)
            worker.start()

            # Step 7: Save rules, notifying consumer after EACH successful batch commit.
            result = self.repository.save_raw_normalized_rules(
                records=records,
                batch_size=self.batch_size,
                on_batch_committed=worker.submit
            )

            summary["inserted"] = result["inserted"]
            summary["skipped"] = result["skipped"]
            summary["failed"] = result["failed"]

            summary["inserted"] = result["inserted"]
            summary["skipped"] = result["skipped"]
            summary["failed"] = result["failed"]

            persisted = (summary["inserted"] + summary["skipped"])

            if summary["failed"] != 0 or persisted != summary["prepared"]:
                raise RuntimeError(
                    "Incomplete PostgreSQL persistence: "
                    f"prepared={summary['prepared']}, "
                    f"inserted={summary['inserted']}, "
                    f"skipped={summary['skipped']}, "
                    f"failed={summary['failed']}"
                )

            # Step 8: Wait for normalization after all source batches were submitted.
            summary["normalization"] = worker.finish()
            worker = None

            normalization = summary["normalization"]

            if normalization["failed_batches"] > 0:
                raise RuntimeError(f"Normalization failed for {normalization['failed_batches']} batches")

            if normalization["processed"] != summary["prepared"]:
                raise RuntimeError(
                    "Normalization did not process all "
                    "persisted rules: "
                    f"expected={summary['prepared']} "
                    f"processed={normalization['processed']}"
                )

            # Step 9: Determine sync status.
            status = (
                "PARTIAL"
                if summary["raw_only"] > 0 or summary["metadata_errors"] > 0 or summary["not_processed"] > 0
                else "SUCCESS"
            )

            summary["status"] = status

            if summary["raw_only"] > 0 or summary["metadata_errors"] > 0 or summary["not_processed"] > 0:
                status = "PARTIAL"
            else:
                status = "SUCCESS"

            # Step 10: Save synchronization status.
            self.repository.update_sync_status(
                revision=revision,
                status=status,
                error=(
                    f"{summary['metadata_errors']} metadata "
                    "parsing errors; "
                    f"{summary['raw_only']} raw-only rules"
                    if status == "PARTIAL"
                    else None
                ),
            )

            logger.info(
                "ComplianceAsCode sync finished: "
                "revision=%s inserted=%d skipped=%d "
                "normalization=%s",
                revision,
                summary["inserted"],
                summary["skipped"],
                normalization,
            )

        except Exception as exc:
            summary["status"] = "FAILED"
            summary["error"] = str(exc)

            logger.exception("ComplianceAsCode synchronization failed")

            try:
                if "source_id" not in summary:
                    summary["source_id"] = (self.repository.get_or_create_source())

                self.repository.update_sync_status(revision=summary["revision"] or "", status="FAILED", error=str(exc))
            except Exception:
                logger.exception("Could not persist synchronization failure")

        finally:
            if worker is not None:
                try:
                    summary["normalization"] = worker.finish()
                except Exception:
                    logger.exception("Could not finish normalization worker")

            summary["duration_ms"] = round((time.perf_counter() - started) * 1000)
            summary["completed_at"] = (datetime.now(timezone.utc).isoformat())

        return summary
