"""PostgreSQL repository for ComplianceAsCode rules"""
import logging
from collections.abc import Callable

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB


from app.common.database import db

logger = logging.getLogger(__name__)


class MisconfigRuleRepository:
    SOURCE_KEY = "COMPLIANCE_AS_CODE"
    SOURCE_NAME = "ComplianceAsCode"
    SOURCE_URL = "https://github.com/ComplianceAsCode/content"

    JSON_FIELDS = (
        "identifiers",
        "references_data",
        "raw_data",
        "normalized_rule",
        "required_evidence",
    )

    RULE_COLUMNS = (
        "external_rule_id",
        "source_revision",
        "source_file",
        "source_reference_url",
        "title",
        "description",
        "rationale",
        "severity",
        "category",
        "target_type",
        "target_product",
        "platform_expression",
        "identifiers",
        "references_data",
        "remediation",
        "remediation_available",
        "raw_format",
        "raw_content",
        "raw_data",
        "content_sha256",
        "parse_status",
        "contains_template",
        "parse_error",
        "normalized_rule",
        "required_evidence",
        "execution_status",
        "validation_error",
        "enabled",
        "deprecated",
    )

    _INSERT_RULE_SQL = text("""
        INSERT INTO vuln_misconfig_rule (
            source_id,
            external_rule_id,
            source_revision,
            source_file,
            source_reference_url,
            title,
            description,
            rationale,
            severity,
            category,
            target_type,
            target_product,
            platform_expression,
            identifiers,
            references_data,
            remediation,
            remediation_available,
            raw_format,
            raw_content,
            raw_data,
            content_sha256,
            parse_status,
            contains_template,
            parse_error,
            normalized_rule,
            required_evidence,
            execution_status,
            validation_error,
            enabled,
            deprecated
        )
        VALUES (
            :source_id,
            :external_rule_id,
            :source_revision,
            :source_file,
            :source_reference_url,
            :title,
            :description,
            :rationale,
            :severity,
            :category,
            :target_type,
            :target_product,
            :platform_expression,
            :identifiers,
            :references_data,
            :remediation,
            :remediation_available,
            :raw_format,
            :raw_content,
            :raw_data,
            :content_sha256,
            :parse_status,
            :contains_template,
            :parse_error,
            :normalized_rule,
            :required_evidence,
            :execution_status,
            :validation_error,
            :enabled,
            :deprecated
        )
        ON CONFLICT (source_id, source_file, source_revision) DO NOTHING
        RETURNING id
    """).bindparams(
        bindparam("identifiers", type_=JSONB),
        bindparam("references_data", type_=JSONB),
        bindparam("raw_data", type_=JSONB),
        bindparam("normalized_rule", type_=JSONB(none_as_null=True)),
        bindparam("required_evidence", type_=JSONB),
    )

    def get_or_create_source(self) -> int:
        """Register or update the ComplianceAsCode source metadata.

        Returns:
            int: Database ID of the source row.
        """

        sql = text("""
            INSERT INTO vuln_misconfig_source (
                source_key,
                source_name,
                source_url,
                source_type
            )
            VALUES (
                :source_key,
                :source_name,
                :source_url,
                'GITHUB'
            )
            ON CONFLICT (source_key)
            DO UPDATE SET
                source_name = EXCLUDED.source_name,
                source_url = EXCLUDED.source_url,
                updated_at = NOW()
            RETURNING id
        """)

        with db.transaction() as conn:
            source_id = conn.execute(
                sql,
                {
                    "source_key": self.SOURCE_KEY,
                    "source_name": self.SOURCE_NAME,
                    "source_url": self.SOURCE_URL,
                }
            ).scalar_one()

        return source_id

    def _prepare_record(self, record: dict, source_id: int) -> dict:
        """Validate source fields and set database defaults while forcing imported rules
        disabled.

        Args:
            record (dict): Parsed or raw-only source rule record.
            source_id (int): Database ID of the registered ComplianceAsCode source.

        Returns:
            dict: Insert parameters with source ID, JSON defaults, and unprocessed
                normalization state.
        """
        params = {column: record.get(column) for column in self.RULE_COLUMNS}
        params["source_id"] = source_id

        # Required fields.
        for field in ("external_rule_id", "source_revision", "source_file", "title", "raw_content", "content_sha256"):
            if not params.get(field):
                raise ValueError(f"Missing required rule field: {field}")

        # JSONB defaults.
        params["identifiers"] = (
            params["identifiers"]
            if params["identifiers"] is not None
            else {}
        )

        params["references_data"] = (
            params["references_data"]
            if params["references_data"] is not None
            else []
        )

        params["raw_data"] = (
            params["raw_data"]
            if params["raw_data"] is not None
            else {}
        )

        params["required_evidence"] = (
            params["required_evidence"]
            if params["required_evidence"] is not None
            else []
        )

        # normalized_rule=None becomes SQL JSONB null.
        # It is not activated until the normalizer runs.
        params["normalized_rule"] = None
        params["severity"] = (params["severity"] or "UNKNOWN")
        params["parse_status"] = (params["parse_status"] or "NOT_PROCESSED")
        params["execution_status"] = (params["execution_status"] or "NOT_PROCESSED")
        params["contains_template"] = bool(params["contains_template"])
        params["remediation_available"] = bool(params["remediation_available"])

        # Imported rules must not be enabled automatically.
        params["enabled"] = False
        params["deprecated"] = bool(params["deprecated"])

        return params

    def save_raw_normalized_rules(
            self,
            records: list[dict],
            batch_size: int = 200,
            on_batch_committed: Callable[[list[str]], None] | None = None,
    ) -> dict:
        """Persist source rules in batches and notify the consumer after each successful
        commit.

        Args:
            records (list[dict]): Parsed or raw-only source records to insert.
            batch_size (int): Positive records per transaction; defaults to 200.
            on_batch_committed (Callable[[list[str]], None] | None): Callback receiving
                source_file paths after a batch commits; None disables notifications.

        Returns:
            dict: source_id and total, inserted, skipped, and failed counts; database or
                callback errors propagate.
        """
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")

        if not records:
            return {
                "source_id": None,
                "total": 0,
                "inserted": 0,
                "skipped": 0,
                "failed": 0,
            }

        source_id = self.get_or_create_source()

        inserted = 0
        skipped = 0

        for start in range(0, len(records), batch_size):
            batch = records[start:start + batch_size]

            params_batch = [
                self._prepare_record(record, source_id)
                for record in batch
            ]

            batch_inserted = 0
            batch_skipped = 0

            with db.transaction() as conn:
                for params in params_batch:
                    result = conn.execute(self._INSERT_RULE_SQL, params)
                    if result.scalar_one_or_none() is None:
                        batch_skipped += 1
                    else:
                        batch_inserted += 1

            inserted += batch_inserted
            skipped += batch_skipped

            if on_batch_committed is not None:
                on_batch_committed([record["source_file"] for record in batch])

            logger.info(
                "Rule batch committed: batch=%d inserted=%d skipped=%d",
                start // batch_size + 1,
                batch_inserted,
                batch_skipped,
            )

        return {
            "source_id": source_id,
            "total": len(records),
            "inserted": inserted,
            "skipped": skipped,
            "failed": 0,
        }

    @staticmethod
    def save_normalized_rules_with_mapping(records: list[dict], batch_size: int = 200) -> dict:
        """Insert or update validated normalized rules by rule and mapping identity in
        batches.

        Args:
            records (list[dict]): Normalized specifications with source rule and mapping
                IDs and JSON evidence fields.
            batch_size (int): Positive records per transaction; defaults to 200.

        Returns:
            dict: total input, inserted, modified, and updated counts; updated is the
                total saved count.
        """

        if batch_size <= 0:
            raise ValueError("batch_size must be positive")

        if not records:
            return {
                "total": 0,
                "inserted": 0,
                "modified": 0,
                "updated": 0,
            }

        update_sql = text("""
              UPDATE vuln_misconfig_rule_normalized
              SET source_revision   = :source_revision,
                  content_sha256    = :content_sha256,
                  external_rule_id  = :external_rule_id,
                  title             = :title,
                  severity          = :severity,
                  evaluation_type   = :evaluation_type,
                  target            = :target,
                  applicability     = :applicability,
                  condition         = :condition,
                  required_evidence = :required_evidence,
                  result_mapping    = :result_mapping,
                  normalized_rule   = :normalized_rule,
                  execution_status  = :execution_status,
                  enabled           = FALSE,
                  validation_error  = :validation_error,
                  updated_at        = NOW()
              WHERE rule_id = :rule_id
                AND mapping_id = :mapping_id
              RETURNING id
              """).bindparams(
            bindparam("target", type_=JSONB),
            bindparam("applicability", type_=JSONB),
            bindparam("condition", type_=JSONB),
            bindparam("required_evidence", type_=JSONB),
            bindparam("result_mapping", type_=JSONB),
            bindparam("normalized_rule", type_=JSONB),
        )

        insert_sql = text("""
                INSERT INTO vuln_misconfig_rule_normalized (
                    rule_id,
                    mapping_id,
                    source_revision,
                    content_sha256,
                    external_rule_id,
                    title,
                    severity,
                    evaluation_type,
                    target,
                    applicability,
                    condition,
                    required_evidence,
                    result_mapping,
                    normalized_rule,
                    execution_status,
                    enabled,
                    validation_error
                )
                VALUES (
                    :rule_id,
                    :mapping_id,
                    :source_revision,
                    :content_sha256,
                    :external_rule_id,
                    :title,
                    :severity,
                    :evaluation_type,
                    :target,
                    :applicability,
                    :condition,
                    :required_evidence,
                    :result_mapping,
                    :normalized_rule,
                    :execution_status,
                    FALSE,
                    :validation_error
                )
                RETURNING id
             """).bindparams(
            bindparam("target", type_=JSONB),
            bindparam("applicability", type_=JSONB),
            bindparam("condition", type_=JSONB),
            bindparam("required_evidence", type_=JSONB),
            bindparam("result_mapping", type_=JSONB),
            bindparam("normalized_rule", type_=JSONB),
        )

        columns = (
            "rule_id",
            "mapping_id",
            "source_revision",
            "content_sha256",
            "external_rule_id",
            "title",
            "severity",
            "evaluation_type",
            "target",
            "applicability",
            "condition",
            "required_evidence",
            "result_mapping",
            "normalized_rule",
            "execution_status",
            "validation_error",
        )

        prepared = []
        seen = set()

        for record in records:
            params = {column: record.get(column) for column in columns}
            if params["rule_id"] is None: raise ValueError("Missing rule_id")
            if params["mapping_id"] is None: raise ValueError("Missing mapping_id")
            if not isinstance(params["normalized_rule"], dict):
                raise ValueError("normalized_rule must be a JSON object")

            identity = (params["rule_id"], params["mapping_id"])

            if identity in seen:
                raise ValueError(f"Duplicate normalized rule identity: {identity}")

            seen.add(identity)

            for field in ("target", "applicability", "condition", "result_mapping"):
                if not isinstance(params[field], dict):
                    raise ValueError(f"{field} must be a JSON object")

            if not isinstance(params["required_evidence"], list):
                raise ValueError("required_evidence must be a JSON array")

            prepared.append(params)

        inserted = 0
        modified = 0

        for start in range(0, len(prepared), batch_size):
            batch = prepared[start:start + batch_size]
            batch_inserted = 0
            batch_modified = 0

            with db.transaction() as conn:
                for params in batch:
                    result = conn.execute(update_sql, params)
                    existing_id = result.scalar_one_or_none()
                    if existing_id is not None:
                        batch_modified += 1
                        continue

                    result = conn.execute(insert_sql, params)
                    result.scalar_one()
                    batch_inserted += 1

            inserted += batch_inserted
            modified += batch_modified

            logger.info("Normalized batch saved: inserted=%d modified=%d", batch_inserted, batch_modified)

        total_saved = inserted + modified
        logger.info("Normalized rules persisted: total=%d inserted=%d modified=%d", total_saved, inserted, modified)

        return {
            "total": len(records),
            "inserted": inserted,
            "modified": modified,
            "updated": total_saved,
        }

    def update_sync_status(self, revision: str, status: str, error: str | None = None, ) -> None:
        """Persist catalog synchronization state, retaining the last revision after
        failures.

        Args:
            revision (str): Source revision; applied to last_revision for SUCCESS or
                PARTIAL.
            status (str): Catalog sync status SUCCESS, FAILED, or PARTIAL, normalized to
                uppercase.
            error (str | None): Synchronization error or partial-import explanation;
                defaults to None.

        Returns:
            None: No return value.
        """
        status = status.upper()
        if status not in {"SUCCESS", "FAILED", "PARTIAL"}:
            raise ValueError(f"Invalid sync status: {status}")

        sql = text("""
            UPDATE vuln_misconfig_source
            SET
                last_revision = CASE
                    WHEN :status IN ('SUCCESS', 'PARTIAL')
                    THEN :revision
                    ELSE last_revision
                END,
                last_synced_at = NOW(),
                last_sync_status = :status,
                last_sync_error = :error,
                updated_at = NOW()
            WHERE source_key = :source_key
        """)

        with db.transaction() as conn:
            result = conn.execute(
                sql,
                {
                    "source_key": self.SOURCE_KEY,
                    "revision": revision,
                    "status": status,
                    "error": error,
                }
            )

            if result.rowcount != 1:
                raise RuntimeError("ComplianceAsCode source is not registered")

        logger.info("ComplianceAsCode sync status updated: revision=%s status=%s", revision, status)

    @staticmethod
    def get_mappings_for_rules(rules: list[dict]) -> list[dict]:
        """Load reviewed mappings for exact source identities without filtering enabled.

        Args:
            rules (list[dict]): Source rules containing source_id, source_file, and
                content_sha256.

        Returns:
            list[dict]: Reviewed mapping rows ordered by id; empty input yields an empty
                list.
        """
        if not rules: return []

        keys = {
            (
                rule["source_id"],
                rule["source_file"],
                rule["content_sha256"],
            )
            for rule in rules
        }

        payload = [
            {
                "source_id": source_id,
                "source_file": source_file,
                "content_sha256": content_sha256,
            }
            for source_id, source_file, content_sha256 in keys
        ]

        sql = text("""
                   WITH requested_rules AS (
                        SELECT * FROM jsonb_to_recordset(:rule_keys)
                        AS x(source_id BIGINT, source_file TEXT, content_sha256 TEXT)
                   )
                   SELECT m.id,
                          m.source_id,
                          m.source_file,
                          m.content_sha256,
                          m.mapping_version,
                          m.evaluation_type,
                          m.target,
                          m.applicability,
                          m.condition,
                          m.required_evidence,
                          m.verification_status,
                          m.enabled,
                          m.review_note
                   FROM vuln_misconfig_rule_mapping m JOIN requested_rules r 
                       ON m.source_id = r.source_id AND m.source_file = r.source_file AND m.content_sha256 = r.content_sha256
                   WHERE m.verification_status = 'REVIEWED'
                   ORDER BY m.id
                   """).bindparams(bindparam("rule_keys",type_=JSONB))

        with db.connect() as conn:
            rows = conn.execute(sql, {"rule_keys": payload}).mappings().all()

        mappings = [dict(row) for row in rows]
        logger.info("Loaded %d reviewed mappings for %d source rules", len(mappings), len(payload))

        return mappings

    def get_raw_normalized_rules(self, revision: str, source_files: list[str] | None = None) -> list[dict]:
        """Load imported source records for a revision and optional source-file subset.

        Args:
            revision (str): Exact Git revision of the requested source rules.
            source_files (list[str] | None): Optional repository-relative paths; None
                loads the revision, while an empty list loads nothing.

        Returns:
            list[dict]: Source rule rows ordered by id, with parse state and raw
                metadata.
        """
        params = {
            "source_key": self.SOURCE_KEY,
            "revision": revision,
        }
        file_filter = ""
        if source_files is not None:
            if not source_files: return []
            params["source_files"] = list(dict.fromkeys(source_files))
            file_filter = "AND r.source_file IN :source_files"

        sql = text(f"""
            SELECT
                r.id,
                r.source_id,
                r.external_rule_id,
                r.source_file,
                r.source_revision,
                r.content_sha256,
                r.title,
                r.severity,
                r.parse_status,
                r.platform_expression,
                r.raw_data,
                r.contains_template,
                r.deprecated
            FROM vuln_misconfig_rule r JOIN vuln_misconfig_source s ON s.id = r.source_id
            WHERE s.source_key = :source_key
              AND r.source_revision = :revision
              {file_filter}
            ORDER BY r.id
        """)

        if source_files is not None:
            sql = sql.bindparams(bindparam("source_files", expanding=True))

        with db.connect() as conn:
            rows = conn.execute(sql, params).mappings().all()

        return [dict(row) for row in rows]

    def get_supported_mappings(self) -> list[dict]:
        """Load reviewed, enabled mappings for the ComplianceAsCode source.

        Returns:
            list[dict]: Mapping rows with identities, conditions, applicability, and
                evidence requirements.
        """
        sql = text("""
            SELECT
                m.id,
                m.source_id,
                m.source_file,
                m.content_sha256,
                m.mapping_version,
                m.evaluation_type,
                m.target,
                m.applicability,
                m.condition,
                m.required_evidence,
                m.verification_status,
                m.enabled
            FROM vuln_misconfig_rule_mapping m JOIN vuln_misconfig_source s ON s.id = m.source_id
            WHERE s.source_key = :source_key
              AND m.verification_status = 'REVIEWED'
              AND m.enabled = TRUE
        """)

        with db.connect() as conn:
            rows = conn.execute(
                sql,
                {"source_key": self.SOURCE_KEY},
            ).mappings().all()

        return [dict(row) for row in rows]

    @staticmethod
    def get_enabled_normalized_rules() -> list[dict]:
        """Load every non-null normalized specification without filtering enabled or
        execution status.

        Returns:
            list[dict]: Normalized rule rows ordered by id.
        """

        sql = text("""
                   SELECT id,
                          rule_id,
                          mapping_id,
                          external_rule_id,
                          title,
                          severity,
                          evaluation_type,
                          target,
                          applicability,
                          condition,
                          required_evidence,
                          result_mapping,
                          normalized_rule
                   FROM vuln_misconfig_rule_normalized
                   WHERE normalized_rule IS NOT NULL
                   ORDER BY id
                   """)

        with db.connect() as conn:
            rows = conn.execute(sql).mappings().all()

        rules = [dict(row) for row in rows]
        logger.info("Loaded %d normalized rules", len(rules))
        return rules

