"""Đọc YAML, kiểm tra dữ liệu và ánh xạ metadata"""
import hashlib
import json
import logging
from pathlib import Path
from urllib.parse import quote
import re

import yaml

logger = logging.getLogger(__name__)


class RuleParseError(ValueError):
    """Rây ê rốt"""


class MisconfigRuleParser:
    VALID_SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}

    def __init__(
            self,
            repository_root: str | Path,
            repository_url: str = "https://github.com/ComplianceAsCode/content"
    ):
        """Resolve the repository root and source URL used for rule metadata.

        Args:
            repository_root (str | Path): Root directory containing the checked-out
                source rules.
            repository_url (str): Repository web URL used to build revision-pinned
                references.

        Returns:
            None: No return value.
        """
        self.repository_root = Path(repository_root).resolve()
        self.repository_url = repository_url.rstrip("/")

    @staticmethod
    def _optional_text(value) -> str | None:
        """Keep nonempty trimmed strings and discard other metadata values.

        Args:
            value (Any): Raw metadata value.

        Returns:
            str | None: Trimmed text or None.
        """
        if isinstance(value, str):
            return value.strip() or None
        return None

    @classmethod
    def _severity(cls, value) -> str:
        """Normalize a recognized severity label, falling back to UNKNOWN.

        Args:
            value (Any): Raw severity metadata.

        Returns:
            str: Uppercase supported severity label or UNKNOWN.
        """
        if not isinstance(value, str): return "UNKNOWN"
        result = value.strip().upper()
        if result not in cls.VALID_SEVERITIES: return "UNKNOWN"
        return result

    @staticmethod
    def _references(value) -> list[dict]:
        """Flatten reference groups into typed string values.

        Args:
            value (Any): Mapping of reference types to scalar or list values; other
                input yields no references.

        Returns:
            list[dict]: Reference entries with type and value; null items are omitted.
        """
        if not isinstance(value, dict): return []
        result = []
        for name, content in value.items():
            if isinstance(content, list):
                values = content
            else:
                values = [content]

            for item in values:
                if item is None: continue
                result.append({"type": str(name), "value": str(item)})

        return result

    @staticmethod
    def _identifiers(value) -> dict:
        """Copy identifier metadata with string keys.

        Args:
            value (Any): Raw identifiers metadata.

        Returns:
            dict: Identifier mapping, or an empty dictionary for non-mapping input.
        """
        if not isinstance(value, dict): return {}
        return {str(key): item for key, item in value.items()}

    def _relative_path(self, rule_path: Path) -> str:
        """Require a rule to be inside the repository and format its relative path.

        Args:
            rule_path (Path): Resolved source rule path.

        Returns:
            str: Repository-relative POSIX path; raises RuleParseError for an outside
                path.
        """
        try:
            relative = rule_path.relative_to(self.repository_root)
        except ValueError as exc:
            raise RuleParseError(f"Rule is outside repository: {rule_path}") from exc

        return relative.as_posix()

    def _reference_url(self, revision: str, relative_path: str) -> str:
        """Build a URL to a source rule at a specific revision.

        Args:
            revision (str): Source Git revision.
            relative_path (str): Repository-relative POSIX rule path.

        Returns:
            str: Repository blob URL with escaped revision and path.
        """
        return (
            f"{self.repository_url}/blob/"
            f"{quote(revision, safe='')}/"
            f"{quote(relative_path, safe='/')}"
        )

    @staticmethod
    def _json_compatible(value):
        """Check that parsed YAML can be JSON serialized without replacing its values.

        Args:
            value (Any): Parsed YAML data to validate.

        Returns:
            Any: The original value; raises RuleParseError if JSON serialization fails.
        """
        try:
            json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise RuleParseError("Parsed YAML contains non-JSON-compatible values") from exc

        return value

    def parse(self, rule_path: str | Path, revision: str) -> dict:
        """Parse rule metadata and preserve source content, marking templates as
        provisional.

        Args:
            rule_path (str | Path): Path to a rule.yml file within the repository.
            revision (str): Nonempty Git revision identifying the source content.

        Returns:
            dict: Disabled source rule record with metadata, revision, raw content,
                checksum, and parse status.
        """
        path = Path(rule_path).resolve()

        if not path.is_file(): raise RuleParseError(f"Rule file not found: {path}")
        if path.name != "rule.yml": raise RuleParseError(f"Expected rule.yml, got: {path.name}")

        relative_path = self._relative_path(path)

        if not revision or not revision.strip():
            raise RuleParseError("Git source revision is required")

        try:
            content_bytes = path.read_bytes()
            raw_content = content_bytes.decode("utf-8-sig")

        except (OSError, UnicodeError) as exc:
            raise RuleParseError(f"Cannot read rule: {relative_path}") from exc

        content_sha256 = hashlib.sha256(content_bytes).hexdigest()
        yaml_content, contains_template = self._prepare_yaml(raw_content)

        try:
            parsed = yaml.safe_load(yaml_content)
        except yaml.YAMLError as exc:
            raise RuleParseError(f"Cannot parse ComplianceAsCode YAML in {relative_path}: {exc}") from exc

        if not isinstance(parsed, dict):
            raise RuleParseError(f"YAML root must be an object: {relative_path}")

        parsed = self._json_compatible(parsed)
        rule_id = path.parent.name
        title = self._optional_text(parsed.get("title"))

        if not title: raise RuleParseError(f"Rule has no valid title: {relative_path}")

        description = self._optional_text(parsed.get("description"))
        rationale = self._optional_text(parsed.get("rationale"))
        severity = self._severity(parsed.get("severity"))
        identifiers = self._identifiers(parsed.get("identifiers"))
        references_data = self._references(parsed.get("references"))
        platform = parsed.get("platform")

        if isinstance(platform, str):
            platform_expression = platform
        else:
            platform_expression = None

        rule_record = {
            "external_rule_id": rule_id,
            "source_revision": revision,
            "source_file": relative_path,
            "source_reference_url": self._reference_url(revision, relative_path),
            "rule_path": relative_path,
            "title": title,
            "description": description,
            "rationale": rationale,
            "severity": severity,
            "category": None,
            "target_type": None,
            "target_product": None,
            "identifiers": identifiers,
            "references_data": references_data,
            "platform_expression": platform_expression,
            "remediation": None,
            "remediation_available": ((path.parent / "bash").is_dir() or (path.parent / "ansible").is_dir()),
            "raw_format": "YAML",
            "raw_data": parsed,
            "raw_content": raw_content,
            "content_sha256": content_sha256,
            "normalized_rule": None,
            "execution_status": "NOT_PROCESSED",
            "required_evidence": [],
            "validation_error": (
                "Contains unrendered ComplianceAsCode templates; metadata is provisional"
                if contains_template
                else None
            ),
            "enabled": False,
            "deprecated": False,
            "parse_status": ("PROVISIONAL" if contains_template else "PARSED"),
            "contains_template": contains_template,
            "parse_error": None,
        }

        logger.debug("Parsed rule id=%s severity=%s path=%s", rule_id, severity, relative_path)
        return rule_record

    def parse_many(self, rule_paths: list[Path], revision: str, ) -> tuple[list[dict], list[dict]]:
        """Parse source files and attempt raw preservation when metadata parsing fails.

        Args:
            rule_paths (list[Path]): Source rule files to process in order.
            revision (str): Git revision shared by the source files.

        Returns:
            tuple[list[dict], list[dict]]: Prepared records and per-path metadata
                errors; records may be incomplete if raw preservation also fails.
        """
        records = []
        errors = []
        parsed_count = 0
        raw_only_count = 0

        for path in rule_paths:
            try:
                record = self.parse(rule_path=path, revision=revision)
                records.append(record)
                parsed_count += 1
            except (RuleParseError, OSError) as exc:
                error = {"path": str(path), "error": str(exc)}
                errors.append(error)
                try:
                    raw_record = self.parse_raw_only(rule_path=path, revision=revision, reason=str(exc))
                    records.append(raw_record)
                    raw_only_count += 1
                except (RuleParseError, OSError, UnicodeError) as raw_exc:
                    logger.error("Cannot preserve rule %s: %s", path, raw_exc)

        logger.info(
            "ComplianceAsCode import preparation: discovered=%d parsed=%d raw_only=%d metadata_errors=%d records=%d",
            len(rule_paths),
            parsed_count,
            raw_only_count,
            len(errors),
            len(records),
        )

        return records, errors

    def parse_raw_only(self, rule_path: str | Path, revision: str, reason: str) -> dict:
        """Preserve raw source and a checksum when structured metadata cannot be parsed.

        Args:
            rule_path (str | Path): Source rule file inside the repository.
            revision (str): Git revision associated with the raw source.
            reason (str): Metadata parsing error stored for later review.

        Returns:
            dict: Disabled RAW_ONLY rule record with the supplied parse error.
        """
        path = Path(rule_path).resolve()
        relative_path = self._relative_path(path)
        raw_bytes = path.read_bytes()
        raw_content = raw_bytes.decode("utf-8-sig")

        return {
            "external_rule_id": path.parent.name,
            "source_revision": revision,
            "source_file": relative_path,
            "source_reference_url": self._reference_url(revision, relative_path),
            "rule_path": relative_path,
            "title": path.parent.name,
            "description": None,
            "rationale": None,
            "severity": "UNKNOWN",
            "category": None,
            "target_type": None,
            "target_product": None,
            "identifiers": {},
            "references_data": [],
            "platform_expression": None,
            "remediation": None,
            "remediation_available": False,
            "raw_format": "YAML",
            "raw_data": {},
            "raw_content": raw_content,
            "content_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "normalized_rule": None,
            "required_evidence": [],
            "validation_error": reason,
            "enabled": False,
            "deprecated": False,
            "parse_status": "RAW_ONLY",
            "contains_template": ("{{%" in raw_content or "{{{" in raw_content),
            "parse_error": reason,
            "execution_status": "NOT_PROCESSED",
        }

    @staticmethod
    def _prepare_yaml(raw_content: str) -> tuple[str, bool]:
        """Remove template directives and replace expressions before safe YAML parsing.

        Args:
            raw_content (str): Original YAML source, possibly containing
                ComplianceAsCode template syntax.

        Returns:
            tuple[str, bool]: Sanitized YAML text and whether a supported template form
                was found.
        """
        contains_template = False
        directive = re.compile(r"^[ \t]*\{\{[%#].*?[%#]}}[ \t]*$")
        lines = []

        for line in raw_content.splitlines(keepends=True):
            if directive.fullmatch(line.rstrip("\r\n")):
                contains_template = True
                lines.append("\n" if line.endswith("\n") else "")
            else:
                lines.append(line)

        sanitized = "".join(lines)
        expression = re.compile(r"\{\{\{.*?}}}", re.DOTALL)
        counter = 0

        def replace_expression(match):
            """Replace one template expression while tracking provisional parsing state.

            Args:
                match (re.Match[str]): Template expression match within the sanitized
                    source.

            Returns:
                str: Placeholder token, or preserved line breaks for a standalone
                    expression.
            """
            nonlocal counter, contains_template
            counter += 1
            contains_template = True
            start = match.start()
            end = match.end()
            line_start = sanitized.rfind("\n", 0, start) + 1
            line_end = sanitized.find("\n", end)
            if line_end == -1: line_end = len(sanitized)
            before = sanitized[line_start:start]
            after = sanitized[end:line_end]

            if not before.strip() and not after.strip():
                return "\n" * match.group(0).count("\n")

            return f"CAC_JINJA_EXPR_{counter:06d}"

        sanitized = expression.sub(replace_expression, sanitized)
        return sanitized, contains_template
