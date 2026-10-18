
"""Clone, fetch, checkout revision và tìm rule.yml."""

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[4]
load_dotenv(PROJECT_ROOT / ".env")


class MisconfigRuleFetcher:
    DEFAULT_URL = "https://github.com/ComplianceAsCode/content.git"
    DEFAULT_DIRECTORIES = ("linux_os/guide", "applications")

    def __init__(
        self,
        git_url: str | None = None,
        git_ref: str | None = None,
        workspace: str | Path | None = None,
        timeout: int | None = None,
        content_directories: tuple[str, ...] | None = None,
    ):
        """Resolve repository settings and validate the Git ref and command timeout.

        Args:
            git_url (str | None): Source Git URL; None uses the environment setting or
                ComplianceAsCode default.
            git_ref (str | None): Branch, tag, or revision to fetch; None uses the
                environment setting or master.
            workspace (str | Path | None): Checkout directory; relative paths resolve
                from the project root. None uses configuration.
            timeout (int | None): Positive Git command timeout in seconds; None uses
                configuration.
            content_directories (tuple[str, ...] | None): Directories to scan within the
                checkout; None uses the default guide and applications paths.

        Returns:
            None: No return value.
        """
        self.git_url = (git_url or os.getenv("MISCONFIG_RULE_GIT_URL") or self.DEFAULT_URL)
        self.git_ref = (git_ref or os.getenv("MISCONFIG_RULE_GIT_REF") or "master")

        configured_workspace = (workspace or os.getenv("MISCONFIG_RULE_WORKSPACE", "./data/complianceascode"))
        workspace_path = Path(configured_workspace)
        if not workspace_path.is_absolute():
            workspace_path = PROJECT_ROOT / workspace_path

        self.workspace = workspace_path.resolve()

        self.timeout = int(
            timeout
            if timeout is not None
            else os.getenv("MISCONFIG_RULE_GIT_TIMEOUT_SECONDS", "300")
        )

        self.content_directories = (
            content_directories
            if content_directories is not None
            else self.DEFAULT_DIRECTORIES
        )

        if (
            not self.git_ref
            or self.git_ref.startswith("-")
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", self.git_ref)
            or ".." in self.git_ref
            or "@{" in self.git_ref
        ):
            raise ValueError("Invalid Git ref")

        if self.timeout <= 0:
            raise ValueError("Git timeout must be positive")

    def _git(self, *args: str, cwd: Path | None = None) -> str:
        """Run Git without a shell and convert process failures into RuntimeError.

        Args:
            cwd (Path | None): Working directory for Git; None inherits the process
                directory.
            *args (str): Git subcommand and arguments passed as separate process
                arguments.

        Returns:
            str: Trimmed standard output from the completed Git command.
        """

        command = ["git", "-c", "core.longpaths=true", *args]
        logger.debug("Executing Git command: %s", command)

        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=True,
                env={
                    **os.environ,
                    "GIT_TERMINAL_PROMPT": "0",
                },
            )

        except FileNotFoundError as exc:
            raise RuntimeError("Git is not installed or not available in PATH") from exc

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Git command timed out after {self.timeout}s") from exc

        except subprocess.CalledProcessError as exc:
            error = (exc.stderr or "").strip()
            raise RuntimeError(f"Git command failed: {error}") from exc

        return result.stdout.strip()

    def _is_repository(self) -> bool:
        """Check that the workspace is the root of a valid Git checkout.

        Returns:
            bool: True when the repository root exactly matches the configured
                workspace.
        """

        if not self.workspace.is_dir(): return False
        if not (self.workspace / ".git").exists(): return False

        try:
            result = self._git("rev-parse", "--show-toplevel", cwd=self.workspace)
            return Path(result).resolve() == self.workspace
        except RuntimeError:
            return False

    def _has_local_changes(self) -> bool:
        """Check tracked workspace files for staged or unstaged modifications.

        Returns:
            bool: True when Git reports tracked changes; untracked files are ignored.
        """
        status = self._git("status", "--porcelain", "--untracked-files=no", cwd=self.workspace)
        return bool(status)

    def _validate_remote(self) -> None:
        """Require the existing origin URL to match the configured source URL.

        Returns:
            None: No return value.
        """
        actual_url = self._git("remote", "get-url", "origin", cwd=self.workspace)

        def normalize_url(value: str) -> str:
            """Remove trailing slashes and a .git suffix for origin URL comparison.

            Args:
                value (str): Repository URL to compare.

            Returns:
                str: Normalized repository URL.
            """
            return value.rstrip("/").removesuffix(".git")

        if normalize_url(actual_url) != normalize_url(self.git_url):
            raise RuntimeError(f"Existing Git workspace has a different origin: {actual_url}. Expected: {self.git_url}")

    def _checkout_revision(self) -> None:
        """Shallow-fetch the configured ref and check out FETCH_HEAD in detached mode.

        Returns:
            None: No return value.
        """
        self._git("fetch", "--depth", "1", "origin", self.git_ref, cwd=self.workspace)

        self._git("checkout", "--detach", "--force", "FETCH_HEAD", cwd=self.workspace)

    def _update_repository(self) -> None:
        """Validate the checkout and remote, reject tracked changes, and update its
        revision.

        Returns:
            None: No return value.
        """
        if not self._is_repository(): raise RuntimeError(f"Invalid Git repository: {self.workspace}")

        self._validate_remote()

        if self._has_local_changes():
            raise RuntimeError("ComplianceAsCode workspace has local changes. Commit, stash or discard them manually.")

        logger.info("Updating existing ComplianceAsCode repository: %s", self.workspace)

        self._checkout_revision()

    def _clone_repository(self) -> None:
        """Create a shallow checkout and remove an incomplete clone if setup fails.

        Returns:
            None: No return value.
        """
        logger.info("Cloning ComplianceAsCode repository into %s", self.workspace)
        self.workspace.parent.mkdir(parents=True, exist_ok=True)

        if self.workspace.exists():
            raise RuntimeError(f"Cannot clone: workspace already exists: {self.workspace}")

        try:
            self._git("clone", "--depth", "1", "--no-checkout", self.git_url, str(self.workspace))
            self._checkout_revision()

            if not self._is_repository(): raise RuntimeError("Cloned repository validation failed")

        except Exception:
            logger.exception("ComplianceAsCode clone failed: %s", self.workspace)

            if self.workspace.exists():
                try:
                    shutil.rmtree(self.workspace)
                except OSError:
                    logger.warning("Failed to clean incomplete clone: %s", self.workspace, exc_info=True)
            raise

    def fetch_repository(self) -> Path:
        """Clone or update the configured checkout and verify its resolved revision.

        Returns:
            Path: Local repository workspace ready for rule discovery.
        """
        if self.workspace.exists():
            if not self.workspace.is_dir():
                raise RuntimeError(f"Workspace exists but is not a directory: {self.workspace}")

            if not self._is_repository():
                raise RuntimeError(f"Workspace exists but is not a valid Git repository: {self.workspace}")

            self._update_repository()

        else:
            self._clone_repository()

        revision = self.get_revision()
        logger.info("ComplianceAsCode repository ready: ""workspace=%s revision=%s", self.workspace, revision)
        return self.workspace

    def get_revision(self) -> str:
        """Read the exact HEAD commit of the validated checkout.

        Returns:
            str: Git commit hash; raises RuntimeError if the checkout is unavailable.
        """
        if not self._is_repository():
            raise RuntimeError("Repository has not been fetched")

        return self._git("rev-parse", "HEAD", cwd=self.workspace)

    def discover_rules(self) -> list[Path]:
        """Discover rule.yml files inside the configured checkout directories.

        Returns:
            list[Path]: Sorted unique rule file paths; symbolic links are excluded.
        """

        if not self._is_repository():
            raise RuntimeError("Repository has not been fetched")

        discovered: set[Path] = set()

        for directory in self.content_directories:
            root = (self.workspace / directory).resolve()

            if not root.is_relative_to(self.workspace):
                raise ValueError(f"Invalid content directory: {directory}")

            if not root.is_dir():
                logger.warning("Content directory not found: %s", directory)
                continue

            for path in root.rglob("rule.yml"):
                if path.is_file() and not path.is_symlink():
                    discovered.add(path)

        results = sorted(discovered)
        logger.info("Discovered %d ComplianceAsCode rule files", len(results))

        return results
