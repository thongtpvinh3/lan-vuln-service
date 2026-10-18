import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.fixture
def config_runner(tmp_path):
    # Isolate the project's dotenv loader from developer credentials and app startup.
    """Create an isolated project and subprocess runner for dotenv configuration tests.

    Args:
        tmp_path (Path): Pytest temporary directory used to construct the isolated
            project.

    Returns:
        tuple[Path, Callable[..., subprocess.CompletedProcess[str]]]: Temporary project
            root and isolated configuration runner.
    """
    project_root = tmp_path / "project"
    config_path = project_root / "app" / "common" / "config.py"
    config_path.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__).resolve().parents[1] / "app/common/config.py", config_path)
    (project_root / ".env").write_text(
        "SCOPE_CHECK_URL=http://default.example/check\nDATABASE_URL=default-only\n",
        encoding="utf-8",
    )
    script = """
import json
import os
import runpy
import sys

namespace = runpy.run_path(sys.argv[1])
config = namespace["ServiceConfig"].from_env()
print(json.dumps({
    "scope": config.scope_check_url,
    "cache_hours": config.nvd_cache_hours,
    "interval": config.nvd_request_interval,
    "auto_fetch": config.cpe_auto_fetch_enabled,
    "has_database": "DATABASE_URL" in os.environ,
}))
"""

    def run(**overrides):
        """Run the copied configuration loader with a filtered environment and explicit
        overrides.

        Args:
            **overrides (str): Environment variable overrides applied to the isolated
                subprocess.

        Returns:
            subprocess.CompletedProcess[str]: Process result with captured stdout,
                stderr, and exit code.
        """
        env = {
            key: value for key, value in os.environ.items()
            if key not in {"LAN_VULN_ENV_FILE", "SCOPE_CHECK_URL", "DATABASE_URL", "PYTHON_DOTENV_DISABLED"}
            and not key.startswith(("NVD_", "CPE_"))
        }
        env.update(overrides)
        return subprocess.run(
            [sys.executable, "-c", script, str(config_path)],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    return project_root, run


def test_default_file_is_relative_to_project_root(config_runner):
    """Verify that the default dotenv path resolves from the copied project root.

    Args:
        config_runner (tuple[Path, Callable[..., subprocess.CompletedProcess[str]]]):
            Temporary project root and isolated configuration runner.

    Returns:
        None: No return value.
    """
    _, run = config_runner
    result = run()
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "scope": "http://default.example/check",
        "cache_hours": 24,
        "interval": 7.0,
        "auto_fetch": False,
        "has_database": True,
    }


@pytest.mark.parametrize("absolute", [False, True])
def test_custom_file_replaces_default_file(config_runner, absolute):
    """Verify that a selected dotenv file replaces the default for relative and absolute
    paths.

    Args:
        config_runner (tuple[Path, Callable[..., subprocess.CompletedProcess[str]]]):
            Temporary project root and isolated configuration runner.
        absolute (bool): Whether to select the custom dotenv file with an absolute path.

    Returns:
        None: No return value.
    """
    root, run = config_runner
    custom_file = root / "config" / "local.env"
    custom_file.parent.mkdir()
    custom_file.write_text(
        "SCOPE_CHECK_URL=http://custom.example/check\nNVD_CACHE_HOURS=12\n"
        "NVD_REQUEST_INTERVAL=0.5\nCPE_AUTO_FETCH_ENABLED=true\n",
        encoding="utf-8",
    )
    result = run(LAN_VULN_ENV_FILE=str(custom_file) if absolute else "config/local.env")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "scope": "http://custom.example/check",
        "cache_hours": 12,
        "interval": 0.5,
        "auto_fetch": True,
        "has_database": False,
    }


def test_process_environment_overrides_file(config_runner):
    """Verify that process environment values take precedence over dotenv values.

    Args:
        config_runner (tuple[Path, Callable[..., subprocess.CompletedProcess[str]]]):
            Temporary project root and isolated configuration runner.

    Returns:
        None: No return value.
    """
    _, run = config_runner
    result = run(SCOPE_CHECK_URL="http://process.example/check")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["scope"] == "http://process.example/check"


def test_missing_custom_file_fails_instead_of_loading_default(config_runner):
    """Verify that explicitly selecting a missing dotenv file fails.

    Args:
        config_runner (tuple[Path, Callable[..., subprocess.CompletedProcess[str]]]):
            Temporary project root and isolated configuration runner.

    Returns:
        None: No return value.
    """
    _, run = config_runner
    result = run(LAN_VULN_ENV_FILE="missing.env")
    assert result.returncode != 0
    assert "FileNotFoundError: Configuration file not found:" in result.stderr
    assert "missing.env" in result.stderr


def test_default_file_is_optional_with_process_configuration(config_runner):
    """Verify that process configuration works without a default dotenv file.

    Args:
        config_runner (tuple[Path, Callable[..., subprocess.CompletedProcess[str]]]):
            Temporary project root and isolated configuration runner.

    Returns:
        None: No return value.
    """
    root, run = config_runner
    (root / ".env").unlink()
    result = run(SCOPE_CHECK_URL="http://container.example/check")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["scope"] == "http://container.example/check"
