import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_environment() -> None:
    """Load the selected dotenv file while preserving process environment values.

    Relative paths resolve from the project root. An explicitly selected missing file
    raises FileNotFoundError; a missing default .env is allowed.

    Returns:
        None: No return value.
    """
    custom_file = os.getenv("LAN_VULN_ENV_FILE")
    env_file = Path(custom_file).expanduser() if custom_file else Path(".env")
    if not env_file.is_absolute():
        env_file = PROJECT_ROOT / env_file
    if custom_file and not env_file.is_file():
        raise FileNotFoundError(f"Configuration file not found: {env_file}")
    load_dotenv(env_file, override=False)


load_environment()


@dataclass(frozen=True)
class ServiceConfig:
    scope_check_url: str
    nvd_client_url: str
    nvd_api_key: str
    nvd_cache_hours: int
    nvd_request_interval: float
    cpe_auto_fetch_enabled: bool
    cpe_fetch_interval_hours: int
    cpe_fetch_limit_per_product: int

    @classmethod
    def from_env(cls) -> "ServiceConfig":
        """Build service and NVD settings from the loaded environment.

        Returns:
            ServiceConfig: Parsed settings, with defaults for optional environment
                variables.
        """
        return cls(
            scope_check_url=os.environ["SCOPE_CHECK_URL"],
            nvd_client_url=os.getenv("NVD_CLIENT_URL", "https://services.nvd.nist.gov/rest/json"),
            nvd_api_key=os.getenv("NVD_API_KEY", ""),
            nvd_cache_hours=int(os.getenv("NVD_CACHE_HOURS", "24")),
            nvd_request_interval=float(os.getenv("NVD_REQUEST_INTERVAL", "7")),
            cpe_auto_fetch_enabled=(os.getenv("CPE_AUTO_FETCH_ENABLED", "false").lower() == "true"),
            cpe_fetch_interval_hours=int(os.getenv("CPE_FETCH_INTERVAL_HOURS", "24")),
            cpe_fetch_limit_per_product=int(os.getenv("CPE_FETCH_LIMIT_PER_PRODUCT", "500")),
        )


@dataclass(frozen=True)
class RabbitMQConfig:
    url: str
    exchange: str
    exchange_type: str
    queue: str
    request_binding: str
    cancel_binding: str
    completed_step_key: str
    completed_stage_key: str
    list_event_type: tuple[str, ...]
    dlx: str
    dlq: str

    @classmethod
    def from_env(cls) -> "RabbitMQConfig":
        """Build RabbitMQ routing and connection settings from the loaded environment.

        Returns:
            RabbitMQConfig: Parsed settings, with defaults for optional environment
                variables.
        """
        return cls(
            url=os.environ["RABBITMQ_URL"],
            exchange=os.getenv("RABBITMQ_EXCHANGE", "lan_scanner"),
            exchange_type=os.getenv("RABBITMQ_EXCHANGE_TYPE", "topic"),
            queue=os.getenv("RABBITMQ_QUEUE", "assessment.inbox"),
            request_binding=os.getenv("RABBITMQ_REQUEST_BINDING", "platform.assessment.#"),
            cancel_binding=os.getenv("RABBITMQ_CANCEL_BINDING", "platform.scan.cancelled"),
            completed_step_key=os.getenv("RABBITMQ_COMPLETED_STEP_KEY", "assessment.step.completed"),
            completed_stage_key=os.getenv("RABBITMQ_COMPLETED_STAGE_KEY", "assessment.stage.completed"),
            list_event_type=tuple(
                item.strip()
                for item in os.getenv(
                    "RABBITMQ_LIST_EVENT_TYPE",
                    "platform.assessment.stage.requested,"
                    "platform.scan.cancelled"
                ).split(",")
                if item.strip()
            ),
            dlx=os.getenv("RABBITMQ_DLX", "vulnerability.assessment.dlx"),
            dlq=os.getenv("RABBITMQ_DLQ", "vulnerability.assessment.dead.v2")
        )


@dataclass(frozen=True)
class DatabaseConfig:
    url: str
    pool_size: int = 5
    max_overflow: int = 5
    pool_timeout: int = 30
    pool_recycle: int = 1800
    connect_timeout: int = 10
    echo: bool = False

    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        """Build database connection pool settings from the loaded environment.

        Returns:
            DatabaseConfig: Parsed settings, with defaults for optional environment
                variables.
        """
        return cls(
            url=os.environ["DATABASE_URL"],
            pool_size=int(os.getenv("DB_POOL_SIZE", 5)),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", 5)),
            pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", 30)),
            pool_recycle=int(os.getenv("DB_POOL_RECYCLE", 1800)),
            connect_timeout=int(os.getenv("DB_CONNECT_TIMEOUT", 10)),
            echo=os.getenv("DB_ECHO", "false").lower() == "true"
        )
