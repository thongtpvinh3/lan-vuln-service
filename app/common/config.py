import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values, load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_environment() -> None:
    """Load the selected dotenv file without replacing process environment values."""
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
    queue: str
    completed_step_key: str
    completed_stage_key: str
    list_event_type: tuple[str, ...]
    topology_version: int

    @classmethod
    def from_env(cls) -> "RabbitMQConfig":
        # Only Platform exports these non-secret settings. A file is convenient for
        # local runs; deployments may inject the generated entries directly.
        keys = ("RABBITMQ_TOPOLOGY_VERSION", "RABBITMQ_EXCHANGE", "RABBITMQ_QUEUE")
        metadata = {}
        config_file = os.getenv("RABBITMQ_CLIENT_ENV_FILE")
        if config_file:
            path = Path(config_file).expanduser()
            if not path.is_absolute():
                path = PROJECT_ROOT / path
            if not path.is_file():
                raise FileNotFoundError(f"Generated RabbitMQ client configuration not found: {path}")
            metadata = dotenv_values(path, interpolate=False)
            if set(metadata) != set(keys):
                raise ValueError("RabbitMQ client file must contain exactly the three Platform-generated settings")
            for key in keys:
                if key in os.environ and os.environ[key] != metadata[key]:
                    raise ValueError(f"{key} conflicts with the Platform-generated client file")
        else:
            metadata = {key: os.getenv(key) for key in keys}
        if any(not metadata.get(key) for key in keys):
            raise ValueError(
                "Missing Platform-generated RabbitMQ client settings; export-env --service assessment "
                "in Platform and set RABBITMQ_CLIENT_ENV_FILE or inject its entries"
            )
        if metadata["RABBITMQ_TOPOLOGY_VERSION"] != "1":
            raise ValueError("Unsupported RabbitMQ topology version; deploy a compatible Assessment release")
        retired = (
            "RABBITMQ_EXCHANGE_TYPE", "RABBITMQ_REQUEST_BINDING", "RABBITMQ_CANCEL_BINDING",
            "RABBITMQ_DLX", "RABBITMQ_DLQ",
        )
        if any(key in os.environ for key in retired):
            raise ValueError("Remove retired RabbitMQ topology settings: " + ", ".join(
                key for key in retired if key in os.environ
            ) + "; Platform owns declarations and bindings")
        return cls(
            url=os.environ["RABBITMQ_URL"],
            exchange=metadata["RABBITMQ_EXCHANGE"],
            queue=metadata["RABBITMQ_QUEUE"],
            topology_version=int(metadata["RABBITMQ_TOPOLOGY_VERSION"]),
            completed_step_key=os.getenv("RABBITMQ_COMPLETED_STEP_KEY", "assessment.step.completed"),
            completed_stage_key=os.getenv("RABBITMQ_COMPLETED_STAGE_KEY", "assessment.stage.completed"),
            list_event_type=tuple(
                item.strip()
                for item in os.getenv(
                    "RABBITMQ_LIST_EVENT_TYPE",
                    "platform.assessment.stage.requested,platform.scan.cancelled"
                ).split(",") if item.strip()
            ),
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
        return cls(
            url=os.environ["DATABASE_URL"],
            pool_size=int(os.getenv("DB_POOL_SIZE", 5)),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", 5)),
            pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", 30)),
            pool_recycle=int(os.getenv("DB_POOL_RECYCLE", 1800)),
            connect_timeout=int(os.getenv("DB_CONNECT_TIMEOUT", 10)),
            echo=os.getenv("DB_ECHO", "false").lower() == "true"
        )
