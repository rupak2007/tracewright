"""Settings loaded from environment variables only. Secrets are never defaulted to real values."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class PipelineSettings(BaseSettings):
    """Settings the analysis pipeline needs. No database fields, so the CLI runs without them."""

    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    environment: Literal["dev", "prod"] = "prod"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    max_upload_bytes: int = Field(default=500 * 1024 * 1024, gt=0)
    min_free_disk_bytes: int = Field(default=1024**3, ge=0)

    config_dir: Path = Path("config")
    anomaly_scorer: Literal["off", "robust_z", "iforest"] = "off"  # gate G1: eval/decisions/G1.md
    knowledge_dir: Path = Path("knowledge")  # playbooks/ and cards/<attack version>/
    zeek_bin: str = "zeek"
    # Baked in at image build time (Dockerfile.worker) so a drifted base image fails loudly.
    zeek_expected_version: str | None = None
    zeek_timeout_s: int = Field(default=900, gt=0)
    capinfos_bin: str = "capinfos"
    tcpdump_bin: str = "tcpdump"
    editcap_bin: str = "editcap"
    tool_timeout_s: int = Field(default=60, gt=0)


class Settings(PipelineSettings):
    postgres_host: str = "db"
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_db: str
    postgres_user: str
    postgres_password: SecretStr

    uploads_dir: Path = Path("/data/uploads")
    artifacts_dir: Path = Path("/data/artifacts")

    @property
    def database_url(self) -> URL:
        return URL.create(
            "postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )


class LlmSettings(BaseSettings):
    """Optional narrative provider (SEC-05): `none` by default; external providers need explicit
    configuration and a key from the environment. Read by the API only, never by the worker."""

    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    llm_provider: Literal["none", "ollama", "openai_compatible", "anthropic"] = "none"
    llm_model: str = ""
    llm_base_url: str = ""  # ollama: http://ollama:11434; openai_compatible: .../v1
    llm_api_key: SecretStr | None = None
    llm_timeout_s: float = Field(default=120.0, gt=0)


@lru_cache
def get_llm_settings() -> LlmSettings:
    return LlmSettings()


class ApiSettings(BaseSettings):
    """HTTP edge settings (SEC-07): optional bearer token; CORS limited to the UI origins."""

    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    api_token: SecretStr | None = None
    cors_origins: list[str] = [
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://localhost:5173",
    ]


@lru_cache
def get_api_settings() -> ApiSettings:
    return ApiSettings()


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_pipeline_settings() -> PipelineSettings:
    return PipelineSettings()
