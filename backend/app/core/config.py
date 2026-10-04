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
    zeek_bin: str = "zeek"
    # Baked in at image build time (Dockerfile.worker) so a drifted base image fails loudly.
    zeek_expected_version: str | None = None
    zeek_timeout_s: int = Field(default=900, gt=0)
    capinfos_bin: str = "capinfos"
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


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_pipeline_settings() -> PipelineSettings:
    return PipelineSettings()
