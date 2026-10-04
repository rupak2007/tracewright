"""Data-quality warnings (FR-06, architecture §6). Pure functions of measured profile values."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.errors import ConfigError

Severity = Literal["info", "warning"]
MetricValue = int | float | str | None


class ProfileConfig(BaseModel):
    """Thresholds from config/profile.yaml. Initial defaults, not measured values."""

    model_config = ConfigDict(extra="forbid")

    beacon_min_events: int = Field(gt=0)
    beacon_target_interval_s: float = Field(gt=0)
    one_sided_no_handshake_share: float = Field(ge=0, le=1)
    one_sided_min_tcp_connections: int = Field(ge=0)
    weird_share_of_connections: float = Field(ge=0)
    weird_min_count: int = Field(ge=0)
    snaplen_min_bytes: int = Field(gt=0)
    small_host_population_min_internal: int = Field(ge=0)
    weak_exfil_baseline_min_pairs: int = Field(ge=0)
    normalise_skipped_share: float = Field(ge=0, le=1)
    top_talkers: int = Field(gt=0)


class QualityWarning(BaseModel):
    code: str
    severity: Severity
    message: str
    metric: dict[str, MetricValue]


def load_profile_config(path: Path) -> ProfileConfig:
    try:
        return ProfileConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
        raise ConfigError(f"Invalid profile config {path.name}: {exc}") from exc


class WarningInputs(BaseModel):
    """The measured values warnings are derived from."""

    connections: int
    tcp_connections: int
    tcp_no_handshake: int
    weird_rows: int
    dns_queries: int
    internal_hosts: int
    internal_external_pairs: int
    span_s: float | None
    snaplen: int | None
    normalise_lines_total: int
    normalise_lines_skipped: int


def max_beacon_interval_s(span_s: float | None, cfg: ProfileConfig) -> float | None:
    """Longest beacon interval the capture can support: span / minimum events (PRD §10)."""
    if span_s is None or span_s <= 0:
        return None
    return span_s / cfg.beacon_min_events


def compute_warnings(m: WarningInputs, cfg: ProfileConfig) -> list[QualityWarning]:
    out: list[QualityWarning] = []

    def add(code: str, severity: Severity, message: str, **metric: MetricValue) -> None:
        out.append(QualityWarning(code=code, severity=severity, message=message, metric=metric))

    if m.connections == 0:
        add("NOTHING_TO_ANALYSE", "warning", "No connections were found in this capture.")
        return out  # every other warning would only restate this

    max_interval = max_beacon_interval_s(m.span_s, cfg)
    if max_interval is None or max_interval < cfg.beacon_target_interval_s:
        shown = "unknown" if max_interval is None else f"{max_interval:.3g} s"
        add(
            "CAPTURE_SHORT_FOR_BEACONS",
            "warning",
            f"Capture span supports beacon intervals up to about {shown} "
            f"(span / {cfg.beacon_min_events} events); slower beacons cannot be detected.",
            span_s=m.span_s,
            max_detectable_interval_s=max_interval,
        )

    if m.tcp_connections >= cfg.one_sided_min_tcp_connections:
        share = m.tcp_no_handshake / m.tcp_connections
        if share >= cfg.one_sided_no_handshake_share:
            add(
                "ONE_SIDED_TRAFFIC",
                "warning",
                f"{share:.0%} of TCP connections show no handshake (neither SYN nor SYN-ACK "
                "seen); the capture may be one-sided or start mid-flow, which degrades "
                "connection-state signals.",
                tcp_connections=m.tcp_connections,
                no_handshake_share=share,
            )

    if m.snaplen is not None and m.snaplen < cfg.snaplen_min_bytes:
        add(
            "TRUNCATED_PACKETS",
            "warning",
            f"Capture snap length is {m.snaplen} bytes; packets are truncated, so byte counts "
            "and payload-derived fields are unreliable.",
            snaplen=m.snaplen,
        )

    if m.weird_rows >= cfg.weird_min_count and (
        m.weird_rows / m.connections >= cfg.weird_share_of_connections
    ):
        add(
            "HIGH_WEIRD_COUNT",
            "warning",
            f"Zeek reported {m.weird_rows} protocol anomalies for {m.connections} connections; "
            "the capture may be damaged or contain unusual traffic.",
            weird_rows=m.weird_rows,
            connections=m.connections,
        )

    if m.internal_hosts < cfg.small_host_population_min_internal:
        add(
            "SMALL_HOST_POPULATION",
            "info",
            f"Only {m.internal_hosts} internal host(s) were observed; baselines derived from "
            "this capture are weak.",
            internal_hosts=m.internal_hosts,
        )

    if m.dns_queries == 0:
        add("NO_DNS", "info", "No DNS traffic was observed; DNS-based detection is not applicable.")

    if m.internal_external_pairs < cfg.weak_exfil_baseline_min_pairs:
        add(
            "WEAK_BASELINE_EXFIL",
            "info",
            f"Only {m.internal_external_pairs} internal-to-external host pair(s); exfiltration "
            "checks will use an absolute volume floor only, with lowered confidence.",
            internal_external_pairs=m.internal_external_pairs,
        )

    if m.normalise_lines_total and (
        m.normalise_lines_skipped / m.normalise_lines_total > cfg.normalise_skipped_share
    ):
        add(
            "NORMALISE_SKIPPED_HIGH",
            "warning",
            f"{m.normalise_lines_skipped} of {m.normalise_lines_total} Zeek log lines could not "
            "be parsed and were skipped.",
            lines_skipped=m.normalise_lines_skipped,
            lines_total=m.normalise_lines_total,
        )
    return out
