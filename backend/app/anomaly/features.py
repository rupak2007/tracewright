"""Entity-window features v1 (architecture §8): 16 features per (internal host, tumbling window).

Windows start at the capture's first connection and are `window_s` long; a row exists for every
internal host with any activity in the window. Raw counts/bytes/durations get `log1p` (Isolation
Forest draws split points uniformly between feature min and max, so heavy tails would dominate);
shares and the entropy stay linear; the byte ratio is `log((out+1)/(in+1))`. Pure function of the
normalised tables and the network context.
"""

import numpy as np
import pandas as pd

from app.anomaly.config import AnomalyConfig
from app.detect.base import epoch_seconds
from app.detect.dns_tunnel import shannon_entropy, split_name
from app.ingest.normalise import CaptureTables
from app.profile.context import NetworkContext

FEATURES = (
    "out_conns",
    "in_conns",
    "distinct_dst_ips",
    "distinct_dst_ports",
    "failed_share",
    "bytes_out",
    "bytes_in",
    "out_in_ratio",
    "mean_duration",
    "external_dst_share",
    "no_service_share",
    "nonstd_port_share",
    "dns_queries",
    "distinct_domains",
    "dns_label_entropy",
    "icmp_conns",
)
LOG1P = (
    "out_conns",
    "in_conns",
    "distinct_dst_ips",
    "distinct_dst_ports",
    "bytes_out",
    "bytes_in",
    "mean_duration",
    "dns_queries",
    "distinct_domains",
    "icmp_conns",
)


def _prepare(conn: pd.DataFrame, t0: float, window_s: float) -> pd.DataFrame:
    out = conn.copy()
    out["_t"] = epoch_seconds(out["ts"])
    out["widx"] = np.floor((out["_t"] - t0) / window_s).astype(np.int64)
    for column in ("orig_bytes", "resp_bytes"):
        out[column] = out[column].fillna(0).astype(np.int64)
    out["duration"] = out["duration"].astype("float64")
    return out


def build_windows(
    tables: CaptureTables,
    network: NetworkContext,
    cfg: AnomalyConfig,
    t0: float | None = None,
) -> pd.DataFrame:
    """One row per (host, window): `host`, `widx`, `window_start` (epoch s) and the 16 features."""
    conn = tables.conn[tables.conn["orig_h"].notna() & tables.conn["resp_h"].notna()]
    empty = pd.DataFrame(columns=["host", "widx", "window_start", *FEATURES])
    if conn.empty:
        return empty
    start = float(epoch_seconds(conn["ts"]).min()) if t0 is None else t0
    conn = _prepare(conn, start, cfg.window_s)
    fcfg = cfg.features
    zone_o = network.classify_series(conn["orig_h"])
    zone_r = network.classify_series(conn["resp_h"])
    conn["o_int"] = zone_o == "internal"
    conn["r_int"] = zone_r == "internal"
    standard = set(fcfg.extra_standard_ports)
    port = conn["resp_p"].fillna(0).astype(np.int64)
    conn["nonstd"] = (
        conn["proto"].isin(["tcp", "udp"]) & (port > fcfg.standard_port_max) & ~port.isin(standard)
    )
    conn["failed"] = conn["conn_state"].isin(fcfg.failed_states)
    conn["established"] = conn["conn_state"].isin(fcfg.established_states)
    conn["no_service"] = conn["established"] & conn["service"].isna()

    outbound = conn[conn["o_int"]]
    inbound = conn[conn["r_int"]]
    frames: list[pd.DataFrame] = []
    if not outbound.empty:
        outbound = outbound.assign(ext=~outbound["r_int"])
        g = outbound.groupby(["orig_h", "widx"])
        frames.append(
            pd.DataFrame(
                {
                    "out_conns": g.size(),
                    "distinct_dst_ips": g["resp_h"].nunique(),
                    "distinct_dst_ports": g["resp_p"].nunique(),
                    "failed_share": g["failed"].mean(),
                    "bytes_out": g["orig_bytes"].sum(),
                    "bytes_in": g["resp_bytes"].sum(),
                    "external_dst_share": g["ext"].mean(),
                    "nonstd_port_share": g["nonstd"].mean(),
                }
            ).rename_axis(["host", "widx"])
        )
    if not inbound.empty:
        g = inbound.groupby(["resp_h", "widx"])
        inb = pd.DataFrame(
            {
                "in_conns": g.size(),
                "bytes_out_in": g["resp_bytes"].sum(),
                "bytes_in_in": g["orig_bytes"].sum(),
            }
        ).rename_axis(["host", "widx"])
        frames.append(inb)
    involved = pd.concat(
        [
            outbound.rename(columns={"orig_h": "host"})[
                ["host", "widx", "duration", "established", "no_service", "proto"]
            ],
            inbound.rename(columns={"resp_h": "host"})[
                ["host", "widx", "duration", "established", "no_service", "proto"]
            ],
        ],
        ignore_index=True,
    )
    if not involved.empty:
        g = involved.groupby(["host", "widx"])
        est = g["established"].sum()
        frames.append(
            pd.DataFrame(
                {
                    "mean_duration": g["duration"].mean(),
                    "no_service_share": (g["no_service"].sum() / est.where(est > 0)).fillna(0.0),
                    "icmp_conns": g["proto"].apply(lambda s: int((s == "icmp").sum())),
                }
            )
        )
    frames.append(_dns_frame(tables, network, start, cfg))
    merged = pd.concat([f for f in frames if not f.empty], axis=1).fillna(0.0).reset_index()
    for column in ("out_conns", "in_conns", "bytes_out_in", "bytes_in_in"):
        if column not in merged:
            merged[column] = 0.0
    merged["bytes_out"] = merged.get("bytes_out", 0.0) + merged["bytes_out_in"]
    merged["bytes_in"] = merged.get("bytes_in", 0.0) + merged["bytes_in_in"]
    for column in FEATURES:
        if column not in merged:
            merged[column] = 0.0
    merged["out_in_ratio"] = np.log((merged["bytes_out"] + 1.0) / (merged["bytes_in"] + 1.0))
    for column in LOG1P:
        merged[column] = np.log1p(merged[column].astype("float64"))
    merged["window_start"] = start + merged["widx"].astype("float64") * cfg.window_s
    merged = merged[["host", "widx", "window_start", *FEATURES]]
    return merged.sort_values(["window_start", "host"], kind="stable").reset_index(drop=True)


def _dns_frame(
    tables: CaptureTables, network: NetworkContext, t0: float, cfg: AnomalyConfig
) -> pd.DataFrame:
    dns = tables.dns[tables.dns["orig_h"].notna() & tables.dns["query"].notna()]
    if dns.empty:
        return pd.DataFrame()
    dns = dns[network.classify_series(dns["orig_h"]) == "internal"].copy()
    if dns.empty:
        return pd.DataFrame()
    dns["widx"] = np.floor((epoch_seconds(dns["ts"]) - t0) / cfg.window_s).astype(np.int64)
    names = dns["query"].astype(str).str.lower().str.rstrip(".")
    split = names.map(split_name)
    dns["registered"] = split.map(lambda p: p[0])
    dns["entropy"] = split.map(lambda p: shannon_entropy(p[1].replace(".", "")) if p[1] else np.nan)
    g = dns.groupby(["orig_h", "widx"])
    return pd.DataFrame(
        {
            "dns_queries": g.size().astype("float64"),
            "distinct_domains": g["registered"].nunique().astype("float64"),
            "dns_label_entropy": g["entropy"].mean().fillna(0.0),
        }
    ).rename_axis(["host", "widx"])
