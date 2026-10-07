"""DET-DNSTUN: DNS tunnelling (PRD §10, architecture §7.3).

Unit: (client, registered domain). The registered domain comes from `tldextract` using only its
bundled public-suffix snapshot (no network fetch: the worker has no egress). Names under a suffix
the snapshot does not know (for example `.test`) fall back to their last two labels.
Metrics, per unit: unique subdomains, mean subdomain length and mean Shannon entropy (bits per
character, dots excluded) over the UNIQUE subdomain strings, TXT/NULL share and NXDOMAIN rate over
all queries, query count and total query-name bytes.
Fires when
  A) unique_subdomains >= min_unique_subdomains AND (mean entropy >= min_mean_entropy OR
     mean subdomain length >= min_mean_subdomain_len), or
  B) TXT/NULL share >= txt_null_share with >= txt_null_min_queries queries.
Confidence is high when A holds with BOTH the entropy and the length criterion, medium otherwise
(the documents define only the high condition). Allowlisted registered domains (the domain itself
or a parent entry) are suppressed and counted. Query names are attacker-controlled: they are
inspected as text only and the only one stored is the registered domain.
"""

import math
from collections import Counter
from functools import lru_cache

import numpy as np
import tldextract

from app.detect.base import (
    Confidence,
    DetectorInput,
    DetectorOutput,
    MetricValue,
    epoch_seconds,
    group_indices,
    make_finding,
)
from app.detect.config import DnsTunnelConfig

BENIGN_CAUSES = (
    "content delivery networks",
    "antivirus and reputation lookups",
    "telemetry",
    "ad-tech",
)

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@lru_cache(maxsize=65536)
def split_name(name: str) -> tuple[str, str]:
    """(registered domain, subdomain part) of a lower-cased DNS name without a trailing dot."""
    ext = _EXTRACT(name)
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}", ext.subdomain
    labels = name.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:]), ".".join(labels[:-2])
    return name, ""


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0.0 for the empty string)."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def is_allowlisted(registered: str, allowed: list[str]) -> bool:
    return any(registered == d or registered.endswith("." + d) for d in map(str.lower, allowed))


def thresholds(cfg: DnsTunnelConfig) -> dict[str, MetricValue]:
    return {
        "min_unique_subdomains": cfg.min_unique_subdomains,
        "min_mean_entropy": cfg.min_mean_entropy,
        "min_mean_subdomain_len": cfg.min_mean_subdomain_len,
        "txt_null_share": cfg.txt_null_share,
        "txt_null_min_queries": cfg.txt_null_min_queries,
        "txt_null_qtypes": ",".join(cfg.txt_null_qtypes),
    }


class DnsTunnelDetector:
    detector_id = "DET-DNSTUN"
    version = "1.0.0"

    def run(self, inp: DetectorInput) -> DetectorOutput:
        cfg = inp.config.dnstun
        out = DetectorOutput()
        dns = inp.tables.dns
        dns = dns[dns["query"].notna() & dns["orig_h"].notna()]
        if dns.empty:
            return out
        dns = dns.sort_values(["ts", "uid"], kind="stable").reset_index(drop=True).copy()
        names = dns["query"].astype(str).str.lower().str.rstrip(".")
        split = names.map(split_name)
        dns["registered"] = split.map(lambda pair: pair[0])
        dns["sub"] = split.map(lambda pair: pair[1])
        dns["name"] = names
        times = epoch_seconds(dns["ts"])
        qtypes = dns["qtype_name"].fillna("").astype(str).str.upper()
        txt_null = qtypes.isin([q.upper() for q in cfg.txt_null_qtypes]).to_numpy()
        rcode = dns["rcode_name"].fillna("").astype(str).str.upper()
        nx = (rcode == "NXDOMAIN").to_numpy()
        rcode_known = (rcode != "").to_numpy()
        uids = dns["uid"].astype(str).to_numpy(dtype=object)
        allowed = inp.network.allowlist.domains

        for (client, registered), idx in group_indices(dns, ["orig_h", "registered"]):
            n = len(idx)
            if n < min(cfg.min_unique_subdomains, cfg.txt_null_min_queries):
                continue
            subs = dns["sub"].to_numpy(dtype=object)[idx]
            unique_names = {
                str(name): str(sub)
                for name, sub in zip(dns["name"].to_numpy(dtype=object)[idx], subs, strict=True)
                if sub
            }
            unique_subs = sorted(set(unique_names.values()))
            unique = len(unique_names)
            mean_len = float(np.mean([len(s) for s in unique_subs])) if unique_subs else 0.0
            mean_entropy = (
                float(np.mean([shannon_entropy(s.replace(".", "")) for s in unique_subs]))
                if unique_subs
                else 0.0
            )
            txt_share = float(txt_null[idx].mean())
            known = int(rcode_known[idx].sum())
            nx_rate = float(nx[idx].sum() / known) if known else 0.0
            name_bytes = int(sum(len(x) for x in dns["name"].to_numpy(dtype=object)[idx]))

            entropy_ok = mean_entropy >= cfg.min_mean_entropy
            length_ok = mean_len >= cfg.min_mean_subdomain_len
            rule_a = unique >= cfg.min_unique_subdomains and (entropy_ok or length_ok)
            rule_b = txt_share >= cfg.txt_null_share and n >= cfg.txt_null_min_queries
            if not (rule_a or rule_b):
                continue
            confidence: Confidence = "high" if rule_a and entropy_ok and length_ok else "medium"
            if is_allowlisted(str(registered), allowed):
                out.suppressed["allowlisted_domain"] += 1
                continue
            out.findings.append(
                make_finding(
                    inp,
                    detector_id=self.detector_id,
                    version=self.version,
                    type_="DNSTUN",
                    primary=str(client),
                    secondary=[str(registered)],
                    start=float(times[idx[0]]),
                    end=float(times[idx[-1]]),
                    metrics={
                        "rule": "subdomain_volume" if rule_a else "txt_null_share",
                        "unique_subdomains": unique,
                        "mean_subdomain_len": round(mean_len, 4),
                        "mean_label_entropy": round(mean_entropy, 4),
                        "txt_null_share": round(txt_share, 4),
                        "nxdomain_rate": round(nx_rate, 4),
                        "query_count": n,
                        "name_bytes_total": name_bytes,
                    },
                    thresholds=thresholds(cfg),
                    confidence=confidence,
                    benign_causes=BENIGN_CAUSES,
                    uids=[str(u) for u in uids[idx]],
                )
            )
        return out


DETECTOR = DnsTunnelDetector()
