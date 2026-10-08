"""Deterministic narrative validator (architecture §13, GR-04..GR-08). Pure: no I/O, no clock.

Six checks, every failure is reported (the list feeds the one repair attempt):
 1 the text parses as JSON and matches the output schema;
 2 every cited E-/F-/K- id exists in the pack, and K- ids are this incident's technique cards or
   detector playbooks;
 3 every pseudonym, port and number in an `observed` statement appears in the fields of the evidence
   it cites (numbers within +-1%, with percent, byte and time unit normalisation); pseudonyms in any
   other text must at least exist in the pack;
 4 every inference has a confidence and at least one alternative explanation;
 5 no verdict language anywhere (`is compromised`, `confirmed attack`, `definitely`, `proves`, ...);
 6 no real IP address, domain-like name or server-side real value anywhere (pseudonym leak guard).
"""

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from app.explain.evidence_pack import EvidencePack
from app.explain.schema import NarrativeOutput

TOLERANCE = 0.01
BANNED = re.compile(
    r"is compromised|has been compromised|confirmed\s+(?:attack|breach|compromise)|definitely"
    r"|\bproves?\b|without\s+(?:a\s+)?doubt|\binfected\b",
    re.IGNORECASE,
)
_ID = re.compile(r"^(?:E-\d+|F-\d+|K-[A-Za-z0-9.\-]+)$")
_TOKEN = re.compile(r"\b[HXD]\d+\b")
_TIME = re.compile(r"T\+\d{2}:\d{2}(?::\d{2})?")
_ID_IN_TEXT = re.compile(r"\b(?:E|F)-\d+\b|\bK-[A-Za-z0-9.\-]+\b|\bT\d{4}(?:\.\d{3})?\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_CANDIDATE = re.compile(r"[0-9A-Fa-f:]{3,}")
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
# a number, optionally followed by a unit; a sentence-ending period after it is fine
_NUMBER = re.compile(
    r"(?<![\w.])(\d+(?:\.\d+)?)\s?"
    r"(%|[KMGT]i?B|bytes?|ms|seconds?|secs?|minutes?|mins?|hours?|s|h)?(?!\w)(?!\.\d)"
)
_PLAIN_NUMBER = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?!\w)(?!\.\d)")
_UNIT_FACTORS: dict[str, tuple[float, ...]] = {
    "": (1.0,),
    "%": (1.0, 0.01),
    "b": (1.0,),
    "byte": (1.0,),
    "bytes": (1.0,),
    "kb": (1e3, 1024.0),
    "kib": (1024.0,),
    "mb": (1e6, 1024.0**2),
    "mib": (1024.0**2,),
    "gb": (1e9, 1024.0**3),
    "gib": (1024.0**3,),
    "tb": (1e12, 1024.0**4),
    "tib": (1024.0**4,),
    "ms": (1e-3,),
    "s": (1.0,),
    "sec": (1.0,),
    "secs": (1.0,),
    "second": (1.0,),
    "seconds": (1.0,),
    "min": (60.0,),
    "mins": (60.0,),
    "minute": (60.0,),
    "minutes": (60.0,),
    "h": (3600.0,),
    "hour": (3600.0,),
    "hours": (3600.0,),
}


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    output: NarrativeOutput | None = None


def _strip_fence(text: str) -> str:
    stripped = text.strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", stripped, re.DOTALL)
    return fenced.group(1) if fenced else stripped


def _numbers(value: Any) -> list[float]:
    """Every number reachable in a pack fragment (numeric strings too; time stamps excluded)."""
    if isinstance(value, bool):
        return []
    if isinstance(value, int | float):
        return [float(value)] if math.isfinite(value) else []
    if isinstance(value, str):
        if _TIME.fullmatch(value):
            return []
        return [float(m.group(0)) for m in _PLAIN_NUMBER.finditer(value)]
    if isinstance(value, dict):
        return [n for v in value.values() for n in _numbers(v)]
    if isinstance(value, list):
        return [n for v in value for n in _numbers(v)]
    return []


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _close(a: float, b: float) -> bool:
    if b == 0:
        return a == 0
    return abs(a - b) <= TOLERANCE * abs(b) or abs(a - b) < 1e-9


def _number_supported(
    number: float, unit: str, available: list[float], exact: bool = False
) -> bool:
    """`exact` (a bare integer such as a port or a count) must match a stored number exactly: the
    +-1% tolerance is for rounding of measured, unit-bearing or decimal values only."""
    if exact:
        return any(number == v for v in available)
    factors = _UNIT_FACTORS.get(unit.lower(), (1.0,))
    candidates = {number * f for f in factors}
    if unit == "%":
        candidates.add(number)  # "90%" may cite a stored 90 as well as a stored 0.9
    return any(_close(c, v) for c in candidates for v in available)


def _has_ipv6(text: str) -> str | None:
    """The first token that parses as an IPv6 address (handles `::`), or None."""
    for token in _IPV6_CANDIDATE.findall(text):
        if token.count(":") < 2:
            continue
        # a sentence may end right after the address ("... 2001:db8::1:2."): try trimmed forms too
        for candidate in (token, token.rstrip(":"), token.lstrip(":"), token.strip(":")):
            try:
                ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            return str(candidate)
    return None


def _texts(output: NarrativeOutput) -> list[str]:
    texts = [output.summary, *output.open_questions]
    texts += [o.statement for o in output.observed]
    for i in output.inferences:
        texts += [i.statement, *i.alternative_explanations]
    texts += [r.action for r in output.recommendations]
    return texts


def _evidence_for(pack: EvidencePack, cited: list[str]) -> tuple[list[float], set[str], list[str]]:
    """Numbers, pseudonym tokens and string values available in the cited evidence / findings."""
    numbers: list[float] = []
    tokens: set[str] = set()
    strings: list[str] = []
    findings = {f["fid"]: f for f in pack.pack["findings"]}
    for cid in cited:
        item: Any = pack.pack["evidence"].get(cid) or findings.get(cid)
        if item is None:
            continue
        numbers += _numbers(item)
        for text in _strings(item):
            strings.append(text)
            tokens.update(_TOKEN.findall(text))
    return numbers, tokens, strings


def validate_narrative(raw: str, pack: EvidencePack) -> ValidationResult:
    errors: list[str] = []
    try:
        data = json.loads(_strip_fence(raw))
    except ValueError:
        return ValidationResult(False, ["check 1: the output is not valid JSON"])
    try:
        output = NarrativeOutput.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:6]
        )
        return ValidationResult(False, [f"check 1: schema violation ({details})"])

    # 2. cited ids exist; K- ids belong to this incident
    known_e = set(pack.pack["evidence"])
    known_f = {f["fid"] for f in pack.pack["findings"]}
    known_k = set(pack.pack["knowledge"])
    cited_groups: list[tuple[str, list[str]]] = []
    cited_groups += [(f"observed[{n}]", o.evidence_ids) for n, o in enumerate(output.observed)]
    for n, inf in enumerate(output.inferences):
        cited_groups.append((f"inferences[{n}].supporting_ids", inf.supporting_ids))
        cited_groups.append((f"inferences[{n}].knowledge_ids", inf.knowledge_ids))
    cited_groups += [
        (f"recommendations[{n}]", r.rationale_ids) for n, r in enumerate(output.recommendations)
    ]
    for where, ids in cited_groups:
        for cid in ids:
            if not _ID.match(cid):
                errors.append(f"check 2: {where} cites {cid!r}, which is not an E-/F-/K- id")
            elif cid.startswith("E-") and cid not in known_e:
                errors.append(f"check 2: {where} cites {cid}, which is not in the evidence pack")
            elif cid.startswith("F-") and cid not in known_f:
                errors.append(
                    f"check 2: {where} cites {cid}, which is not a finding of this incident"
                )
            elif cid.startswith("K-") and cid not in known_k:
                errors.append(
                    f"check 2: {where} cites {cid}, not a technique or playbook of this incident"
                )
    for n, inf in enumerate(output.inferences):
        for cid in inf.knowledge_ids:
            if _ID.match(cid) and not cid.startswith("K-"):
                errors.append(f"check 2: inferences[{n}].knowledge_ids must be K- ids, got {cid}")
    for n, o in enumerate(output.observed):
        if not all(c.startswith(("E-", "F-")) for c in o.evidence_ids):
            errors.append(f"check 2: observed[{n}] must cite E- or F- ids only")

    # 3. observed statements: tokens, times, ports and numbers come from the cited evidence
    pack_tokens = set(pack.pack["entities"])
    for n, o in enumerate(output.observed):
        numbers, tokens, strings = _evidence_for(pack, o.evidence_ids)
        statement = o.statement
        for token in _TOKEN.findall(statement):
            if token not in pack_tokens:
                errors.append(f"check 3: observed[{n}] names {token}, which is not in the pack")
            elif token not in tokens:
                errors.append(
                    f"check 3: observed[{n}] names {token}, absent from its cited evidence"
                )
        for stamp in _TIME.findall(statement):
            if not any(stamp in s or s.startswith(stamp) for s in strings):
                errors.append(
                    f"check 3: observed[{n}] states time {stamp}, absent from its cited evidence"
                )
        scrub = _TIME.sub(" ", _ID_IN_TEXT.sub(" ", _TOKEN.sub(" ", statement)))
        for m in _NUMBER.finditer(scrub):
            number, unit = float(m.group(1)), m.group(2) or ""
            exact = unit == "" and "." not in m.group(1)
            if not _number_supported(number, unit, numbers, exact):
                stated = m.group(0).strip()
                errors.append(
                    f"check 3: observed[{n}] states {stated}, absent from its cited evidence"
                )
    for text in _texts(output):
        for token in _TOKEN.findall(text):
            if token not in pack_tokens:
                errors.append(f"check 3: the text names {token}, which is not in the pack")

    # 4. inferences are hedged
    for n, inf in enumerate(output.inferences):
        if not [a for a in inf.alternative_explanations if a.strip()]:
            errors.append(f"check 4: inferences[{n}] has no alternative explanation")

    # 5. no verdict language (anywhere, including the raw text)
    for text in [*_texts(output), raw]:
        match = BANNED.search(text)
        if match:
            errors.append(f"check 5: verdict language {match.group(0)!r} is not allowed")
            break

    # 6. no real addresses, names or server-side values
    combined = "\n".join(_texts(output))
    untimed = _TIME.sub(" ", combined)  # relative times look like IPv6 otherwise
    v4 = _IPV4.search(untimed)
    if v4:
        errors.append(f"check 6: a real IPv4 address ({v4.group(0)}) appears; use the pseudonyms")
    v6 = _has_ipv6(untimed)
    if v6:
        errors.append(f"check 6: a real IPv6 address ({v6}) appears; use the pseudonyms")
    domain = _DOMAIN.search(_ID_IN_TEXT.sub(" ", combined))
    if domain and not re.fullmatch(r"\d+(?:\.\d+)+", domain.group(0)):
        errors.append(
            f"check 6: a domain-like name ({domain.group(0)}) appears; use the pseudonyms"
        )
    for real in pack.mapping.values():
        if real and real in combined:
            errors.append("check 6: a real host or domain from the capture appears in the text")
            break

    unique = list(dict.fromkeys(errors))
    return ValidationResult(not unique, unique, output if not unique else None)
