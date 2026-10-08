"""Narrative endpoints: start generation (background) and read the validated result or the fallback.

The narrative is generated in the API (never in the worker) from the pseudonymised evidence pack.
The raw model output is stored for evaluation but never returned: `output` is set only for a
validated narrative, and the real values behind the pseudonyms are returned separately for display.
"""

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Request
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.api.deps import AuthDep, RowId, SessionDep, SettingsDep
from app.api.errors import ApiError
from app.api.schemas import NarrativeOut
from app.attack.cards import load_cards
from app.core.config import Settings, get_llm_settings
from app.core.errors import ConfigError
from app.db.models import Incident, Investigation, Narrative, utcnow
from app.explain.evidence_pack import EvidencePack, build_pack
from app.explain.knowledge import load_playbooks
from app.explain.llm_client import LlmClient, LlmUnavailable, NoneClient, make_client
from app.explain.narrative import generate_narrative, prompt_hash
from app.explain.pseudonymise import Pseudonymiser
from app.explain.schema import NarrativeOutput
from app.profile.context import load_network_context
from app.report.model import IncidentDetail
from app.report.narrative_block import NarrativeBlock

router = APIRouter(dependencies=[AuthDep])
LABEL = "Machine-generated narrative, validated against the evidence; the analyst decides."
ClientFactory = Callable[[], LlmClient]


def default_client_factory() -> LlmClient:
    try:
        return make_client(get_llm_settings())
    except LlmUnavailable:
        return NoneClient()


def pack_for(inc: Incident, inv: Investigation, settings: Settings) -> EvidencePack:
    """The incident's pseudonymised pack; the mapping is rebuilt identically on every read."""
    detail = IncidentDetail.model_validate(inc.detail)
    profile = inv.profile or {}
    capture = profile.get("capture", {})
    start = capture.get("first_ts") or inc.start_ts.timestamp()
    network = load_network_context(settings.config_dir / "network.yaml")
    version = str((inv.manifest or {}).get("attack_version", ""))
    try:
        cards = load_cards(settings.knowledge_dir / "cards" / version)
        playbooks = load_playbooks(settings.knowledge_dir)
    except ConfigError:
        cards, playbooks = {}, {}
    return build_pack(
        detail,
        capture_start=float(start),
        capture_span_s=capture.get("duration_s"),
        warning_codes=[str(w.get("code")) for w in (inv.warnings or []) if isinstance(w, dict)],
        max_beacon_interval_s=profile.get("max_beacon_interval_s"),
        pseudo=Pseudonymiser(lambda ip: network.classify(ip) == "internal"),
        cards=cards,
        playbooks=playbooks,
    )


def validated_narrative_block(
    session: Session, inc: Incident, inv: Investigation, settings: Settings
) -> dict[str, NarrativeBlock] | None:
    """The incident's narrative for a report, only when it passed validation (else the template)."""
    row = session.scalars(select(Narrative).where(Narrative.incident_id == inc.id)).first()
    if row is None or row.status != "validated" or not row.output:
        return None
    block = NarrativeBlock(
        NarrativeOutput.model_validate(row.output),
        pack_for(inc, inv, settings).mapping,
        row.provider,
        row.model,
    )
    return {inc.local_id: block}


def run_generation(
    engine: Engine, incident_id: int, settings: Settings, factory: ClientFactory
) -> None:
    """Background task: build the pack, ask the provider, validate, store. Never raises."""
    with Session(engine) as session:
        row = session.scalars(select(Narrative).where(Narrative.incident_id == incident_id)).first()
        inc = session.get(Incident, incident_id)
        inv = session.get(Investigation, inc.investigation_id) if inc else None
        if row is None or inc is None or inv is None:
            return
        client = factory()
        row.provider, row.model, row.prompt_hash = client.provider, client.model, prompt_hash()
        try:
            result = generate_narrative(pack_for(inc, inv, settings), client)
            row.status = result.status
            row.output = result.output.model_dump() if result.output else None
            row.raw_output, row.reasons = result.raw_output, result.reasons
        except Exception as exc:  # a generation bug must degrade to the template, not to a crash
            row.status, row.output, row.reasons = (
                "unavailable",
                None,
                [f"{type(exc).__name__} while generating"],
            )
        session.commit()


@router.post("/incidents/{incident_id}/narrative", status_code=202, response_model=NarrativeOut)
def start_narrative(
    incident_id: RowId,
    request: Request,
    background: BackgroundTasks,
    session: SessionDep,
    settings: SettingsDep,
) -> NarrativeOut:
    inc = session.get(Incident, incident_id)
    if inc is None:
        raise ApiError(404, "NOT_FOUND", "No such incident.")
    factory: ClientFactory = getattr(
        request.app.state, "llm_client_factory", default_client_factory
    )
    row = session.scalars(select(Narrative).where(Narrative.incident_id == incident_id)).first()
    if row is None:
        row = Narrative(incident_id=incident_id, status="pending")
        session.add(row)
    row.status, row.output, row.raw_output, row.reasons = "pending", None, None, []
    row.created_at = utcnow()
    session.commit()
    background.add_task(run_generation, request.app.state.engine, incident_id, settings, factory)
    return view(session, inc, settings)


def _is_stale(created_at: datetime | None) -> bool:
    """A pending narrative older than two provider calls (plus slack) is not still running."""
    if created_at is None:
        return False
    limit = timedelta(seconds=2 * get_llm_settings().llm_timeout_s + 60)
    return utcnow() - created_at > limit


def view(session: Session, inc: Incident, settings: Settings) -> NarrativeOut:
    row = session.scalars(select(Narrative).where(Narrative.incident_id == inc.id)).first()
    if row is None:
        return NarrativeOut(
            status="not_requested",
            label=LABEL,
            provider=get_llm_settings().llm_provider,
            model="",
            prompt_hash="",
            reasons=[],
            output=None,
            entities={},
            created_at=None,
        )
    entities: dict[str, str] = {}
    if row.status == "validated":
        inv = session.get(Investigation, inc.investigation_id)
        if inv is not None:
            entities = pack_for(inc, inv, settings).mapping
    shown: dict[str, Any] | None = row.output if row.status == "validated" else None
    status, reasons = row.status, list(row.reasons or [])
    if status == "pending" and _is_stale(row.created_at):
        # the background task died with the API process (restart) or the provider hung: do not
        # leave the UI waiting forever; the analyst can request a new generation
        status, reasons = "unavailable", ["generation did not finish (API restarted or timed out)"]
    return NarrativeOut(
        status=status,
        label=LABEL,
        provider=row.provider,
        model=row.model,
        prompt_hash=row.prompt_hash,
        reasons=reasons,
        output=shown,
        entities=entities,
        created_at=row.created_at,
    )


@router.get("/incidents/{incident_id}/narrative", response_model=NarrativeOut)
def get_narrative(incident_id: RowId, session: SessionDep, settings: SettingsDep) -> NarrativeOut:
    inc = session.get(Incident, incident_id)
    if inc is None:
        raise ApiError(404, "NOT_FOUND", "No such incident.")
    return view(session, inc, settings)
