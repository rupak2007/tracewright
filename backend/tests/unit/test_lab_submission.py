"""Schema tests for externally supplied runs (synthetic metadata only; see tests/lab_helpers.py)."""

import copy
from typing import Any

import pytest

pytest.importorskip("lab")

from lab.runmeta import Provenance, RunMeta
from lab.schema import parse_episode
from lab.submission import (
    check_labels_match_submission,
    check_run_flags,
    parse_submission,
    valid_run_id,
)

from tests.lab_helpers import episode_dict, valid_submission


def test_valid_submission_parses() -> None:
    sub = parse_submission(valid_submission())
    assert sub.run_id == "x001" and sub.holdout is False
    assert sub.client_ips() == {"172.20.0.101"}
    assert sub.declared_pairs() == {("attack", "SCAN")}
    assert sub.provenance.supplied_by == "test-author"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda s: s.pop("provenance"), "missing fields"),
        (lambda s: s.pop("clients"), "missing fields"),
        (lambda s: s.update(extra=1), "unknown fields"),
        (lambda s: s.update(run_id="../escape"), "invalid run_id"),
        (lambda s: s.update(run_id=""), "invalid run_id"),
        (lambda s: s.update(run_id="a/b"), "invalid run_id"),
        (lambda s: s.update(holdout="yes"), "holdout must be true or false"),
        (lambda s: s.update(start="2026-11-02T10:00:00"), "ending in 'Z'"),
        (lambda s: s.update(end="2026-11-02T09:00:00.000Z"), "end is before start"),
        (lambda s: s.update(network_config="../../etc/passwd"), "network_config"),
        (lambda s: s.update(network_config="other.yaml"), "network_config"),
        (lambda s: s.update(clients=[]), "non-empty list"),
        (lambda s: s.update(clients=[{"id": "c1"}]), "exactly 'id' and 'ip'"),
        (lambda s: s.update(clients=[{"id": "c1", "ip": "not-an-ip"}]), "does not appear"),
        (
            lambda s: s.update(
                clients=[{"id": "c1", "ip": "10.0.0.1"}, {"id": "c1", "ip": "10.0.0.2"}]
            ),
            "unique",
        ),
        (lambda s: s.update(scenarios=[]), "non-empty list"),
        (lambda s: s["scenarios"][0].update(**{"class": "NOT_A_CLASS"}), "not registered"),
        (lambda s: s["scenarios"][0].update(kind="mystery"), "not registered"),
        (lambda s: s["scenarios"][0].update(kind="hard_negative"), "not registered"),
        (lambda s: s["scenarios"][0].update(client="ghost"), "not a declared client"),
        (lambda s: s["scenarios"][0].update(surprise=1), "unknown scenario fields"),
        (lambda s: s.update(holdout=True), "only kind 'holdout'"),
        (
            lambda s: s["scenarios"][0].update(kind="holdout", **{"class": "SLOWLORIS"}),
            "require holdout: true",
        ),
    ],
)
def test_invalid_submissions_are_rejected(mutate: Any, message: str) -> None:
    raw = copy.deepcopy(valid_submission())
    mutate(raw)
    with pytest.raises(ValueError, match=message):
        parse_submission(raw)


def test_non_object_submission_rejected() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        parse_submission([])


def test_holdout_run_requires_holdout_family_scenarios() -> None:
    raw = valid_submission(holdout=True)
    raw["scenarios"] = [{"kind": "holdout", "class": "SLOWLORIS", "client": "c1"}]
    assert parse_submission(raw).holdout is True


@pytest.mark.parametrize(
    "field",
    ["supplied_by", "supplied_at", "collection_method", "tool_versions", "isolated_environment"],
)
def test_each_provenance_field_is_required(field: str) -> None:
    raw = copy.deepcopy(valid_submission())
    del raw["provenance"][field]
    with pytest.raises(ValueError, match="missing provenance fields"):
        parse_submission(raw)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"supplied_by": "  "}, "supplied_by is required"),
        ({"collection_method": ""}, "collection_method is required"),
        ({"tool_versions": {}}, "tool_versions"),
        ({"tool_versions": {"x": ""}}, "tool_versions"),
        ({"isolated_environment": False}, "isolated_environment must be true"),
        ({"contains_real_user_data": True}, "contains_real_user_data must be false"),
        ({"supplied_at": "yesterday"}, "ending in 'Z'"),
        ({"scenario_parameters": []}, "scenario_parameters"),
        ({"unknown_field": 1}, "unknown provenance fields"),
    ],
)
def test_invalid_provenance_is_rejected(change: dict[str, Any], message: str) -> None:
    raw = copy.deepcopy(valid_submission())
    raw["provenance"].update(change)
    with pytest.raises(ValueError, match=message):
        parse_submission(raw)


def test_provenance_must_be_an_object() -> None:
    with pytest.raises(ValueError, match="provenance must be an object"):
        Provenance.from_dict("trust me")


@pytest.mark.parametrize("bad", ["", ".", "..", "a b", "a/b", "x" * 65, 5, None])
def test_run_id_charset(bad: object) -> None:
    with pytest.raises(ValueError, match="invalid run_id"):
        valid_run_id(bad)


def test_labels_must_agree_with_the_submission() -> None:
    sub = parse_submission(valid_submission())
    good = [parse_episode(episode_dict())]
    assert check_labels_match_submission(sub, good) == []
    assert check_labels_match_submission(sub, []) == ["labels.jsonl has no episodes"]

    other_run = [parse_episode(episode_dict(run_id="other", n=1) | {"episode_id": "other-e1"})]
    assert any("label run_id 'other'" in p for p in check_labels_match_submission(sub, other_run))

    stranger = [parse_episode(episode_dict(actor="172.20.0.199"))]
    assert any("not a declared client" in p for p in check_labels_match_submission(sub, stranger))

    undeclared = [
        parse_episode(
            episode_dict(),
        ),
        parse_episode(episode_dict(cls="BRUTE", n=2)),
    ]
    assert any(
        "attack:BRUTE was not declared" in p for p in check_labels_match_submission(sub, undeclared)
    )

    missing = [parse_episode(episode_dict(kind="hard_negative", cls="NTP"))]
    problems = check_labels_match_submission(sub, missing)
    assert any("attack:SCAN has no labelled episode" in p for p in problems)

    late = episode_dict() | {"start": "2026-11-02T12:00:00.000Z", "end": "2026-11-02T12:01:00.000Z"}
    assert any(
        "outside the declared start/end window" in p
        for p in check_labels_match_submission(sub, [parse_episode(late)])
    )


def test_run_flags_must_match_labelled_kinds() -> None:
    attack = [parse_episode(episode_dict())]
    holdout = [parse_episode(episode_dict(kind="holdout", cls="SLOWLORIS"))]
    benign = [parse_episode(episode_dict(kind="hard_negative", cls="NTP"))]
    assert check_run_flags(False, False, attack) == []
    assert check_run_flags(True, False, holdout) == []
    assert check_run_flags(False, True, benign) == []
    assert check_run_flags(True, False, attack)  # holdout flag on an attack run
    assert check_run_flags(False, False, holdout)  # holdout labels without the flag
    assert check_run_flags(False, True, attack)  # benign flag on an attack run
    assert check_run_flags(False, False, benign)  # hard negatives only but not benign_only


def _meta(**overrides: Any) -> RunMeta:
    base: dict[str, Any] = {
        "run_id": "x001",
        "capture_sha256": "ab" * 32,
        "capture_bytes": 24,
        "start": "2026-11-02T10:00:00.000Z",
        "end": "2026-11-02T10:10:00.000Z",
        "seed": None,
        "holdout": False,
        "benign_only": False,
        "duration_s": 600.0,
        "scenarios": (),
        "network_config": "network.lab.yaml",
        "origin": "external",
        "clients": ({"id": "c1", "ip": "172.20.0.101"},),
        "provenance": valid_submission()["provenance"],
        "campaign_id": "camp-1",
    }
    base.update(overrides)
    return RunMeta(**base)


def test_run_meta_origin_rules() -> None:
    assert _meta().origin == "external"
    with pytest.raises(ValueError, match=r"missing provenance fields|provenance must be"):
        _meta(provenance=None)
    with pytest.raises(ValueError, match="must identify its clients"):
        _meta(clients=())
    with pytest.raises(ValueError, match="unknown origin"):
        _meta(origin="somewhere")
    with pytest.raises(ValueError, match="only valid for external"):
        _meta(origin="lab_runner", seed=1)
    with pytest.raises(ValueError, match="must record its seed"):
        _meta(origin="lab_runner", provenance=None, clients=(), seed=None, campaign_id=None)
    with pytest.raises(ValueError, match="'id' and 'ip'"):
        _meta(clients=({"id": "c1"},))
    assert (
        _meta(origin="lab_runner", provenance=None, clients=(), seed=3, campaign_id=None).seed == 3
    )


def test_brute_and_scan_episodes_must_declare_their_subpopulation() -> None:
    """PRD section 18 reports FTP/HTTP vs SSH BRUTE and default vs slow SCAN separately."""
    from lab.submission import check_subpopulation_params

    def ep(cls: str, params: dict[str, object]) -> Any:
        raw = episode_dict(cls=cls)
        raw["params"] = params
        return parse_episode(raw)

    assert (
        check_subpopulation_params([ep("BRUTE", {"service": "ssh"}), ep("SCAN", {"speed": "slow"})])
        == []
    )
    problems = check_subpopulation_params(
        [
            ep("BRUTE", {}),
            ep("BRUTE", {"service": "gopher"}),
            ep("SCAN", {"speed": "fast"}),
            ep("SCAN", {}),
        ]
    )
    assert len(problems) == 4 and all("reported separately" in p for p in problems)
    assert (
        check_subpopulation_params([ep("BEACON", {}), ep("DNSTUN", {})]) == []
    )  # no sub-populations


def test_external_runs_need_a_campaign_id_and_lab_runs_must_not_have_one() -> None:
    with pytest.raises(ValueError, match="campaign_id"):
        _meta(campaign_id=None)
    with pytest.raises(ValueError, match="campaign_id is only valid for external"):
        _meta(origin="lab_runner", provenance=None, clients=(), seed=3, campaign_id="c")
    raw = valid_submission()
    del raw["campaign_id"]
    with pytest.raises(ValueError, match="missing fields"):
        parse_submission(raw)
    for bad in ("", "a b", "../x", 7):
        with pytest.raises(ValueError, match="invalid run_id"):
            parse_submission({**valid_submission(), "campaign_id": bad})


def test_network_roles_reject_episodes_a_detector_could_never_see() -> None:
    """Regression for the P3 topology limit: dual-homed clients talk external-to-external."""
    from lab.submission import check_network_roles

    def ep(cls: str, actor: str, target: str) -> Any:
        raw = episode_dict(cls=cls, actor=actor)
        raw["targets"] = [target]
        return parse_episode(raw)

    def classify(address: str) -> str:
        return "internal" if address.startswith("172.20.") else "external"

    ok = [ep("EXFIL", "172.20.0.101", "172.21.0.20"), ep("BEACON", "172.20.0.101", "172.21.0.20")]
    assert check_network_roles(ok, classify) == []
    bad = [
        ep("EXFIL", "172.21.0.101", "172.21.0.20"),  # the dual-homed case
        ep("EXFIL", "172.20.0.101", "172.20.0.20"),  # internal-to-internal transfer
        ep("DNSTUN", "172.21.0.101", "172.20.0.20"),
    ]
    problems = check_network_roles(bad, classify)
    assert len(problems) == 3 and sum("EXFIL needs an external target" in p for p in problems) == 1
    assert check_network_roles([ep("SCAN", "172.21.0.101", "172.20.0.20")], classify) == []
