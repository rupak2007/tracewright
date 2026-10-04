import pytest

pytest.importorskip("lab")

from lab import run_lab


def test_parse_plan_defaults_and_params() -> None:
    item = run_lab.parse_plan("client2:cdn_browsing:30:" + '{"hosts": 5}')
    assert item == {
        "client": "client2",
        "scenario": "cdn_browsing",
        "duration_s": 30.0,
        "params": {"hosts": 5},
    }
    assert run_lab.parse_plan("client1:ntp")["duration_s"] == 60.0


@pytest.mark.parametrize(
    "bad",
    ["client9:ntp:10", "client1", "client1:not_a_scenario:10", "client1:ntp:0", "client1:ntp:5:[]"],
)
def test_parse_plan_rejects_bad_items(bad: str) -> None:
    with pytest.raises(ValueError):
        run_lab.parse_plan(bad)


def test_only_benign_scenarios_exist_in_this_milestone() -> None:
    from lab.benign.scenarios import SCENARIOS
    from lab.schema import HARD_NEGATIVE_CLASSES

    labelled = {s.cls for s in SCENARIOS.values() if s.cls}
    assert labelled <= set(HARD_NEGATIVE_CLASSES)  # no attack/holdout class has a scenario


def test_duplicate_client_in_a_plan_is_rejected_before_any_docker_call(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = run_lab.main(
        ["--run-id", "dup-test", "--plan", "client1:ntp:5", "--plan", "client1:ntp:5"]
    )
    assert code == 2 and "one scenario per run" in capsys.readouterr().err
    assert not (run_lab.DATA / "dup-test").exists()
