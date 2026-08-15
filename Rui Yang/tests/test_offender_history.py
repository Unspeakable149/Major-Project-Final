"""Unit tests for the persistent repeat-offender store (offender_history.py).

Every test gets its own SQLite file via pytest's tmp_path fixture, so these
never touch the real offender_history.db - a real risk to guard against
given that db is shared across the live dashboard and every CLI test run
this project has ever done (see the session log's "two-folder" debugging
saga for how much cross-contamination that file has already seen).
"""

import pytest

from offender_history import OffenderHistory


@pytest.fixture
def history(tmp_path):
    return OffenderHistory(db_path=str(tmp_path / "test_offenders.db"))


def test_unseen_ip_has_zero_prior_offences(history):
    assert history.get_count("1.2.3.4") == 0


def test_record_then_get_count_reflects_one_offence(history):
    history.record("1.2.3.4")
    assert history.get_count("1.2.3.4") == 1


def test_record_accumulates_across_multiple_calls(history):
    # This is the exact behaviour the whole "repeat offender" feature
    # depends on - each new upload/flow should ADD to the count, not
    # overwrite it, which is what ON CONFLICT DO UPDATE ... + is for.
    history.record("1.2.3.4")
    history.record("1.2.3.4")
    history.record("1.2.3.4")
    assert history.get_count("1.2.3.4") == 3


def test_record_with_explicit_count_adds_that_many_at_once(history):
    history.record("1.2.3.4", count=5)
    assert history.get_count("1.2.3.4") == 5
    history.record("1.2.3.4", count=2)
    assert history.get_count("1.2.3.4") == 7


def test_different_ips_tracked_independently(history):
    history.record("1.1.1.1")
    history.record("1.1.1.1")
    history.record("2.2.2.2")
    assert history.get_count("1.1.1.1") == 2
    assert history.get_count("2.2.2.2") == 1
    assert history.get_count("3.3.3.3") == 0


def test_top_offenders_orders_worst_first(history):
    history.record("low.ip", count=1)
    history.record("high.ip", count=10)
    history.record("mid.ip", count=5)

    top = history.top_offenders(limit=10)
    ips_in_order = [row["ip"] for row in top]
    assert ips_in_order == ["high.ip", "mid.ip", "low.ip"]


def test_top_offenders_respects_limit(history):
    for i in range(5):
        history.record(f"ip{i}", count=i + 1)
    top = history.top_offenders(limit=2)
    assert len(top) == 2
    # the two highest counts (5 and 4) should be the ones returned
    assert {row["offences"] for row in top} == {5, 4}


def test_top_offenders_includes_timestamps(history):
    history.record("1.2.3.4")
    top = history.top_offenders(limit=1)
    assert top[0]["first_seen"] is not None
    assert top[0]["last_seen"] is not None


def test_reset_wipes_all_history(history):
    history.record("1.2.3.4", count=10)
    history.record("5.6.7.8", count=3)
    history.reset()
    assert history.get_count("1.2.3.4") == 0
    assert history.get_count("5.6.7.8") == 0
    assert history.top_offenders() == []


def test_history_persists_across_separate_instances_of_same_file(tmp_path):
    # Simulates two separate uploads in two separate Streamlit reruns, both
    # pointing at the same on-disk db - the whole point of this being
    # persistent rather than in-memory.
    db_path = str(tmp_path / "shared.db")
    OffenderHistory(db_path=db_path).record("9.9.9.9", count=4)
    second_instance = OffenderHistory(db_path=db_path)
    assert second_instance.get_count("9.9.9.9") == 4
