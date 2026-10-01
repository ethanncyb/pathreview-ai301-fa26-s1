"""Red-team tests for the prompt injection defense.

Issue #29 asks for a curated set of known prompt injection attacks run against
the safety layer. This module loads the corpus in
`tests/fixtures/injection_attempts/` and records what `PromptDefense` currently
does with it.

The corpus is run in three delivery shapes, because the reproduction on #29
showed that delivery, not wording, decides detection here:

- ``as-is``: the payload occupies the whole input field.
- ``prefixed``: one ``\\n`` prepended -- the shape the existing unit tests use.
- ``embedded``: the payload mid-sentence in a longer single-line prompt.

Payloads the defense does not currently catch are marked ``xfail(strict=True)``
rather than asserted as blocked, per the convention in `docs/CONTRIBUTING.md`.
They are a record of the current gap, not an endorsement of it: when a fix lands
the marker fails loudly as ``XPASS(strict)`` and must be removed, which is the
signal this suite exists to give.
"""

import json
from pathlib import Path

import pytest

from safety.prompt_defense import PromptDefense

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "injection_attempts"

# Delivery shapes. Each varies exactly one condition against "as-is".
DELIVERIES = {
    "as-is": lambda payload: payload,
    "prefixed": lambda payload: f"\n{payload}",
    "embedded": lambda payload: f"Please summarize the following: {payload}",
}

# Payload ids the defense does not detect today, by delivery shape, as observed
# on f89c06f and reported on issue #29. Three of the six INJECTION_PATTERNS are
# anchored on a literal newline, so a payload with no newline before its
# keyword reaches none of them.
#
# "prefixed" is absent from this map on purpose: a leading newline puts the
# ignore-family keyword at the start of a line, which is exactly what
# INJECTION_PATTERNS is written to catch, so those cases are expected to pass.
EXPECTED_UNDETECTED = {
    "as-is": {
        "ignore-say",
        "ignore-print",
        "ignore-print-upper",
        "nevermind",
        "screaming-stop",
        "leak-spell-check-instead",
        "leak-spell-check-instead-upper",
        "leak-print-instead",
        "leak-spell-check",
        "leak-print",
    },
    "prefixed": {
        # Keyword not at line start even with the newline.
        "nevermind",
        # Carries none of the ignore-family keywords at all.
        "screaming-stop",
    },
    "embedded": {
        "ignore-say",
        "ignore-print",
        "ignore-print-upper",
        "nevermind",
        "screaming-stop",
        "leak-spell-check-instead",
        "leak-spell-check-instead-upper",
        "leak-print-instead",
        "leak-spell-check",
        "leak-print",
    },
}


def _load_corpus() -> list[dict]:
    """Load every payload from the fixture directory.

    Returns:
        One dict per payload, carrying its id, the payload string, its
        provenance, and whether it is a positive control.
    """
    corpus: list[dict] = []
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        for entry in data["payloads"]:
            corpus.append(
                {
                    "id": entry["id"],
                    "payload": entry["payload"],
                    "note": entry["note"],
                    "source": data["source"],
                    "is_control": path.name == "positive_controls.json",
                }
            )
    return corpus


CORPUS = _load_corpus()
ATTACKS = [entry for entry in CORPUS if not entry["is_control"]]
CONTROLS = [entry for entry in CORPUS if entry["is_control"]]


def _attack_cases() -> list:
    """Build one parametrised case per attack payload per delivery shape."""
    cases = []
    for entry in ATTACKS:
        for delivery in DELIVERIES:
            marks = []
            if entry["id"] in EXPECTED_UNDETECTED[delivery]:
                marks.append(
                    pytest.mark.xfail(
                        strict=True,
                        reason=(
                            f"issue #29: {entry['id']} delivered {delivery} is not "
                            "matched by INJECTION_PATTERNS"
                        ),
                    )
                )
            cases.append(pytest.param(entry, delivery, marks=marks, id=f"{entry['id']}-{delivery}"))
    return cases


@pytest.mark.security
class TestCorpusIsBlocked:
    """Every curated attack payload should be detected, in every delivery shape."""

    @pytest.mark.parametrize("entry,delivery", _attack_cases())
    def test_attack_payload_detected(self, entry: dict, delivery: str) -> None:
        """Test that a known attack payload is flagged as an injection attempt."""
        text = DELIVERIES[delivery](entry["payload"])

        assert PromptDefense.is_injection_attempt(text) is True


@pytest.mark.security
class TestHarnessReachesTheDefense:
    """Guards against a suite that looks green because it tests nothing.

    Every assertion above is about payloads the defense may or may not catch.
    If the import, the corpus loader, or the delivery wrappers broke, those
    tests would report undetected for the wrong reason and the xfail markers
    would hide it. These two cases fail loudly instead.
    """

    @pytest.mark.parametrize("entry", CONTROLS, ids=[entry["id"] for entry in CONTROLS])
    def test_positive_control_detected(self, entry: dict) -> None:
        """Test that a payload the patterns target is flagged in every shape."""
        for delivery, build in DELIVERIES.items():
            assert (
                PromptDefense.is_injection_attempt(build(entry["payload"])) is True
            ), f"positive control {entry['id']} not detected when {delivery}"

    def test_corpus_loaded(self) -> None:
        """Test that the corpus is non-empty and every entry has a payload."""
        assert ATTACKS, f"no attack payloads loaded from {FIXTURE_DIR}"
        assert CONTROLS, f"no positive controls loaded from {FIXTURE_DIR}"
        assert all(entry["payload"] for entry in CORPUS)


@pytest.mark.security
class TestSanitizeAgainstCorpus:
    """What `sanitize` does to the corpus, recorded rather than asserted."""

    @pytest.mark.parametrize("entry", ATTACKS, ids=[entry["id"] for entry in ATTACKS])
    def test_sanitize_is_idempotent(self, entry: dict) -> None:
        """Test that sanitizing an already-sanitized payload changes nothing."""
        once = PromptDefense.sanitize(entry["payload"])

        assert PromptDefense.sanitize(once) == once

    def test_sanitize_strips_template_delimiters_from_control(self) -> None:
        """Test that sanitize removes the delimiters it targets."""
        payload = "{{ config.items() }}"

        assert "{{" not in PromptDefense.sanitize(payload)
        assert "}}" not in PromptDefense.sanitize(payload)
