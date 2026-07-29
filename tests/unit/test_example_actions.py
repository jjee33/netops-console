"""The shipped example actions must actually be definable.

Examples that do not work are worse than no examples: someone pastes one in,
gets a validation error, and concludes the feature is broken. This keeps them
honest as the validation rules tighten.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.modules.actions.service import validate_definition

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "actions.json"
ACTIONS = json.loads(EXAMPLES.read_text())


def test_the_pack_is_not_empty() -> None:
    assert len(ACTIONS) >= 5


@pytest.mark.parametrize("action", ACTIONS, ids=[a["name"] for a in ACTIONS])
def test_every_example_validates(action: dict) -> None:
    validate_definition(
        name=action["name"],
        execution_type=action["execution_type"],
        argv_template=action["argv_template"],
        param_schema=action["param_schema"],
        timeout_seconds=action["timeout_seconds"],
    )


@pytest.mark.parametrize("action", ACTIONS, ids=[a["name"] for a in ACTIONS])
def test_every_example_explains_itself(action: dict) -> None:
    """An action's description is where its real cost is stated — that a docker
    command needs a root-equivalent group, or that a unit restart needs sudoers.
    An example without one teaches the wrong habit."""
    assert action["description"].strip()


@pytest.mark.parametrize("action", ACTIONS, ids=[a["name"] for a in ACTIONS])
def test_state_changing_examples_ask_first(action: dict) -> None:
    changes_state = any(
        word in action["name"].lower() for word in ("restart", "reboot", "stop", "delete")
    )
    if changes_state:
        assert action["confirmation_required"], (
            f"{action['name']!r} changes state on a device; an accidental click "
            f"should not be enough"
        )


def test_privileged_examples_are_flagged() -> None:
    """`elevated_required` is what tells an operator they must install a sudoers
    entry themselves — this application cannot grant itself privilege."""
    for action in ACTIONS:
        if any(token == "sudo" for token in action["argv_template"]):
            assert action["elevated_required"], f"{action['name']!r} uses sudo but is not flagged"
