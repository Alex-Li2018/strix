"""STRIX_REPORT_LANGUAGE flows into the rendered system prompt.

The directive must appear exactly when the setting is resolved non-empty,
and must not leak into prompts when it is unset or blank.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.agents.prompt import render_system_prompt
from strix.config import loader


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _fresh_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("STRIX_REPORT_LANGUAGE", raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    yield
    # monkeypatch restores env + _cached on teardown.


def test_default_prompt_has_no_language_directive() -> None:
    prompt = render_system_prompt()
    assert "REPORT LANGUAGE" not in prompt


def test_report_language_env_adds_directive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "Simplified Chinese")
    monkeypatch.setattr(loader, "_cached", None)
    prompt = render_system_prompt()
    assert "REPORT LANGUAGE" in prompt
    assert "Simplified Chinese" in prompt
    # The keep-technical-content-as-is clause rides along.
    assert "CVSS vectors stay exactly as they are" in prompt


def test_blank_language_env_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "   ")
    monkeypatch.setattr(loader, "_cached", None)
    prompt = render_system_prompt()
    assert "REPORT LANGUAGE" not in prompt
