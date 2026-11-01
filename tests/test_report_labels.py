"""Report skeleton labels follow STRIX_REPORT_LANGUAGE.

The language directive tells the model which language to write prose in;
the artifact writers render the surrounding skeleton — headings, field
labels, severity names — themselves. These tests pin that skeleton to
Simplified Chinese when requested (the only built-in table) and to
English otherwise, while severity values stay machine-readable English
in CSV/JSON and translate only in the rendered markdown.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.config import loader
from strix.report.labels import get_labels
from strix.report.writer import (
    format_final_report,
    render_vulnerability_md,
    write_executive_report,
    write_vulnerabilities,
)


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture(autouse=True)
def _fresh_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("STRIX_REPORT_LANGUAGE", raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    yield
    # monkeypatch restores env + _cached on teardown.


def _vuln_report() -> dict[str, Any]:
    return {
        "id": "VULN-0001",
        "title": "SQL 注入",
        "severity": "critical",
        "timestamp": "2026-11-01T00:00:00+00:00",
        "target": "https://example.com",
        "description": "描述正文",
        "impact": "影响正文",
        "poc_description": "复现步骤正文",
        "poc_script_code": "```python\nprint('poc')\n```",
        "remediation_steps": "修复正文",
        "code_locations": [
            {
                "file": "app.py",
                "start_line": 3,
                "end_line": 5,
                "label": "注入点",
                "fix_before": "cursor.execute(q % x)",
                "fix_after": "cursor.execute(q, (x,))",
            },
        ],
        "update_history": [
            {
                "timestamp": "2026-11-01T01:00:00+00:00",
                "agent_name": "tester",
                "fields": ["severity"],
                "previous_severity": "high",
                "reason": "证据升级",
            },
        ],
    }


def test_vulnerability_md_renders_chinese_skeleton(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "简体中文")
    monkeypatch.setattr(loader, "_cached", None)

    md = render_vulnerability_md(_vuln_report())

    assert "# SQL 注入" in md
    assert "**漏洞编号:** VULN-0001" in md
    assert "**严重程度:** 严重" in md
    assert "**目标:** https://example.com" in md
    assert "## 漏洞描述" in md
    assert "## 影响" in md
    assert "## 概念验证" in md
    assert "## 修复方案" in md
    assert "**位置 1:** `app.py`（第 3-5 行）" in md
    assert "**修复建议:**" in md
    assert "## 更新历史" in md
    assert "更新：severity" in md
    assert "原因：证据升级" in md
    assert "原严重程度: high" in md
    # The PoC body is never translated.
    assert "print('poc')" in md
    # No English skeleton heading survives.
    assert "## Description" not in md
    assert "**Severity:**" not in md


def test_vulnerability_md_english_by_default() -> None:
    md = render_vulnerability_md(_vuln_report())

    assert "**Severity:** CRITICAL" in md
    assert "## Description" in md
    assert "**Location 1:** `app.py` (lines 3-5)" in md


def test_executive_report_renders_chinese_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "Simplified Chinese")
    monkeypatch.setattr(loader, "_cached", None)

    write_executive_report(tmp_path, "报告正文")

    md = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
    assert "# 安全渗透测试报告" in md
    assert "**生成时间:**" in md
    assert "报告正文" in md
    assert "# Security Penetration Test Report" not in md


def test_final_report_renders_chinese_section_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "zh-cn")
    monkeypatch.setattr(loader, "_cached", None)

    out = format_final_report(
        {
            "executive_summary": "摘要",
            "methodology": "方法",
            "technical_analysis": "分析",
            "recommendations": "建议",
        }
    )

    assert "# 执行摘要" in out
    assert "# 测试方法" in out
    assert "# 技术分析" in out
    assert "# 安全建议" in out
    assert "# Executive Summary" not in out
    assert get_labels().summary_panel_title == "渗透测试摘要"


@pytest.mark.parametrize(
    "language",
    ["Japanese", "繁體中文", "Traditional Chinese"],
)
def test_untabled_languages_keep_english_skeleton(
    monkeypatch: pytest.MonkeyPatch, language: str
) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", language)
    monkeypatch.setattr(loader, "_cached", None)

    out = format_final_report({"executive_summary": "x"})

    assert "# Executive Summary" in out
    assert "# 执行摘要" not in out


def test_english_skeleton_when_unset() -> None:
    out = format_final_report({"executive_summary": "x"})

    assert "# Executive Summary" in out


def test_machine_readable_artifacts_keep_english_severity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "简体中文")
    monkeypatch.setattr(loader, "_cached", None)

    report = _vuln_report()
    write_vulnerabilities(tmp_path, [report], set())

    csv_text = (tmp_path / "vulnerabilities.csv").read_text(encoding="utf-8")
    assert "CRITICAL" in csv_text
    stored = json.loads((tmp_path / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert stored[0]["severity"] == "critical"
