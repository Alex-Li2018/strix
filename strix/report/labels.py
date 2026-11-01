"""Localized label tables for generated report skeletons.

The ``STRIX_REPORT_LANGUAGE`` directive tells the model which language to
write prose in, but the artifact writers render the surrounding skeleton —
headings, field labels, severity names — in hardcoded English. This module
maps that skeleton to the report language. The one curated table is
Simplified Chinese; any other language keeps the English skeleton while the
prose still follows the language directive.

Severity *values* translate only in the rendered markdown. CSV, JSON, and
SARIF artifacts keep their machine-readable English values.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from strix.config import load_settings


@dataclass(frozen=True)
class ReportLabels:
    """Skeleton strings for one report language; the defaults are English."""

    report_title: str = "Security Penetration Test Report"
    generated: str = "Generated"
    executive_summary: str = "Executive Summary"
    methodology: str = "Methodology"
    technical_analysis: str = "Technical Analysis"
    recommendations: str = "Recommendations"
    summary_panel_title: str = "Penetration test summary"

    untitled_vulnerability: str = "Untitled Vulnerability"
    vuln_id: str = "ID"
    severity: str = "Severity"
    found: str = "Found"
    unknown_value: str = "unknown"
    no_description: str = "No description provided."

    target: str = "Target"
    package: str = "Package"
    ecosystem: str = "Ecosystem"
    installed_version: str = "Installed Version"
    fixed_version: str = "Fixed Version"
    introduced_by: str = "Introduced By"
    dependency_chain: str = "Dependency Chain"
    endpoint: str = "Endpoint"
    method: str = "Method"
    cve: str = "CVE"
    cwe: str = "CWE"
    cvss: str = "CVSS"
    advisory_cvss: str = "Advisory CVSS"
    contextual_cvss_vector: str = "Contextual CVSS Vector"
    confidence: str = "Confidence"
    fix_effort: str = "Fix Effort"

    description: str = "Description"
    evidence: str = "Evidence"
    impact: str = "Impact"
    counterevidence: str = "Counterevidence"
    confidence_rationale: str = "Confidence Rationale"
    severity_change_conditions: str = "What Would Change This Severity"
    contextual_cvss: str = "Contextual CVSS"
    proof_of_concept: str = "Proof of Concept"
    code_analysis: str = "Code Analysis"
    location: str = "Location {n}"
    # Rendered directly after a filename; the leading space lives in the
    # template so full-width punctuation needs no extra gap.
    lines_span: str = " (lines {start}-{end})"
    line_single: str = " (line {start})"
    suggested_fix: str = "Suggested Fix"
    remediation: str = "Remediation"
    fix_verification: str = "Fix Verification"
    assumptions: str = "Assumptions"
    update_history: str = "Update History"

    unknown_author: str = "an agent"
    update_line: str = "**{timestamp}** — {author} updated: {fields}"
    dropped_superseded: str = "Dropped as superseded: {fields}"
    previous_value: str = "Previous {label}: {value}"
    reason_line: str = "Reason: {reason}"

    # Rendered severity names by lowercase input; missing keys fall back to
    # the raw value uppercased, so the English table stays empty.
    severity_names: dict[str, str] = field(default_factory=dict)

    def severity_name(self, raw: str) -> str:
        """Render *raw* severity for the markdown report."""
        text = str(raw).strip()
        return self.severity_names.get(text.lower(), text.upper())


_ZH_LABELS = ReportLabels(
    report_title="安全渗透测试报告",
    generated="生成时间",
    executive_summary="执行摘要",
    methodology="测试方法",
    technical_analysis="技术分析",
    recommendations="安全建议",
    summary_panel_title="渗透测试摘要",
    untitled_vulnerability="未命名漏洞",
    vuln_id="漏洞编号",
    severity="严重程度",
    found="发现时间",
    unknown_value="未知",
    no_description="未提供描述。",
    target="目标",
    package="软件包",
    ecosystem="软件生态",
    installed_version="已安装版本",
    fixed_version="修复版本",
    introduced_by="引入来源",
    dependency_chain="依赖链",
    endpoint="端点",
    method="请求方法",
    advisory_cvss="公告 CVSS",
    contextual_cvss_vector="上下文 CVSS 向量",
    confidence="置信度",
    fix_effort="修复工作量",
    description="漏洞描述",
    evidence="证据",
    impact="影响",
    counterevidence="反证分析",
    confidence_rationale="置信度依据",
    severity_change_conditions="严重程度变更条件",
    contextual_cvss="上下文 CVSS",
    proof_of_concept="概念验证",
    code_analysis="代码分析",
    location="位置 {n}",
    lines_span="（第 {start}-{end} 行）",
    line_single="（第 {start} 行）",
    suggested_fix="修复建议",
    remediation="修复方案",
    fix_verification="修复验证",
    assumptions="假设条件",
    update_history="更新历史",
    unknown_author="未知代理",
    update_line="**{timestamp}** — {author} 更新：{fields}",
    dropped_superseded="已因被取代而移除：{fields}",
    previous_value="原{label}: {value}",
    reason_line="原因：{reason}",
    severity_names={
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息",
    },
)

# Generic Chinese markers default to Simplified (the common convention for a
# bare "Chinese"/"zh"); explicit Traditional variants are excluded because only
# the Simplified table exists.
_SIMPLIFIED_MARKERS = ("zh", "chinese", "中文", "简体", "汉语", "华语")
_TRADITIONAL_MARKERS = ("hant", "traditional", "繁", "zh-tw", "zh-hk", "zh-mo")


def _is_simplified_chinese(language: str | None) -> bool:
    text = (language or "").strip().lower()
    if not text:
        return False
    if any(marker in text for marker in _TRADITIONAL_MARKERS):
        return False
    return any(marker in text for marker in _SIMPLIFIED_MARKERS)


def get_labels() -> ReportLabels:
    """Skeleton labels for the configured report language."""
    if _is_simplified_chinese(load_settings().report.language):
        return _ZH_LABELS
    return ReportLabels()


__all__ = ["ReportLabels", "get_labels"]
