#!/usr/bin/env python3
"""Report rendering -- Markdown + JSON (WS-7, SPEC §9.1).

The section order is a design decision, not a style preference. A user must be
able to stop reading at any point and still have acted correctly:

  1. Verdict            -- one line
  2. Quick wins         -- high impact, simple fix, diffs inline
  3. Findings by priority
  4. Not fixable in IaC -- CLI command / console steps (§6.4)
  5. Compliance coverage -- only with --compliance (Phase 2; seam only)
  6. Degradation & scan integrity

Two rules this module exists to enforce
---------------------------------------

**A scan that found nothing because it could not read the files must never look
like a scan that found nothing because the files were clean.** So degradation is
not a footnote: it is stamped on the verdict line itself (section 1, the one line
everybody reads) *and* expanded in section 6. ``render_markdown`` on a degraded
scan cannot produce output that reads clean -- see ``tests/test_report.py``.

**A finding you cannot patch is not a finding you hide.** Non-IaC findings are
ranked with everything else in section 3 and given their `aws` command or console
steps in section 4.

remediationComplexity, and why quick wins would otherwise be empty
-----------------------------------------------------------------
``Finding.remediationComplexity`` defaults to ``moderate`` and ``is_quick_win``
requires ``simple``, so a merge with no LLM enrichment yields **zero** quick wins
-- the section people actually act on would be permanently empty on any scan that
did not pay for an Opus pass. That is a bug in the pipeline, not a reason to
lower the bar.

The fix is ``derive_complexity``: if the *deterministic* fix catalog (WS-5)
generated a patch for this finding and **every change in it is additive**
(``type == "add"`` -- a new attribute, a new block, a new companion resource;
nothing existing overridden, nothing removed), then the fix is mechanically
simple by construction. The diff is already written, it applies cleanly, and
Checkov re-passes on it. There is no judgment call, because nothing the author
wrote is being second-guessed. That is what ``simple`` means.

It is a *floor*, never a ceiling, and never a downgrade:
  - only promotes ``moderate`` (the default) -> ``simple``;
  - never touches a finding an LLM explicitly rated ``complex``;
  - records ``remediationComplexitySource: "fix-catalog"`` so the promotion is
    auditable and an enrichment pass can overrule it.

A patch that *modifies* an existing value (``replace_block``, an attribute the
author already set) is NOT promoted: overriding a deliberate choice is exactly
the judgment call ``simple`` promises there isn't one of.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from classify import classify_findings, is_non_iac  # noqa: E402
from compliance import (  # noqa: E402
    ControlMap,
    attach_compliance,
    build_control_coverage,
)
from findings import UNMAPPED, is_quick_win, priority_score  # noqa: E402

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational", UNMAPPED)

# The one tier that carries line numbers for Terraform (parse_iac.py §1.1).
# Anything below it means no line provenance, which means no SARIF and no patches.
# Kept as a public constant: other Terraform code (and tests) key on it.
FULL_PARSE_TIER = "tfparse"

# Phase 3 (WS-14): the same "full tier" idea, per format. Each format has one
# parser tier that carries line numbers; a fall-back below it is a DEGRADED scan
# (no line numbers -> no SARIF, no patches), exactly as for Terraform. The parse
# result's own ``degraded`` / ``lineProvenance`` flags are the source of truth;
# this map is only the fallback inference when those flags are absent (e.g. a
# hand-built parse_result in a unit test).
FULL_PARSE_TIERS = {
    "terraform": {"tfparse"},
    "cloudformation": {"cfn-lint"},
    "kubernetes": {"ruamel"},
    "docker-compose": {"ruamel"},
    "docker_compose": {"ruamel"},
    "compose": {"ruamel"},
}

# Where each format's line numbers come from — the "fix it, then re-scan" hint on
# a degraded parse.
PARSER_INSTALL_HINT = {
    "terraform": "pip install tfparse",
    "cloudformation": "pip install cfn-lint",
    "kubernetes": "pip install ruamel.yaml",
    "docker-compose": "pip install ruamel.yaml",
    "docker_compose": "pip install ruamel.yaml",
    "compose": "pip install ruamel.yaml",
}

# Formats for which Checkov's community edition has no (or effectively no) rule
# coverage. A zero-finding scan on one of these is NOT a clean bill of health —
# it is a coverage gap — and the report must say so rather than read as "clean".
# Measured against checkov 3.2.500: there is no docker-compose framework; the
# `dockerfile` framework only reads files literally named `Dockerfile`, and the
# `secrets` framework does not fire on a compose file's `environment:` values.
# So a Compose scan finds nothing deterministically; its value is the LLM layer.
THIN_CHECKOV_COVERAGE = {
    "docker-compose": (
        "Checkov's community edition has no Docker Compose ruleset (no compose "
        "framework; the `dockerfile` framework only reads files named `Dockerfile`; "
        "the `secrets` framework does not fire on compose `environment:` values). "
        "The deterministic layer therefore assessed nothing here — findings for "
        "Compose come from the LLM layer, which this build does not run."
    ),
}
THIN_CHECKOV_COVERAGE["docker_compose"] = THIN_CHECKOV_COVERAGE["docker-compose"]
THIN_CHECKOV_COVERAGE["compose"] = THIN_CHECKOV_COVERAGE["docker-compose"]

# Formats with no automated fixer in this build (WS-14: K8s/Compose are
# findings-only). A finding on one of these is remediated by editing the manifest
# by hand, guided by the rule's guideline — there is no diff, and the report must
# not imply an automated Terraform patch exists.
FINDINGS_ONLY_FORMATS = {"kubernetes", "docker-compose", "docker_compose", "compose"}


# ---------------------------------------------------------------------------
# remediationComplexity derivation (see the module docstring)
# ---------------------------------------------------------------------------


def _changes_for_finding(finding_id: str, patches: Sequence[Any]) -> List[Any]:
    out: List[Any] = []
    for patch in patches:
        if finding_id in (patch.findingIds or []):
            for change in patch.changes:
                if not change.findingIds or finding_id in change.findingIds:
                    out.append(change)
    return out


def is_mechanically_simple(changes: Sequence[Any]) -> bool:
    """Every change is additive: nothing the author wrote is overridden or removed."""
    if not changes:
        return False
    return all(getattr(c, "type", None) == "add" for c in changes)


def derive_complexity(
    findings: Sequence[Dict[str, Any]], patches: Sequence[Any]
) -> List[Dict[str, Any]]:
    """Promote moderate -> simple where the deterministic catalog wrote an additive patch.

    Rescores priorityScore/isQuickWin afterwards, because complexity is an input
    to both (findings.py ``priority_score``).
    """
    for finding in findings:
        current = finding.get("remediationComplexity") or "moderate"
        if current != "moderate":
            continue  # an explicit LLM judgment; not ours to overrule
        changes = _changes_for_finding(finding.get("id") or "", patches)
        if not is_mechanically_simple(changes):
            continue
        finding["remediationComplexity"] = "simple"
        finding["remediationComplexitySource"] = "fix-catalog"
        finding["priorityScore"] = priority_score(
            finding.get("severity") or UNMAPPED,
            finding.get("exploitability") or "moderate",
            "simple",
            affects_critical_resource=bool(finding.get("affectsCriticalResource")),
            is_public_facing=bool(finding.get("isPublicFacing")),
            verification=finding.get("verification") or "static-only",
            threat_score=finding.get("threatScore"),
        )
        finding["isQuickWin"] = is_quick_win(finding.get("severity") or UNMAPPED, "simple")
    return list(findings)


# ---------------------------------------------------------------------------
# Degradation (the correctness requirement)
# ---------------------------------------------------------------------------


def assess_degradation(
    checkov_result: Optional[Dict[str, Any]], parse_result: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Did this scan actually get to read the files?

    Two independent ways it did not:
      * Checkov absent/failed -- ``run_checkov.py`` sets ``degraded``. The whole
        deterministic layer is missing; whatever is left cannot be trusted as
        coverage.
      * The parser fell back off tfparse -- no line numbers, therefore no SARIF
        and no patches. Degraded, not graceful.
    """
    checkov_result = checkov_result or {}
    parse_result = parse_result or {}

    reasons: List[Dict[str, str]] = []

    if checkov_result.get("degraded"):
        reasons.append(
            {
                "source": "checkov",
                "reason": checkov_result.get("degradationReason")
                or "Checkov did not run.",
                "impact": (
                    "The deterministic rule layer did not run. Coverage is unknown -- "
                    "this scan is NOT evidence that your infrastructure is clean."
                ),
                "fix": checkov_result.get("installHint") or "install checkov",
            }
        )

    # Parser degradation is format-aware (WS-14). Every parse tier now reports its
    # own ``degraded`` / ``lineProvenance`` honestly, so trust those; fall back to
    # the per-format full-tier map only when a caller hand-built a parse_result
    # without them (older unit tests pass ``{"parseTier": "hcl2", "degraded": True}``).
    fmt = (parse_result.get("format") or "terraform").lower()
    tier = parse_result.get("parseTier")
    parse_error = parse_result.get("error")
    line_provenance = parse_result.get("lineProvenance")
    if line_provenance is None:
        full_tiers = FULL_PARSE_TIERS.get(fmt, {FULL_PARSE_TIER})
        line_provenance = bool(tier) and tier in full_tiers
    # A parser that returned an error (e.g. "no manifests found", or a zero-resource
    # parse that could not read the tree) is a loud degradation, not a clean scan.
    parser_degraded = (
        bool(parse_error)
        or bool(parse_result.get("degraded"))
        or (bool(tier) and not line_provenance)
    )

    if parser_degraded:
        reasons.append(
            {
                "source": "parser",
                "reason": parse_result.get("degradationReason")
                or (str(parse_error) if parse_error else None)
                or (
                    "Parser fell back to the %s tier; the line-number parser was "
                    "unavailable." % tier
                    if tier
                    else "Parser degraded."
                ),
                "impact": (
                    "No line numbers. That means no SARIF output and no remediation "
                    "diffs -- every finding below is location-approximate and cannot "
                    "be patched automatically."
                ),
                "fix": PARSER_INSTALL_HINT.get(fmt, "pip install tfparse"),
            }
        )

    return {
        "degraded": bool(reasons),
        "reasons": reasons,
        "parseTier": tier,
        "checkovDegraded": bool(checkov_result.get("degraded")),
        "parserDegraded": parser_degraded,
        "patchesPossible": bool(line_provenance) if tier else False,
    }


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def _severity_counts(findings: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        sev = finding.get("severity") or UNMAPPED
        counts[sev] = counts.get(sev, 0) + 1
    return {s: counts[s] for s in SEVERITY_ORDER if s in counts}


def verdict_line(report: Dict[str, Any]) -> str:
    """Section 1. One line. It carries the degradation flag, because this is the
    line everyone reads and a degraded scan must never read like a clean one."""
    findings = report["findings"]
    counts = report["summary"]["bySeverity"]
    quick = len(report["quickWins"])
    degraded = report["degradation"]["degraded"]

    if not findings:
        if degraded:
            return (
                "DEGRADED SCAN -- 0 findings, but the scan could not read your "
                "infrastructure. This is NOT a clean result. See "
                "'Degradation & scan integrity' below."
            )
        if report.get("coverageNote"):
            # Zero findings on a format Checkov cannot cover. NOT a clean result:
            # nothing scanned it. Say so on the one line everyone reads.
            return (
                "0 findings -- but Checkov has no ruleset for this format, so nothing "
                "assessed it. This is a COVERAGE GAP, not a clean result. See "
                "'Degradation & scan integrity' below."
            )
        return "0 findings. Clean against the rules that ran."

    parts = ", ".join("%d %s" % (n, sev) for sev, n in counts.items())
    line = "%d finding%s: %s. %d quick win%s." % (
        len(findings),
        "" if len(findings) == 1 else "s",
        parts,
        quick,
        "" if quick == 1 else "s",
    )
    if degraded:
        line = "DEGRADED SCAN -- " + line + " Coverage is incomplete; see below."
    return line


def build_report(
    merge_result: Dict[str, Any],
    *,
    checkov_result: Optional[Dict[str, Any]] = None,
    parse_result: Optional[Dict[str, Any]] = None,
    patches: Optional[Sequence[Any]] = None,
    file_patches: Optional[Sequence[Any]] = None,
    root: str = ".",
    compliance: Optional[str] = None,
    compliance_coverage: Optional[Dict[str, Any]] = None,
    fix_catalog_rule_ids: Optional[Sequence[str]] = None,
    iac_format: Optional[str] = None,
) -> Dict[str, Any]:
    """The JSON report. ``render_markdown`` renders exactly this, nothing more.

    ``iac_format`` (WS-14) names the IaC format scanned (``terraform`` by
    default/None). It controls three things and nothing else, so Terraform and
    CloudFormation output is byte-for-byte unchanged when it is ``None``:
      * findings-only formats (K8s/Compose) render guidance, not a phantom diff;
      * a format Checkov cannot cover (Compose) gets an honest coverage caveat
        instead of a "clean" verdict on zero findings;
      * each finding is stamped with ``iacFormat`` so the renderer can tell.
    """
    patches = list(patches or [])
    findings = [dict(f) for f in merge_result.get("findings") or []]
    fmt = (iac_format or "").lower() or None
    if fmt:
        for finding in findings:
            finding.setdefault("iacFormat", fmt)

    # 1. complexity floor from the deterministic catalog, then
    # 2. classification -- a rule that produced a real patch on THIS tree is iac,
    #    whatever the pattern catalog's Prowler-era keywords think (classify.py).
    derive_complexity(findings, patches)
    patched_rule_ids = {r for p in patches for r in (p.ruleIds or [])}
    if fix_catalog_rule_ids:
        patched_rule_ids |= set(fix_catalog_rule_ids)
    classify_findings(findings, sorted(patched_rule_ids))

    diffs = diffs_by_finding(patches)
    for finding in findings:
        finding["diff"] = diffs.get(finding["id"])

    findings.sort(
        key=lambda f: (-int(f.get("priorityScore") or 0), f.get("ruleId") or "", f["id"])
    )

    degradation = assess_degradation(checkov_result, parse_result)
    quick_wins = [f for f in findings if f.get("isQuickWin")]
    non_iac = [f for f in findings if is_non_iac(f)]

    # Coverage caveat: a zero-finding scan on a format Checkov cannot cover
    # (Compose) must not read as clean. Only fires when the deterministic layer
    # genuinely produced nothing AND was not itself degraded (that is a different,
    # louder failure already handled above).
    coverage_note = None
    if (
        fmt in THIN_CHECKOV_COVERAGE
        and not findings
        and not degradation["checkovDegraded"]
    ):
        coverage_note = THIN_CHECKOV_COVERAGE[fmt]

    summary = dict(merge_result.get("summary") or {})
    summary.update(
        {
            "total": len(findings),
            "bySeverity": _severity_counts(findings),
            "quickWins": len(quick_wins),
            "nonIaC": len(non_iac),
            "withDiff": sum(1 for f in findings if f.get("diff")),
        }
    )

    report: Dict[str, Any] = {
        "root": root,
        "iacFormat": fmt,
        "coverageNote": coverage_note,
        "summary": summary,
        "degradation": degradation,
        "findings": findings,
        "quickWins": quick_wins,
        "nonIaC": non_iac,
        "exposureChains": merge_result.get("exposureChains") or [],
        "suppressionLog": merge_result.get("suppressionLog") or [],
        "injectionAttempts": merge_result.get("injectionAttempts") or [],
        "filePatches": [fp.to_dict() for fp in (file_patches or [])],
        # Section 5. Filled by WS-10 from a checked-in, human-reviewed
        # control-map.json when a caller passes ``compliance_coverage``. It is
        # never model-generated: a hallucinated control ID is risk #3 (SPEC
        # §14.3), so this stays None unless real, data-backed coverage is given.
        "compliance": compliance_coverage,
        "complianceRequested": compliance,
    }
    report["verdict"] = verdict_line(report)
    return report


def diffs_by_finding(patches: Sequence[Any]) -> Dict[str, str]:
    """finding id -> the per-resource diff to show it with.

    Per-resource diffs are for DISPLAY. The applicable set is ``filePatches``
    (``generate_file_patches``) -- per-resource diffs for the same file are each
    cut against the pristine file and do not stack.
    """
    out: Dict[str, str] = {}
    for patch in patches:
        for fid in patch.findingIds or []:
            if fid not in out and patch.diff:
                out[fid] = patch.diff
    return out


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _location_line(finding: Dict[str, Any]) -> str:
    loc = finding.get("location") or {}
    file = loc.get("file") or "?"
    start = loc.get("startLine")
    # file:line, clickable in a terminal. No line -> say so, do not print ":0".
    where = "%s:%s" % (file, start) if start else "%s (no line -- degraded parse)" % file
    return "`%s` — `%s`" % (where, loc.get("resourceAddress") or "?")


def _fence(diff: str) -> List[str]:
    return ["```diff", diff.rstrip("\n"), "```"]


def _finding_block(finding: Dict[str, Any], index: int, *, with_diff: bool = True) -> List[str]:
    sev = finding.get("severity") or UNMAPPED
    score = finding.get("priorityScore") or 0
    score_txt = "unranked" if sev == UNMAPPED else "score %d" % score
    lines = [
        "#### %d. [%s] %s — %s" % (index, sev, finding.get("ruleId") or "?", finding.get("title") or ""),
        "",
        "%s · %s" % (_location_line(finding), score_txt),
        "",
    ]

    if finding.get("businessImpact"):
        lines.append("- **Impact:** %s" % finding["businessImpact"])
    if finding.get("attackScenario"):
        lines.append("- **Attack scenario:** %s" % finding["attackScenario"])
    if not finding.get("businessImpact") and not finding.get("attackScenario"):
        lines.append(
            "- **Impact:** not enriched. Impact and attack-scenario analysis come from "
            "the Opus pass; this run is deterministic-only."
        )
    if finding.get("remediationApproach"):
        lines.append("- **Fix:** %s" % finding["remediationApproach"])
    if finding.get("inExposureChain"):
        lines.append("- **In an exposure chain** — see `exposureChains` in the JSON report.")
    if len(finding.get("source") or []) > 1:
        lines.append("- Corroborated by %s." % " + ".join(finding["source"]))
    if finding.get("severityAdjustedFrom"):
        lines.append(
            "- Severity adjusted from `%s`: %s"
            % (finding["severityAdjustedFrom"], finding.get("severityAdjustmentReason") or "")
        )

    if is_non_iac(finding):
        lines.append(
            "- **Not fixable in IaC** (`%s`, %s). No diff. Steps are in *Not fixable in IaC* below."
            % (finding.get("remediationType"), finding.get("nonIaCCategory") or "")
        )
    elif with_diff and finding.get("diff"):
        lines.append("")
        lines.extend(_fence(finding["diff"]))
    elif with_diff and (finding.get("iacFormat") or "terraform") in FINDINGS_ONLY_FORMATS:
        # WS-14: K8s/Compose are findings-only in this build — there is no
        # automated fixer, so we do NOT imply one. Point at the file to edit and
        # the rule's own guideline; never fabricate a diff.
        loc = finding.get("location") or {}
        line = (
            "- **Findings-only for %s.** No automated fix in this build — remediate "
            "by editing `%s` (`%s`) directly."
            % (
                finding.get("iacFormat"),
                loc.get("file") or "?",
                loc.get("resourceAddress") or "?",
            )
        )
        if finding.get("guideline"):
            line += " Guideline: %s" % finding["guideline"]
        lines.append(line)
    elif with_diff:
        lines.append(
            "- No deterministic fix for this rule. It needs the remediation engineer "
            "(`--fix` / the LLM pass), or a human."
        )

    lines.append("")
    return lines


_DEGRADED_EMPTY = (
    "**Nothing to show — but this scan was DEGRADED and could not read your "
    "infrastructure.** Do not read this as clean. See *Degradation & scan integrity*."
)


def _render_quick_wins(report: Dict[str, Any]) -> List[str]:
    lines = ["## Quick wins", ""]
    quick = report["quickWins"]
    if not quick:
        # An empty section that explains itself. Silence here reads as "nothing to
        # do", which is a different claim entirely.
        high = [f for f in report["findings"] if f.get("severity") in ("critical", "high")]
        if report["degradation"]["degraded"] and not high:
            lines += [_DEGRADED_EMPTY, ""]
        elif not high:
            lines += ["No critical or high findings, so nothing qualifies. Work the list below.", ""]
        else:
            lines += [
                "None. There are %d critical/high findings, but none of them has a "
                "mechanical fix — every one needs a judgment call (policy scoping, an "
                "access-affecting change, or a value only you can choose). They are the "
                "top of *Findings by priority*; read them there." % len(high),
                "",
            ]
        return lines

    lines += [
        "%d high-impact findings with a mechanical, additive fix. The diffs below apply "
        "cleanly and Checkov re-passes on them." % len(quick),
        "",
    ]
    for i, finding in enumerate(quick, 1):
        lines += _finding_block(finding, i)
    return lines


def _render_findings(report: Dict[str, Any]) -> List[str]:
    lines = ["## Findings by priority", ""]
    findings = report["findings"]
    if not findings:
        lines += [_DEGRADED_EMPTY if report["degradation"]["degraded"] else "None.", ""]
        return lines
    unmapped = sum(1 for f in findings if (f.get("severity") or UNMAPPED) == UNMAPPED)
    if unmapped:
        lines += [
            "%d finding%s ha%s no severity in the checked-in map and therefore no score. "
            "They are listed last as **unranked** — that is not the same as low risk."
            % (unmapped, "" if unmapped == 1 else "s", "s" if unmapped == 1 else "ve"),
            "",
        ]
    for i, finding in enumerate(findings, 1):
        lines += _finding_block(finding, i)
    return lines


def _render_non_iac(report: Dict[str, Any]) -> List[str]:
    lines = ["## Not fixable in IaC", ""]
    non_iac = report["nonIaC"]
    if not non_iac:
        lines += [
            _DEGRADED_EMPTY
            if report["degradation"]["degraded"]
            else "None. Every finding above is addressable in Terraform.",
            "",
        ]
        return lines

    lines += [
        "%d finding%s can't be fixed by editing a `.tf` file — account-level settings, "
        "console-only toggles, or changes that need a human decision. No diff; here is "
        "what to actually run."
        % (len(non_iac), "" if len(non_iac) == 1 else "s"),
        "",
    ]
    for i, finding in enumerate(non_iac, 1):
        loc = finding.get("location") or {}
        lines += [
            "#### %d. [%s] %s — %s"
            % (i, finding.get("severity"), finding.get("ruleId"), finding.get("title") or ""),
            "",
            "%s · route: **%s** (`%s`)"
            % (
                _location_line(finding),
                finding.get("remediationType"),
                finding.get("nonIaCCategory") or "",
            ),
            "",
            "- **Why not IaC:** %s" % (finding.get("classificationReason") or "—"),
        ]
        steps = finding.get("remediationSteps") or {}
        if steps.get("command"):
            lines += ["", "```bash", steps["command"], "```"]
        if steps.get("steps"):
            lines.append("")
            for step in steps["steps"]:
                lines.append("1. %s" % step)
        if steps.get("note"):
            lines += ["", "> %s" % steps["note"]]
        if not steps:
            lines.append(
                "- No checked-in command for this pattern. We do not invent `aws` "
                "commands — consult the AWS docs for this control."
            )
        lines.append("")
    return lines


def _render_compliance(report: Dict[str, Any]) -> List[str]:
    """Section 5. Only rendered with --compliance. The Phase-2 (WS-10) seam."""
    if not report.get("complianceRequested"):
        return []
    lines = ["## Compliance coverage", ""]
    if not report.get("compliance"):
        lines += [
            "**Not available in this build.** Control mapping (`--compliance %s`) lands in "
            "Phase 2 (WS-10), backed by a checked-in, human-reviewed `control-map.json`."
            % report["complianceRequested"],
            "",
            "This section is deliberately empty rather than approximate. A fabricated "
            "control ID inside a FedRAMP package is the single worst thing this tool "
            "could produce, so it maps nothing until the data exists (SPEC §14.3).",
            "",
        ]
        return lines
    cov = report["compliance"]

    # The one sentence that ships in EVERY compliance report, non-optional. It is
    # the mitigation for "clean scan = compliant" (SPEC §7.2 / §14.6). It appears
    # first, before any satisfied/violated detail, so it cannot be missed.
    lines += [
        "> **%s**" % cov["mandatoryCaveat"],
        ">",
        "> A clean scan here is NOT a clean %s posture. This tool assesses only what "
        "Terraform can express. Controls that are procedural or otherwise invisible to "
        "IaC are listed below, unevaluated." % cov.get("baseline", "800-53"),
        "",
        "_Baseline: %s. %d of %d controls in this baseline are assessable from IaC._"
        % (
            cov.get("baselineSource", "800-53"),
            cov.get("assessableControlCount", 0),
            cov.get("baselineControlCount", 0),
        ),
        "",
    ]

    violated = cov.get("violated") or []
    satisfied = cov.get("satisfied") or []
    not_assessable = cov.get("notAssessable") or {}
    unmapped_rules = cov.get("unmappedRules") or []

    lines += ["### Controls with violations (%d)" % len(violated), ""]
    if violated:
        for v in violated:
            lines.append(
                "- **%s** (%s family) — %d finding%s: %s"
                % (
                    v["control"],
                    v["family"],
                    len(v["findingIds"]),
                    "" if len(v["findingIds"]) == 1 else "s",
                    ", ".join(v["ruleIds"]),
                )
            )
    else:
        lines.append("- None mapped from this scan's findings.")
    lines.append("")

    lines += ["### Controls with passing evidence (%d)" % len(satisfied), ""]
    if satisfied:
        lines.append(
            "> Passing checks are evidence toward these controls, not proof a control "
            "is fully met — a control can have process facets IaC cannot see."
        )
        lines.append("")
        for s in satisfied:
            lines.append(
                "- **%s** (%s family) — %s"
                % (s["control"], s["family"], ", ".join(s["ruleIds"]))
            )
    else:
        lines.append("- No passing checks mapped to a control in this scan.")
    lines.append("")

    lines += [
        "### NOT ASSESSABLE FROM IaC (%d)" % not_assessable.get("count", 0),
        "",
        not_assessable.get("note", ""),
        "",
    ]
    controls = not_assessable.get("controls") or []
    if controls:
        lines.append("`%s`" % "`, `".join(controls))
        lines.append("")

    if unmapped_rules:
        lines += [
            "### Findings on rules with no control mapping (%d)" % len(unmapped_rules),
            "",
            "These findings fired on rules that control-map.json does not map to a "
            "control. They are reported as `unmapped`, never guessed (SPEC §5.3): "
            "`%s`" % "`, `".join(unmapped_rules),
            "",
        ]

    return lines


def _render_degradation(report: Dict[str, Any]) -> List[str]:
    """Section 6. Unmissable when it fires."""
    degradation = report["degradation"]
    suppressions = report.get("suppressionLog") or []
    injections = report.get("injectionAttempts") or []
    coverage_note = report.get("coverageNote")

    if (
        not degradation["degraded"]
        and not suppressions
        and not injections
        and not coverage_note
    ):
        return []

    lines = ["## Degradation & scan integrity", ""]

    if coverage_note:
        lines += [
            "> # ⚠️ COVERAGE GAP — this format has no deterministic ruleset",
            ">",
            "> **0 findings here does NOT mean clean.** %s" % coverage_note,
            "",
        ]

    if degradation["degraded"]:
        lines += [
            "> # ⚠️ THIS WAS A DEGRADED SCAN",
            ">",
            "> **The results above are incomplete. Absence of findings here is NOT "
            "evidence that your infrastructure is clean — it is evidence that this "
            "scan could not fully read it.**",
            "",
        ]
        for reason in degradation["reasons"]:
            lines += [
                "### %s" % reason["source"],
                "",
                "- **What happened:** %s" % reason["reason"],
                "- **What it cost you:** %s" % reason["impact"],
                "- **Fix it:** `%s`, then re-scan." % reason["fix"],
                "",
            ]

    if suppressions:
        lines += [
            "### Suppression requests (%d)" % len(suppressions),
            "",
            "The enrichment model tried to talk the scan out of %d finding%s. It was "
            "refused — the deterministic layer cannot be argued with — but you should "
            "know it happened. Untrusted IaC content can attempt exactly this "
            "(SPEC §11)."
            % (len(suppressions), "" if len(suppressions) == 1 else "s"),
            "",
        ]
        for entry in suppressions:
            lines.append(
                "- `%s` — %s"
                % (
                    entry.get("findingId") or entry.get("ruleId") or "?",
                    entry.get("reason") or entry.get("request") or "(no reason given)",
                )
            )
        lines.append("")

    if injections:
        lines += [
            "### Prompt-injection attempts (%d)" % len(injections),
            "",
            "Structural injection attempts were detected in the enrichment payloads and "
            "discarded.",
            "",
        ]
        for entry in injections:
            lines.append("- `%s` — %s" % (entry.get("findingId") or "?", entry.get("reason") or ""))
        lines.append("")

    return lines


def render_markdown(report: Dict[str, Any]) -> str:
    """§9.1's order, exactly. Stop reading anywhere and you have still acted correctly."""
    lines: List[str] = ["# IaC security scan", ""]

    # 1. Verdict
    lines += ["## Verdict", "", "**%s**" % report["verdict"], ""]

    # 2. Quick wins
    lines += _render_quick_wins(report)

    # 3. Findings by priority
    lines += _render_findings(report)

    # 4. Not fixable in IaC
    lines += _render_non_iac(report)

    # 5. Compliance coverage (only with --compliance)
    lines += _render_compliance(report)

    # 6. Degradation & scan integrity
    lines += _render_degradation(report)

    return "\n".join(lines).rstrip() + "\n"


SECTION_ORDER = (
    "## Verdict",
    "## Quick wins",
    "## Findings by priority",
    "## Not fixable in IaC",
    "## Compliance coverage",
    "## Degradation & scan integrity",
)


# ---------------------------------------------------------------------------
# End-to-end scan (what the /iac-scan command and the tests drive)
# ---------------------------------------------------------------------------


def _compose_file(root: str) -> str:
    """Locate the Compose file. ``parse_docker_compose`` takes a FILE, not a dir."""
    if os.path.isfile(root):
        return root
    import glob as _glob

    for name in ("docker-compose.yaml", "docker-compose.yml", "compose.yaml", "compose.yml"):
        hit = _glob.glob(os.path.join(root, name))
        if hit:
            return hit[0]
    # No compose file: hand the directory to the parser so it returns a loud error
    # dict (its own degradation), rather than guessing a filename.
    return root


def detect_iac_format(root: str) -> Optional[str]:
    """Best-effort format detection from a directory's contents.

    The whole point is defense against the worst failure this tool has: scanning a
    CloudFormation repo with the Terraform framework finds nothing and reports a
    false-clean. If we can tell what the files ARE, we should not require the user
    to also tell us. Returns None only when nothing recognizable is present (the
    caller then falls back to terraform and the parser's own degradation fires).

    Deliberately conservative: file presence + a light content sniff, no full
    parse. `.tf` wins outright; among YAML we distinguish CFN
    (AWSTemplateFormatVersion / a top-level Resources map) from k8s
    (apiVersion + kind) from compose (a compose filename / a top-level services:).
    """
    import glob as _glob

    if os.path.isfile(root):
        low = root.lower()
        if low.endswith(".tf"):
            return "terraform"
        if os.path.basename(low).startswith(("docker-compose", "compose")):
            return "docker-compose"
        # fall through to content sniff below on the single file
        yaml_files = [root]
    else:
        if _glob.glob(os.path.join(root, "*.tf")) or _glob.glob(
            os.path.join(root, "**", "*.tf"), recursive=True
        ):
            return "terraform"
        for name in ("docker-compose.yaml", "docker-compose.yml", "compose.yaml", "compose.yml"):
            if _glob.glob(os.path.join(root, name)):
                return "docker-compose"
        yaml_files = [
            p
            for pat in ("*.yaml", "*.yml", "*.json", "*.template")
            for p in _glob.glob(os.path.join(root, pat))
            + _glob.glob(os.path.join(root, "**", pat), recursive=True)
        ]

    cfn = k8s = False
    for path in yaml_files[:50]:  # bounded sniff; do not read a whole repo
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                head = fh.read(4096)
        except OSError:
            continue
        if "AWSTemplateFormatVersion" in head or "\nResources:" in head or head.startswith("Resources:"):
            cfn = True
        if "apiVersion:" in head and "kind:" in head:
            k8s = True
    if cfn and not k8s:
        return "cloudformation"
    if k8s and not cfn:
        return "kubernetes"
    if cfn and k8s:
        # Ambiguous: prefer CFN (the format with a fixer) but this is a real
        # ambiguity the caller may want to resolve explicitly.
        return "cloudformation"
    return None


def parse_for_format(iac_format: str, root: str) -> Dict[str, Any]:
    """Route to the right parser for the format (WS-14). Terraform is unchanged."""
    from parse_iac import (
        parse_cloudformation,
        parse_docker_compose,
        parse_kubernetes,
        parse_terraform,
    )

    fmt = (iac_format or "terraform").lower()
    if fmt == "terraform":
        return parse_terraform(root)
    if fmt == "cloudformation":
        return parse_cloudformation(root)
    if fmt == "kubernetes":
        return parse_kubernetes(root)
    if fmt in ("docker-compose", "docker_compose", "compose"):
        return parse_docker_compose(_compose_file(root))
    raise ValueError("unsupported IaC format: %r" % iac_format)


def scan(
    root: str,
    *,
    iac_format: Optional[str] = None,
    compliance: Optional[str] = None,
    use_fmt: bool = True,
) -> Dict[str, Any]:
    """Run the whole deterministic pipeline over ``root`` and build the report.

    No LLM. Enrichment (WS-6) is layered on by passing ``enrichments=`` to
    ``merge`` and calling ``build_report`` directly.

    ``iac_format`` (WS-14) selects the parser and the Checkov framework set.
    When it is ``None`` the format is detected from the directory (the CLI
    passes ``None`` unless ``--iac-format`` is given). Terraform and
    CloudFormation have deterministic fixers wired in here; K8s and Compose are
    findings-only, and the report renders them as such (no phantom diffs) —
    see ``build_report``.
    """
    from merge_findings import merge
    from run_checkov import frameworks_for_format, run_checkov

    import contextlib

    # Explicit format wins. Otherwise detect from the directory's contents, and
    # fall back to terraform only when nothing is recognizable -- the parser's
    # own degradation then fires. This is the guard against scanning a
    # CloudFormation repo with the Terraform framework and reporting a
    # false-clean.
    detected = detect_iac_format(root) if not iac_format else None
    fmt = (iac_format or detected or "terraform").lower()

    checkov_result = run_checkov(root, frameworks_for_format(fmt))
    # The parsers print progress to stdout; keep it off OUR stdout so a
    # `--format json`/`sarif` CLI run emits a clean machine document. Progress
    # still shows, on stderr.
    with contextlib.redirect_stdout(sys.stderr):
        parse_result = parse_for_format(fmt, root)
    # A parser error dict carries no `format`; stamp it so the degradation
    # notice names the right install hint (cfn-lint for CFN, not tfparse).
    parse_result.setdefault("format", fmt)
    merge_result = merge(checkov_result.get("findings") or [], parse_result=parse_result)

    patches: List[Any] = []
    file_patches: List[Any] = []
    fix_catalog_rule_ids: List[str] = []
    # Only with line provenance: no line numbers -> no patching regardless. Do
    # not fabricate a diff against lines we do not have; the degradation notice
    # says exactly this.
    full_tier = parse_result.get("parseTier") in FULL_PARSE_TIERS.get(fmt, set())
    if fmt == "terraform" and full_tier:
        from patch_terraform import (
            FixCatalog,
            generate_file_patches,
            generate_security_patches,
            load_terraform_resources,
        )

        catalog = FixCatalog.load()
        resources, _ = load_terraform_resources(root)
        patches = generate_security_patches(
            root, merge_result["findings"], catalog, resources, use_fmt=use_fmt
        )
        file_patches = generate_file_patches(root, patches, resources, use_fmt=use_fmt)
        fix_catalog_rule_ids = list(catalog.rule_ids)
    elif fmt == "cloudformation" and full_tier and not parse_result.get("degraded"):
        import patch_cloudformation as pc

        cfn_catalog = pc.CFNFixCatalog.load()
        cfn_resources, _ = pc.load_cloudformation_resources(root)
        patches = pc.generate_security_patches(
            root, merge_result["findings"], cfn_catalog, cfn_resources
        )
        file_patches = pc.generate_file_patches(root, patches, cfn_resources)
        fix_catalog_rule_ids = list(cfn_catalog.rule_ids)

    compliance_coverage = None
    if compliance:
        # Control coverage is joined from the checked-in, human-reviewed
        # control-map.json only. No control ID is ever generated at runtime
        # (SPEC §5.3 / §14.3). A missing map is a loud failure, not a silent
        # empty section -- but if the data file is absent we still ship the
        # gap message rather than a fabricated one.
        control_map = ControlMap.load()
        attach_compliance(merge_result.get("findings") or [], control_map)
        compliance_coverage = build_control_coverage(
            merge_result.get("findings") or [],
            checkov_result.get("passedChecks") or [],
            control_map,
            baseline=compliance,
        )

    return build_report(
        merge_result,
        checkov_result=checkov_result,
        parse_result=parse_result,
        patches=patches,
        file_patches=file_patches,
        root=root,
        compliance=compliance,
        compliance_coverage=compliance_coverage,
        fix_catalog_rule_ids=fix_catalog_rule_ids,
        iac_format=fmt,
    )


def main(argv: Optional[List[str]] = None) -> int:
    """CLI. Exit codes are SPEC §9.2 and they are the product:

        0 -- clean at or above the --severity floor
        1 -- findings at or above the floor
        2 -- scan error (a degraded scan is an error, never a silent success)

    so that ``iac-scan --severity high || exit 1`` is a working CI gate.
    """
    import argparse

    from emit_sarif import (
        DEFAULT_FLOOR,
        EXIT_ERROR,
        SEVERITY_FLOORS,
        DegradedScanError,
        emit_sarif,
        findings_at_or_above,
        gate_exit_code,
    )

    parser = argparse.ArgumentParser(description="Render an IaC security scan report")
    parser.add_argument("root", help="directory to scan")
    parser.add_argument(
        "--iac-format",
        dest="iac_format",
        choices=("terraform", "cloudformation", "kubernetes", "docker-compose"),
        default=None,
        help="IaC format to scan (default: detect from the directory; terraform "
        "when nothing is recognizable). Selects the parser and the Checkov "
        "framework set. K8s/Compose are findings-only (no auto-fix).",
    )
    parser.add_argument("--format", choices=("markdown", "json", "sarif"), default="markdown")
    parser.add_argument("--out", help="write to this file instead of stdout")
    parser.add_argument(
        "--severity",
        choices=SEVERITY_FLOORS,
        default=DEFAULT_FLOOR,
        help="reporting floor and CI gate threshold (default: %s)" % DEFAULT_FLOOR,
    )
    parser.add_argument(
        "--compliance",
        metavar="BASELINE",
        help="render the compliance section (Phase 2 -- currently a declared gap)",
    )
    parser.add_argument("--no-fmt", action="store_true", help="skip terraform fmt on patches")
    args = parser.parse_args(argv)

    try:
        report = scan(
            args.root,
            iac_format=args.iac_format,
            compliance=args.compliance,
            use_fmt=not args.no_fmt,
        )
    except Exception as exc:  # noqa: BLE001 -- any scan failure is exit 2, never 0
        sys.stderr.write("scan error: %s\n" % exc)
        return EXIT_ERROR

    if args.format == "sarif":
        try:
            text = json.dumps(emit_sarif(report, root=args.root), indent=2)
        except DegradedScanError as exc:
            # No line numbers means nothing honest to emit. Say so; emit nothing.
            sys.stderr.write("DEGRADED SCAN — no SARIF emitted.\n%s\n" % exc)
            return EXIT_ERROR
    elif args.format == "json":
        text = json.dumps(report, indent=2, default=str)
    else:
        text = render_markdown(report)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")

    exit_code = gate_exit_code(report, args.severity)

    # The floor decides the gate, so state what it caught -- and, separately, what it
    # could not rank. An unmapped finding never trips the gate (it has no rank), which
    # would make it invisible to CI if we did not say this out loud.
    hits = findings_at_or_above(report["findings"], args.severity)
    unmapped = sum(1 for f in report["findings"] if (f.get("severity") or UNMAPPED) == UNMAPPED)
    if hits:
        sys.stderr.write(
            "%d finding%s at or above the '%s' floor.\n"
            % (len(hits), "" if len(hits) == 1 else "s", args.severity)
        )
    if unmapped:
        sys.stderr.write(
            "%d finding%s ha%s no severity in data/rule-severity.json and therefore no rank; "
            "%s NOT evaluated against the gate.\n"
            % (
                unmapped,
                "" if unmapped == 1 else "s",
                "s" if unmapped == 1 else "ve",
                "it is" if unmapped == 1 else "they are",
            )
        )

    return exit_code


__all__ = [
    "SECTION_ORDER",
    "FULL_PARSE_TIER",
    "FULL_PARSE_TIERS",
    "THIN_CHECKOV_COVERAGE",
    "FINDINGS_ONLY_FORMATS",
    "assess_degradation",
    "build_report",
    "derive_complexity",
    "diffs_by_finding",
    "is_mechanically_simple",
    "parse_for_format",
    "render_markdown",
    "scan",
    "verdict_line",
]


if __name__ == "__main__":
    sys.exit(main())
