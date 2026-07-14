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
from findings import UNMAPPED, is_quick_win, priority_score  # noqa: E402

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational", UNMAPPED)

# The one tier that carries line numbers (parse_iac.py §1.1). Anything below it
# means no line provenance, which means no SARIF and no patches.
FULL_PARSE_TIER = "tfparse"


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
                    "this scan is NOT evidence that your Terraform is clean."
                ),
                "fix": checkov_result.get("installHint") or "install checkov",
            }
        )

    tier = parse_result.get("parseTier")
    if tier and tier != FULL_PARSE_TIER:
        reasons.append(
            {
                "source": "parser",
                "reason": parse_result.get("degradationReason")
                or ("Parser fell back to the %s tier; tfparse was unavailable." % tier),
                "impact": (
                    "No line numbers. That means no SARIF output and no remediation "
                    "diffs -- every finding below is location-approximate and cannot "
                    "be patched automatically."
                ),
                "fix": "pip install tfparse",
            }
        )
    elif parse_result.get("degraded") and not tier:
        reasons.append(
            {
                "source": "parser",
                "reason": parse_result.get("degradationReason") or "Parser degraded.",
                "impact": "Parse coverage is incomplete; findings may be missing.",
                "fix": "pip install tfparse",
            }
        )

    return {
        "degraded": bool(reasons),
        "reasons": reasons,
        "parseTier": tier,
        "checkovDegraded": bool(checkov_result.get("degraded")),
        "parserDegraded": bool(tier and tier != FULL_PARSE_TIER)
        or bool(parse_result.get("degraded")),
        "patchesPossible": tier == FULL_PARSE_TIER if tier else False,
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
    fix_catalog_rule_ids: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """The JSON report. ``render_markdown`` renders exactly this, nothing more."""
    patches = list(patches or [])
    findings = [dict(f) for f in merge_result.get("findings") or []]

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
        "summary": summary,
        "degradation": degradation,
        "findings": findings,
        "quickWins": quick_wins,
        "nonIaC": non_iac,
        "exposureChains": merge_result.get("exposureChains") or [],
        "suppressionLog": merge_result.get("suppressionLog") or [],
        "injectionAttempts": merge_result.get("injectionAttempts") or [],
        "filePatches": [fp.to_dict() for fp in (file_patches or [])],
        # Section 5 seam. Phase 2 (WS-10) fills this from a checked-in, human-
        # reviewed control-map.json. Until then it is None and the section says
        # so -- it never guesses a control ID (SPEC §14.3).
        "compliance": None,
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
    lines += ["_(rendered from control-map.json)_", ""]  # pragma: no cover - WS-10
    return lines


def _render_degradation(report: Dict[str, Any]) -> List[str]:
    """Section 6. Unmissable when it fires."""
    degradation = report["degradation"]
    suppressions = report.get("suppressionLog") or []
    injections = report.get("injectionAttempts") or []

    if not degradation["degraded"] and not suppressions and not injections:
        return []

    lines = ["## Degradation & scan integrity", ""]

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


def scan(root: str, *, compliance: Optional[str] = None, use_fmt: bool = True) -> Dict[str, Any]:
    """Run the whole deterministic pipeline over ``root`` and build the report.

    No LLM. Enrichment (WS-6) is layered on by passing ``enrichments=`` to
    ``merge`` and calling ``build_report`` directly.
    """
    from merge_findings import merge
    from parse_iac import parse_terraform
    from patch_terraform import (
        FixCatalog,
        generate_file_patches,
        generate_security_patches,
        load_terraform_resources,
    )
    from run_checkov import run_checkov

    checkov_result = run_checkov(root)
    parse_result = parse_terraform(root)
    merge_result = merge(checkov_result.get("findings") or [], parse_result=parse_result)

    patches: List[Any] = []
    file_patches: List[Any] = []
    # No line provenance -> no patching. Do not fabricate a diff against lines we
    # do not have; the degradation notice says exactly this.
    if parse_result.get("parseTier") == FULL_PARSE_TIER:
        catalog = FixCatalog.load()
        resources, _ = load_terraform_resources(root)
        patches = generate_security_patches(
            root, merge_result["findings"], catalog, resources, use_fmt=use_fmt
        )
        file_patches = generate_file_patches(root, patches, resources, use_fmt=use_fmt)

    return build_report(
        merge_result,
        checkov_result=checkov_result,
        parse_result=parse_result,
        patches=patches,
        file_patches=file_patches,
        root=root,
        compliance=compliance,
    )


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Render an IaC security scan report")
    parser.add_argument("root", help="directory to scan")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--out", help="write to this file instead of stdout")
    parser.add_argument(
        "--compliance",
        metavar="BASELINE",
        help="render the compliance section (Phase 2 -- currently a declared gap)",
    )
    parser.add_argument("--no-fmt", action="store_true", help="skip terraform fmt on patches")
    args = parser.parse_args(argv)

    report = scan(args.root, compliance=args.compliance, use_fmt=not args.no_fmt)
    text = (
        json.dumps(report, indent=2, default=str)
        if args.format == "json"
        else render_markdown(report)
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")

    # A degraded scan is never a silent success (§9.2 reserves 2 for scan error).
    return 2 if report["degradation"]["degraded"] else 0


__all__ = [
    "SECTION_ORDER",
    "FULL_PARSE_TIER",
    "assess_degradation",
    "build_report",
    "derive_complexity",
    "diffs_by_finding",
    "is_mechanically_simple",
    "render_markdown",
    "scan",
    "verdict_line",
]


if __name__ == "__main__":
    sys.exit(main())
