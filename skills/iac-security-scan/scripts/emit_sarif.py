#!/usr/bin/env python3
"""SARIF 2.1.0 emitter + the CI severity gate (WS-9, SPEC §9.2).

Ported from infrabot's ``src/reporting/sarif.ts`` (375 lines) -- which was already a
complete, correct SARIF 2.1.0 emitter (rules, ``security-severity``, ``precision``
from exploitability, level mapping) with **one fatal flaw**:

    // sarif.ts:308 -- createLocation()
    physicalLocation: { artifactLocation: { uri: finding.resourceArn } }

An ARN is not a file URI. GitHub Code Scanning takes ``artifactLocation.uri`` as a
repo-relative path, fails to resolve ``arn:aws:s3:::my-bucket`` to any file in the
checkout, and drops the result on the floor. The emitter was, for CI purposes, dead.

**The fix** (``create_location`` below): a repo-relative file URI plus
``region.startLine``/``region.endLine``. That is the whole change, and it is what
turns a dead emitter into one that annotates a PR diff inline, on the right lines.

It is only possible because of WS-1. SARIF needs real line numbers; infrabot's
findings had **no file or line provenance at all** (they were ARN-centric, from a
live-account scan). Ours carry ``location.file`` / ``startLine`` / ``endLine`` on
every finding, from tfparse's ``__tfmeta``, at 100% provenance on the corpus.

Which leads to the rule this module will not bend on:

    **A degraded scan must not emit SARIF that looks complete.**

If ``parseTier != "tfparse"`` there are no line numbers. The honest options are to
emit nothing, or to emit locations that all point at line 1 of a file we half-read --
green checkmarks and inline annotations on arbitrary lines, from a scan that could not
read the infrastructure. The second is worse than no SARIF at all, so ``emit_sarif``
raises ``DegradedScanError`` and the CLI exits 2 (scan error), loudly. There is no
``--force`` for this.

security-severity
-----------------
GitHub ranks alerts by the numeric string ``properties["security-severity"]`` on the
*rule*, bucketing: >= 9.0 critical, >= 7.0 high, >= 4.0 medium, > 0.0 low. Our source
of truth for severity is ``data/rule-severity.json`` (checked-in, human-reviewed --
never model-generated), and the mapping below lands each seeded severity in its
intended GitHub bucket.

An ``unmapped`` rule -- one with no checked-in seed -- gets **no** ``security-severity``
at all. Not 5.0, not 0.0. A number here is a ranking claim, and we do not have one to
make; inventing a middle value is the exact failure mode ``rule-severity.json``'s
governance exists to prevent. It still appears as a result (a finding you cannot rank
is not a finding you hide) at level ``note``, tagged ``unmapped-severity``, and its
message says so in words.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from findings import UNMAPPED  # noqa: E402

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

TOOL_NAME = "iac-security-scan"
TOOL_VERSION = "0.1.0"
TOOL_INFO_URI = "https://github.com/0-to-1-Labs/iac-security-scan"

# The tier that carries line numbers. Same constant report.py gates patching on.
FULL_PARSE_TIER = "tfparse"

# The uriBaseId every artifactLocation is relative to: the scanned root.
SRCROOT = "SRCROOT"


# ---------------------------------------------------------------------------
# Severity mapping (sarif.ts:340-374, with the unmapped sentinel added)
# ---------------------------------------------------------------------------

# sarif.ts:342 -- severityToLevel
SEVERITY_TO_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
    # No seed => no ranking claim. Visible, but never dressed up as a graded alert.
    UNMAPPED: "note",
}

# sarif.ts:363 -- severityToSecurityScore. GitHub's buckets: >=9.0 critical,
# >=7.0 high, >=4.0 medium, >0.0 low. UNMAPPED is deliberately ABSENT from this
# map -- see the module docstring. Do not add it.
SEVERITY_TO_SECURITY_SEVERITY: Dict[str, str] = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "3.0",
    "informational": "1.0",
}

# sarif.ts:206 -- precision from exploitability.
EXPLOITABILITY_TO_PRECISION: Dict[str, str] = {
    "trivial": "very-high",
    "moderate": "high",
    "complex": "medium",
    "theoretical": "low",
}


def severity_to_level(severity: Optional[str]) -> str:
    return SEVERITY_TO_LEVEL.get(severity or UNMAPPED, "none")


def severity_to_security_severity(severity: Optional[str]) -> Optional[str]:
    """Numeric string GitHub ranks on. ``None`` for unmapped -- omit the property."""
    return SEVERITY_TO_SECURITY_SEVERITY.get(severity or UNMAPPED)


def precision_from_exploitability(exploitability: Optional[str]) -> str:
    return EXPLOITABILITY_TO_PRECISION.get(exploitability or "", "medium")


class DegradedScanError(RuntimeError):
    """SARIF was requested for a scan with no line provenance.

    Raised rather than emitting locations that point at line 1. See the module
    docstring -- this is the one thing this module refuses to do.
    """


# ---------------------------------------------------------------------------
# The fix: locations (was sarif.ts:305-333, createLocation)
# ---------------------------------------------------------------------------


def _file_uri(path: str) -> str:
    """Repo-relative, forward-slashed, percent-encoded. Never absolute, never an ARN."""
    rel = path.replace(os.sep, "/").lstrip("/")
    return urllib.parse.quote(rel)


def create_location(finding: Dict[str, Any]) -> Dict[str, Any]:
    """A SARIF location from a finding's ``location`` block.

    This is the WS-9 edit. infrabot wrote::

        uri: finding.resourceArn      # sarif.ts:308

    which GitHub cannot resolve to a file, so the annotation never lands. We write a
    repo-relative file URI plus a ``region``, which is what makes the finding show up
    as an inline comment on the exact resource block in the PR diff.

    ``region`` is emitted only when we actually have a start line. A finding without
    one keeps a file-level location -- honest and still useful -- rather than a
    fabricated ``startLine: 1``.

    ARN / account / region survive as ``logicalLocations`` (they are ``None`` on every
    static scan, and populated only under ``--live``): the physical location is the
    file, the logical location is the cloud resource. That is the §5 schema inversion
    expressed in SARIF.
    """
    loc = finding.get("location") or {}
    file = loc.get("file")
    if not file:
        raise ValueError(
            "finding %s has no location.file; it should never have been emitted "
            "(findings.py Location makes it required)" % finding.get("id")
        )

    physical: Dict[str, Any] = {
        "artifactLocation": {"uri": _file_uri(file), "uriBaseId": SRCROOT},
    }

    start = loc.get("startLine")
    if isinstance(start, int) and start > 0:
        end = loc.get("endLine")
        region: Dict[str, Any] = {"startLine": start}
        if isinstance(end, int) and end >= start:
            region["endLine"] = end
        physical["region"] = region

    logical: List[Dict[str, Any]] = []
    if loc.get("resourceAddress"):
        logical.append(
            {
                "name": loc["resourceAddress"],
                "kind": "resource",
                "fullyQualifiedName": finding.get("resourceArn") or loc["resourceAddress"],
            }
        )
    if finding.get("region"):
        logical.append({"name": finding["region"], "kind": "region"})
    if finding.get("accountId"):
        logical.append({"name": finding["accountId"], "kind": "account"})

    location: Dict[str, Any] = {"physicalLocation": physical}
    if logical:
        location["logicalLocations"] = logical
    return location


# ---------------------------------------------------------------------------
# Rules (sarif.ts:196-262)
# ---------------------------------------------------------------------------


def _help_markdown(finding: Dict[str, Any]) -> str:
    sev = finding.get("severity") or UNMAPPED
    loc = finding.get("location") or {}
    sections = [
        "## %s\n" % (finding.get("title") or finding.get("ruleId") or "Finding"),
        "**Severity:** %s\n" % sev.upper(),
        "**Service:** %s\n" % (loc.get("service") or "—"),
        "**Exploitability:** %s\n" % (finding.get("exploitability") or "—"),
        "**Remediation complexity:** %s\n" % (finding.get("remediationComplexity") or "—"),
    ]
    if sev == UNMAPPED:
        sections.append(
            "\n> No baseline severity is seeded for this rule in `data/rule-severity.json`, "
            "so it is **unranked** — that is not the same as low risk. Add a reviewed entry "
            "to rank it.\n"
        )
    if finding.get("description"):
        sections.append("\n### Description\n%s\n" % finding["description"])
    if finding.get("businessImpact"):
        sections.append("\n### Business impact\n%s\n" % finding["businessImpact"])
    if finding.get("attackScenario"):
        sections.append("\n### Attack scenario\n%s\n" % finding["attackScenario"])
    if finding.get("remediationApproach"):
        sections.append("\n### Remediation\n%s\n" % finding["remediationApproach"])
    compliance = finding.get("compliance") or {}
    controls = list(compliance.get("nist_800_53") or []) + list(compliance.get("cis_aws") or [])
    if controls:
        sections.append("\n### Compliance\n%s\n" % ", ".join(controls))
    return "".join(sections)


def create_rule(finding: Dict[str, Any]) -> Dict[str, Any]:
    """A SARIF reportingDescriptor for the rule this finding fired."""
    rule_id = finding.get("ruleId") or "UNKNOWN"
    sev = finding.get("severity") or UNMAPPED
    loc = finding.get("location") or {}

    tags = ["security", "iac", "terraform"]
    if loc.get("service"):
        tags.append(loc["service"])
    tags.append(sev)
    if sev == UNMAPPED:
        tags.append("unmapped-severity")
    if finding.get("isQuickWin"):
        tags.append("quick-win")
    compliance = finding.get("compliance") or {}
    if compliance.get("nist_800_53"):
        tags.append("nist-800-53")
    if compliance.get("cis_aws"):
        tags.append("cis-aws")

    properties: Dict[str, Any] = {
        # dict.fromkeys: dedupe, preserve order (sarif.ts:253 used a Set).
        "tags": list(dict.fromkeys(tags)),
        "precision": precision_from_exploitability(finding.get("exploitability")),
    }
    security_severity = severity_to_security_severity(sev)
    if security_severity is not None:
        properties["security-severity"] = security_severity
    else:
        # Say why the number is missing, rather than leaving a silent hole.
        properties["severityUnmapped"] = True

    title = finding.get("title") or rule_id
    rule: Dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,  # SARIF name must be opaque/identifier-ish; title goes in the description
        "shortDescription": {"text": title},
        "defaultConfiguration": {"level": severity_to_level(sev)},
        "properties": properties,
        "help": {
            "text": finding.get("remediationApproach") or title,
            "markdown": _help_markdown(finding),
        },
    }
    if finding.get("description"):
        rule["fullDescription"] = {"text": finding["description"]}
    return rule


# ---------------------------------------------------------------------------
# Results (sarif.ts:284-302)
# ---------------------------------------------------------------------------


def _result_message(finding: Dict[str, Any]) -> str:
    title = finding.get("title") or finding.get("ruleId") or "Finding"
    parts = [title]
    if finding.get("description"):
        parts.append(finding["description"])
    if (finding.get("severity") or UNMAPPED) == UNMAPPED:
        parts.append(
            "Severity is UNMAPPED: no checked-in baseline exists for this rule, so it is "
            "unranked rather than guessed."
        )
    if finding.get("remediationType") in ("cli", "console", "manual"):
        parts.append(
            "Not fixable in Terraform (%s) — see the scan report for the exact steps."
            % finding["remediationType"]
        )
    return " — ".join(parts)


def finding_to_result(finding: Dict[str, Any]) -> Dict[str, Any]:
    sev = finding.get("severity") or UNMAPPED
    properties: Dict[str, Any] = {
        "severity": sev,
        "severitySource": finding.get("severitySource") or "none",
        "exploitability": finding.get("exploitability"),
        "remediationComplexity": finding.get("remediationComplexity"),
        "priorityScore": finding.get("priorityScore") or 0,
        "isQuickWin": bool(finding.get("isQuickWin")),
        "remediationType": finding.get("remediationType"),
        "autoApplicable": bool(finding.get("autoApplicable")),
        "sources": finding.get("source") or [],
        "hasFix": bool(finding.get("diff") or finding.get("fix")),
    }
    if finding.get("severityAdjustedFrom"):
        properties["severityAdjustedFrom"] = finding["severityAdjustedFrom"]
        properties["severityAdjustmentReason"] = finding.get("severityAdjustmentReason")
    compliance = finding.get("compliance") or {}
    frameworks = []
    if compliance.get("nist_800_53"):
        frameworks.append({"framework": "nist_800_53", "controls": compliance["nist_800_53"]})
    if compliance.get("cis_aws"):
        frameworks.append({"framework": "cis_aws", "controls": compliance["cis_aws"]})
    if frameworks:
        properties["compliance"] = frameworks

    result: Dict[str, Any] = {
        "ruleId": finding.get("ruleId") or "UNKNOWN",
        "level": severity_to_level(sev),
        "message": {"text": _result_message(finding)},
        "locations": [create_location(finding)],
        "properties": properties,
    }
    # Stable across runs (findings.py generate_finding_id), which is what lets GitHub
    # track an alert across pushes instead of re-opening it every commit.
    if finding.get("id"):
        result["partialFingerprints"] = {"iacSecurityScanFindingId/v1": finding["id"]}
    return result


# ---------------------------------------------------------------------------
# The log
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _root_uri(root: str) -> str:
    absolute = os.path.abspath(root)
    return "file://" + urllib.parse.quote(absolute.replace(os.sep, "/")) + "/"


def emit_sarif(
    report: Dict[str, Any],
    *,
    root: Optional[str] = None,
    tool_version: str = TOOL_VERSION,
    started_at: Optional[str] = None,
    ended_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 log from a ``report.py`` report dict.

    Raises ``DegradedScanError`` when the scan has no line provenance -- SARIF whose
    locations are all invented is worse than no SARIF, because it looks complete.
    """
    degradation = report.get("degradation") or {}
    tier = degradation.get("parseTier")
    if tier != FULL_PARSE_TIER:
        raise DegradedScanError(
            "Refusing to emit SARIF: the parser ran at tier %r, not %r, so this scan has "
            "NO line numbers. Every location would point at line 1 of a file we only "
            "half-read, and GitHub would render that as a confident, precise, wrong "
            "annotation. Fix the parse (`pip install tfparse`) and re-scan, or use "
            "--format markdown/json, which state the degradation plainly."
            % (tier or "unknown", FULL_PARSE_TIER)
        )
    if degradation.get("checkovDegraded"):
        raise DegradedScanError(
            "Refusing to emit SARIF: Checkov did not run, so the deterministic rule layer "
            "is missing entirely. A near-empty SARIF file uploaded to code scanning reads "
            "as 'clean' — it is not. Install checkov and re-scan."
        )

    root = root or report.get("root") or "."
    findings = list(report.get("findings") or [])

    rules: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        rule_id = finding.get("ruleId") or "UNKNOWN"
        if rule_id not in rules:
            rules[rule_id] = create_rule(finding)

    rule_index = {rule_id: i for i, rule_id in enumerate(rules)}
    results = []
    for finding in findings:
        result = finding_to_result(finding)
        result["ruleIndex"] = rule_index[result["ruleId"]]
        results.append(result)

    timestamp = started_at or _now()
    summary = report.get("summary") or {}

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": tool_version,
                        "informationUri": TOOL_INFO_URI,
                        "rules": list(rules.values()),
                    }
                },
                "originalUriBaseIds": {SRCROOT: {"uri": _root_uri(root)}},
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": timestamp,
                        "endTimeUtc": ended_at or timestamp,
                        "workingDirectory": {"uri": _root_uri(root)},
                    }
                ],
                "properties": {
                    "parseTier": tier,
                    "degraded": False,
                    "totalFindings": len(findings),
                    "bySeverity": summary.get("bySeverity") or {},
                    "unmappedSeverity": sum(
                        1 for f in findings if (f.get("severity") or UNMAPPED) == UNMAPPED
                    ),
                },
            }
        ],
    }


def write_sarif(sarif: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
        fh.write("\n")


# ---------------------------------------------------------------------------
# The CI gate (SPEC §9.2)
#
#   0 -- clean at/above the --severity floor
#   1 -- findings at/above the floor
#   2 -- scan error (including: degraded, i.e. we could not honestly tell you)
#
# so that `iac-scan --severity high || exit 1` is a real gate.
# ---------------------------------------------------------------------------

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

# Most severe first. "informational" is not a valid floor -- a floor of
# informational is just "everything", which is what no floor means anyway.
SEVERITY_FLOORS = ("critical", "high", "medium", "low")
_RANK = {sev: i for i, sev in enumerate(("critical", "high", "medium", "low", "informational"))}

DEFAULT_FLOOR = "medium"


def meets_floor(severity: Optional[str], floor: str) -> bool:
    """Is this severity at or above the floor?

    ``unmapped`` is **not** at or above any floor, and that is deliberate. It has no
    rank; treating it as passing the floor would fail builds on a data gap, and
    treating it as a specific severity would be the invented middle value the whole
    severity-governance rule exists to forbid. The CLI reports the unmapped count
    separately, on stderr, so the gap is visible rather than silently swallowed.
    """
    if severity not in _RANK:
        return False
    if floor not in _RANK:
        raise ValueError("unknown severity floor: %r" % floor)
    return _RANK[severity] <= _RANK[floor]


def findings_at_or_above(findings: Sequence[Dict[str, Any]], floor: str) -> List[Dict[str, Any]]:
    return [f for f in findings if meets_floor(f.get("severity"), floor)]


def gate_exit_code(report: Dict[str, Any], floor: str = DEFAULT_FLOOR) -> int:
    """The CI exit code for this report."""
    if (report.get("degradation") or {}).get("degraded"):
        # We could not read the infrastructure. "Clean" is not a claim we can make,
        # and neither is "dirty". That is a scan error, and CI must stop.
        return EXIT_ERROR
    hits = findings_at_or_above(report.get("findings") or [], floor)
    return EXIT_FINDINGS if hits else EXIT_CLEAN


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Emit SARIF 2.1.0 from an iac-security-scan report (report.py --format json)"
    )
    parser.add_argument("report", help="report JSON path, or '-' for stdin")
    parser.add_argument("--out", help="write here instead of stdout")
    parser.add_argument("--root", help="scanned root (default: report.root)")
    parser.add_argument(
        "--severity",
        choices=SEVERITY_FLOORS,
        default=DEFAULT_FLOOR,
        help="CI gate floor (default: medium)",
    )
    args = parser.parse_args(argv)

    try:
        if args.report == "-":
            report = json.load(sys.stdin)
        else:
            with open(args.report, encoding="utf-8") as fh:
                report = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.stderr.write("error: could not read report: %s\n" % exc)
        return EXIT_ERROR

    try:
        sarif = emit_sarif(report, root=args.root)
    except DegradedScanError as exc:
        sys.stderr.write("DEGRADED SCAN — no SARIF emitted.\n%s\n" % exc)
        return EXIT_ERROR

    if args.out:
        write_sarif(sarif, args.out)
    else:
        sys.stdout.write(json.dumps(sarif, indent=2) + "\n")

    return gate_exit_code(report, args.severity)


__all__ = [
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "SEVERITY_TO_LEVEL",
    "SEVERITY_TO_SECURITY_SEVERITY",
    "SEVERITY_FLOORS",
    "DEFAULT_FLOOR",
    "EXIT_CLEAN",
    "EXIT_FINDINGS",
    "EXIT_ERROR",
    "DegradedScanError",
    "create_location",
    "create_rule",
    "emit_sarif",
    "finding_to_result",
    "findings_at_or_above",
    "gate_exit_code",
    "meets_floor",
    "precision_from_exploitability",
    "severity_to_level",
    "severity_to_security_severity",
    "write_sarif",
]


if __name__ == "__main__":
    sys.exit(main())
