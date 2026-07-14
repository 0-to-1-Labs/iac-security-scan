#!/usr/bin/env python3
"""
Baseline, suppression, and PR-diff-only scoping (WS-15, Phase 4).

Three ways to run this scanner against a *real* repo over time instead of a
one-shot audit. All three are **filters over the merged finding set** plus a
scope summary that the report shows out loud -- nothing here ever *drops* a
finding silently. A finding that this module removes from the report is always
counted, and the count is rendered where a human will see it.

    1. Baseline  -- accept the pre-existing backlog so a scan reports only what
       is NEW since a checked-in snapshot. This is what makes the tool adoptable
       on a repo that starts with 200 findings.

    2. Suppression -- a per-finding, reviewed, *reasoned* acceptance. We honor
       Checkov's own native ``#checkov:skip=<ID>:<reason>`` mechanism (the reason
       lands in ``check_result.suppress_comment``) and, as a parallel escape
       hatch for LLM-only findings that Checkov never saw, an
       ``.iac-security-scan-ignore`` file keyed by finding id + reason. A
       suppression with **no reason is rejected** -- an accepted risk with no
       stated reason is not accepted, it is hidden.

    3. Diff-only -- scope the report to the files changed in this branch vs a
       base ref, so the tool is a fast PR gate instead of a whole-repo scan on
       every push. The base branch is *verified*, never assumed to be ``main``.

Reuse, not reinvention: finding identity comes from ``findings.py``
(``generate_finding_id`` -> ``sha256(ruleId:file:resourceAddress)``); the
finding shape is exactly what ``merge_findings.merge`` emits; path normalization
matches ``run_checkov.normalize_path`` so the diff join lands on the same strings
the finding locations use.

--------------------------------------------------------------------------------
Design note: id-matching and the fixed-then-reintroduced case
--------------------------------------------------------------------------------
A baseline matches on the STABLE finding id -- ``sha256(ruleId:file:address)`` --
NOT on line numbers. That is deliberate and is the whole point: reformatting a
file or shifting a resource down 40 lines must not resurface a finding a team
already consciously accepted. Adding a genuinely NEW insecure resource changes
the address (or the file), so it produces a new id and correctly surfaces.

The honest consequence, which we do not paper over: a finding that is baselined,
then *fixed*, then later *reintroduced at the same address* produces the same id
again and would be re-suppressed by a stale baseline. A stateless, checked-in
"accepted debt" file cannot by itself tell "still the old debt" from "the same
mistake, made again" -- both are byte-identical identities. There is no history
in the file to distinguish them.

The resolution is workflow, and we make it explicit rather than hide the gap:
the baseline is a living, checked-in artifact. When a finding is fixed, the team
regenerates the baseline (``--write-baseline``), which drops the now-absent
finding from it; a later reintroduction then has no baseline entry and surfaces
as new risk. ``apply_baseline`` therefore also reports ``stale`` entries --
baselined ids that did NOT appear in the current scan -- precisely so a fixed
finding is visible as "safe to prune from the baseline," which keeps the file
honest and makes the reintroduction case behave correctly on the next cycle.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Reuse: finding identity and path normalization from the modules that own them.
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from findings import generate_finding_id  # noqa: E402
from run_checkov import normalize_path  # noqa: E402


# ---------------------------------------------------------------------------
# IaC file recognition (Terraform-only MVP -- WS-1 contract)
# ---------------------------------------------------------------------------

#: Terraform source files. The MVP is Terraform-only; Phase 3 widens this, but a
#: security tool must never silently treat an unrecognized changed file as
#: "nothing to scan", so the diff-scope report always states what it skipped.
IAC_SUFFIXES: Tuple[str, ...] = (".tf", ".tf.json")


def is_iac_file(path: str) -> bool:
    """True for a Terraform source path. Matches the WS-1 parser's file set."""
    lowered = path.lower()
    return any(lowered.endswith(suffix) for suffix in IAC_SUFFIXES)


def _finding_id_of(finding: Dict[str, Any]) -> str:
    """The stable id for a finding, computed if absent.

    Every merged finding already carries ``id``; we recompute from identity as a
    defensive fallback so a hand-built finding (tests) still matches.
    """
    fid = finding.get("id")
    if fid:
        return str(fid)
    location = finding.get("location") or {}
    return generate_finding_id(
        finding.get("ruleId") or "",
        location.get("file") or "",
        location.get("resourceAddress") or "",
    )


def _location_file(finding: Dict[str, Any]) -> str:
    return normalize_path((finding.get("location") or {}).get("file") or "")


# ===========================================================================
# 1. BASELINE
# ===========================================================================

BASELINE_SCHEMA = "iac-security-scan/baseline@1"


def write_baseline(
    findings: Sequence[Dict[str, Any]], *, generated_at: Optional[str] = None
) -> Dict[str, Any]:
    """Produce a baseline document from the current findings (``--write-baseline``).

    Records each finding's STABLE id plus human-readable identity fields so the
    file can be reviewed in a PR. Only the id is load-bearing for matching; the
    rest is there so a reviewer can tell what was accepted without running a tool.
    """
    entries: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for finding in findings:
        fid = _finding_id_of(finding)
        if fid in seen:
            continue
        seen.add(fid)
        location = finding.get("location") or {}
        entries.append(
            {
                "id": fid,
                "ruleId": finding.get("ruleId") or "",
                "file": normalize_path(location.get("file") or ""),
                "resourceAddress": location.get("resourceAddress") or "",
                "severity": finding.get("severity"),
                "title": finding.get("title") or "",
            }
        )
    entries.sort(key=lambda e: (e["file"], e["ruleId"], e["resourceAddress"]))
    return {
        "$schema": BASELINE_SCHEMA,
        "version": 1,
        "generatedAt": generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "findingCount": len(entries),
        "findings": entries,
    }


def load_baseline(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError(
            "%s is not an iac-security-scan baseline (missing 'findings'). "
            "Regenerate it with --write-baseline." % path
        )
    return data


def baseline_ids(baseline: Dict[str, Any]) -> Set[str]:
    return {str(e.get("id")) for e in baseline.get("findings") or [] if e.get("id")}


@dataclass
class BaselineResult:
    """Outcome of subtracting a baseline from a finding set."""

    kept: List[Dict[str, Any]]  # findings NEW since the baseline -> reported
    suppressed: List[Dict[str, Any]]  # findings present in the baseline -> hidden
    stale_ids: List[str]  # baselined ids that did NOT appear this scan (prunable)

    @property
    def suppressed_count(self) -> int:
        return len(self.suppressed)

    @property
    def stale_count(self) -> int:
        return len(self.stale_ids)


def apply_baseline(
    findings: Sequence[Dict[str, Any]], baseline: Dict[str, Any]
) -> BaselineResult:
    """Subtract baselined findings from the current findings, matching on id.

    Returns what is NEW (kept), what the baseline suppressed (counted, never
    silently dropped), and which baseline entries are now stale -- accepted debt
    that no longer appears and can be pruned so the fixed-then-reintroduced case
    behaves correctly next cycle (see module docstring).
    """
    ids = baseline_ids(baseline)
    kept: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()
    for finding in findings:
        fid = _finding_id_of(finding)
        seen_ids.add(fid)
        (suppressed if fid in ids else kept).append(finding)
    stale = sorted(ids - seen_ids)
    return BaselineResult(kept=kept, suppressed=suppressed, stale_ids=stale)


# ===========================================================================
# 2. SUPPRESSION (reasoned, per-finding)
# ===========================================================================

#: Checkov substitutes this exact string when a ``#checkov:skip=<ID>`` carries no
#: ``:reason`` tail. It is the tool telling us "no reason was given", so we treat
#: it -- and the empty string -- as NO reason, and reject the suppression.
CHECKOV_NO_REASON = "no comment provided"


class SuppressionError(ValueError):
    """A suppression violated the reasoned-acceptance rule."""


@dataclass(frozen=True)
class Suppression:
    """One reviewed, reasoned acceptance of a specific finding."""

    finding_id: str
    reason: str
    source: str  # "checkov-skip" | "ignore-file"
    rule_id: str = ""
    file: str = ""
    resource_address: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findingId": self.finding_id,
            "reason": self.reason,
            "source": self.source,
            "ruleId": self.rule_id,
            "file": self.file,
            "resourceAddress": self.resource_address,
        }


@dataclass(frozen=True)
class RejectedSuppression:
    """A suppression attempt refused for having no stated reason."""

    finding_id: str
    source: str
    rule_id: str = ""
    file: str = ""
    resource_address: str = ""
    detail: str = "no reason given"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findingId": self.finding_id,
            "source": self.source,
            "ruleId": self.rule_id,
            "file": self.file,
            "resourceAddress": self.resource_address,
            "detail": self.detail,
        }


def _clean_reason(reason: Optional[str]) -> str:
    text = (reason or "").strip()
    if not text or text.lower() == CHECKOV_NO_REASON:
        return ""
    return text


def parse_checkov_skips(
    raw_payload: Any,
) -> Tuple[List[Suppression], List[RejectedSuppression]]:
    """Extract native Checkov skips from a RAW Checkov JSON payload.

    Honors the tool's own mechanism (SPEC: prefer the native path to inventing a
    parallel one). Checkov puts skipped checks in ``results.skipped_checks`` with
    the reason in ``check_result.suppress_comment``. We do NOT read
    ``run_checkov``'s normalized ``skippedChecks`` here because that adapter
    drops the reason -- and a suppression is nothing without its reason.

    A skip whose ``suppress_comment`` is empty or Checkov's "No comment provided"
    sentinel is REJECTED (returned separately), so the finding still surfaces.
    """
    blocks = raw_payload if isinstance(raw_payload, list) else [raw_payload]
    accepted: List[Suppression] = []
    rejected: List[RejectedSuppression] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        results = block.get("results") or {}
        for check in results.get("skipped_checks") or []:
            if not isinstance(check, dict):
                continue
            rule_id = check.get("check_id") or ""
            resource = (check.get("resource") or "").strip()
            file = normalize_path(check.get("file_path") or "")
            fid = generate_finding_id(rule_id, file, resource)
            reason = _clean_reason((check.get("check_result") or {}).get("suppress_comment"))
            if not reason:
                rejected.append(
                    RejectedSuppression(
                        finding_id=fid,
                        source="checkov-skip",
                        rule_id=rule_id,
                        file=file,
                        resource_address=resource,
                        detail="#checkov:skip=%s carried no reason" % rule_id,
                    )
                )
                continue
            accepted.append(
                Suppression(
                    finding_id=fid,
                    reason=reason,
                    source="checkov-skip",
                    rule_id=rule_id,
                    file=file,
                    resource_address=resource,
                )
            )
    return accepted, rejected


#: Default filename for the parallel, id-keyed ignore mechanism.
IGNORE_FILENAME = ".iac-security-scan-ignore"


def parse_ignore_file(
    text: str,
) -> Tuple[List[Suppression], List[RejectedSuppression]]:
    """Parse an ``.iac-security-scan-ignore`` file: ``<finding-id>  <reason>``.

    One entry per line. ``#`` starts a comment; blank lines are ignored. The id
    and the reason are separated by whitespace or a colon. A line with an id but
    NO reason is REJECTED -- same rule as the Checkov path: no reason, no
    suppression.
    """
    accepted: List[Suppression] = []
    rejected: List[RejectedSuppression] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Split id from reason on the first whitespace run or the first colon,
        # whichever comes first, so both "id reason" and "id: reason" work.
        fid, _, remainder = _split_ignore_line(line)
        reason = _clean_reason(remainder)
        if not fid:
            continue
        if not reason:
            rejected.append(
                RejectedSuppression(
                    finding_id=fid,
                    source="ignore-file",
                    detail="ignore entry has no reason",
                )
            )
            continue
        accepted.append(Suppression(finding_id=fid, reason=reason, source="ignore-file"))
    return accepted, rejected


def _split_ignore_line(line: str) -> Tuple[str, str, str]:
    """Return (id, sep, reason_text). Splits on first ':' or whitespace."""
    colon = line.find(":")
    space = -1
    for i, ch in enumerate(line):
        if ch.isspace():
            space = i
            break
    # Choose the earliest separator that exists.
    candidates = [pos for pos in (colon, space) if pos != -1]
    if not candidates:
        return line, "", ""
    cut = min(candidates)
    return line[:cut].strip(), line[cut], line[cut + 1 :].strip()


def load_ignore_file(path: str) -> Tuple[List[Suppression], List[RejectedSuppression]]:
    with open(path, encoding="utf-8") as fh:
        return parse_ignore_file(fh.read())


@dataclass
class SuppressionResult:
    """Outcome of applying reasoned suppressions to a finding set."""

    kept: List[Dict[str, Any]]
    suppressed: List[Dict[str, Any]]  # findings hidden, each with its reason
    rejected: List[RejectedSuppression]  # reasonless attempts -- findings STAYED
    unmatched: List[Suppression] = field(default_factory=list)  # matched no live finding

    @property
    def suppressed_count(self) -> int:
        return len(self.suppressed)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    @property
    def unmatched_count(self) -> int:
        return len(self.unmatched)


def _synthesized_suppressed(sup: Suppression) -> Dict[str, Any]:
    """A finding-shaped record for a suppression whose finding never reached us.

    A native ``#checkov:skip`` moves the check into ``skipped_checks``, so it is
    absent from ``failed_checks`` and therefore from the merged set entirely. It
    is still a real, tool-enforced suppression of a real finding, so we surface it
    from the skip record itself -- otherwise the native mechanism would suppress
    findings the report never mentions, which is precisely the silence we forbid.
    """
    return {
        "id": sup.finding_id,
        "ruleId": sup.rule_id,
        "title": sup.rule_id,
        "location": {
            "file": sup.file,
            "startLine": 0,
            "endLine": 0,
            "resourceAddress": sup.resource_address,
            "resourceType": "",
            "service": "",
        },
        "suppression": {"reason": sup.reason, "source": sup.source},
    }


def apply_suppressions(
    findings: Sequence[Dict[str, Any]],
    suppressions: Sequence[Suppression],
    *,
    rejected: Optional[Sequence[RejectedSuppression]] = None,
) -> SuppressionResult:
    """Hide findings that have a reviewed, *reasoned* suppression; count them.

    Two suppression sources reach here and they behave differently:

      * ``ignore-file`` -- the finding is still in the live set (Checkov reported
        it as failed). We remove it, annotate it with its reason and source, and
        count it. An ignore entry that matches nothing live is ``unmatched`` (a
        stale/wrong id) -- reported, but it hides nothing.

      * ``checkov-skip`` -- Checkov already moved the check to ``skipped_checks``,
        so the finding never reached the merged set. It is still a real,
        tool-enforced suppression, so we surface it from the skip record itself
        and count it. This is what keeps native suppressions from being silent.

    Reasonless attempts in ``rejected`` hide nothing; they are carried through so
    the report can say the suppression was refused.
    """
    ignore_by_id: Dict[str, Suppression] = {}
    native: List[Suppression] = []
    for sup in suppressions:
        if sup.source == "checkov-skip":
            native.append(sup)
        else:
            # First reasoned suppression for an id wins; a later one does not override.
            ignore_by_id.setdefault(sup.finding_id, sup)

    kept: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []
    matched_ignore: Set[str] = set()
    for finding in findings:
        fid = _finding_id_of(finding)
        sup = ignore_by_id.get(fid)
        if sup is None:
            kept.append(finding)
            continue
        matched_ignore.add(fid)
        annotated = dict(finding)
        annotated["suppression"] = {"reason": sup.reason, "source": sup.source}
        suppressed.append(annotated)

    # Native Checkov skips: each valid one is a real finding Checkov already
    # suppressed. Surface and count it even though it is not in the live set.
    seen_native: Set[str] = set()
    for sup in native:
        if sup.finding_id in seen_native:
            continue
        seen_native.add(sup.finding_id)
        suppressed.append(_synthesized_suppressed(sup))

    unmatched = [
        sup
        for fid, sup in ignore_by_id.items()
        if fid not in matched_ignore
    ]
    return SuppressionResult(
        kept=kept,
        suppressed=suppressed,
        rejected=list(rejected or []),
        unmatched=unmatched,
    )


# ===========================================================================
# 3. DIFF-ONLY (PR gate)
# ===========================================================================

DEFAULT_BASE = "origin/main"


class GitScopeError(RuntimeError):
    """git could not resolve the base ref or the repo -- a diff-only run cannot
    guess its scope, so it fails loudly (never silently scans everything)."""


def _git(args: List[str], repo_root: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", repo_root, *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def repo_toplevel(root: str) -> str:
    proc = _git(["rev-parse", "--show-toplevel"], root)
    if proc.returncode != 0:
        raise GitScopeError(
            "%s is not inside a git repository; --diff-only needs git to find the "
            "changed files." % os.path.abspath(root)
        )
    return proc.stdout.strip()


def resolve_base(base: Optional[str], repo_root: str) -> str:
    """Verify the base ref exists; NEVER assume ``main`` (standing rule).

    Tries the requested base (default ``origin/main``). If that specific ref does
    not resolve, we do NOT silently fall back to a different branch -- we raise,
    listing what was tried, so a PR gate can never be scoped against a base the
    user did not mean.
    """
    requested = base or DEFAULT_BASE
    if _git(["rev-parse", "--verify", "--quiet", requested], repo_root).returncode == 0:
        return requested
    # A precise, actionable failure beats a wrong scope. Offer the common
    # alternatives that *do* resolve so the caller can pick one explicitly.
    alternatives = [
        ref
        for ref in ("origin/main", "origin/master", "main", "master", "HEAD~1")
        if ref != requested
        and _git(["rev-parse", "--verify", "--quiet", ref], repo_root).returncode == 0
    ]
    hint = (
        " Refs that DO resolve here: %s. Pass one with --base." % ", ".join(alternatives)
        if alternatives
        else " No common base ref resolves; pass an explicit --base."
    )
    raise GitScopeError("base ref %r does not resolve.%s" % (requested, hint))


def changed_files(base: str, repo_root: str) -> List[str]:
    """Repo-root-relative paths changed on this branch vs ``base`` (``base...HEAD``).

    The three-dot form compares HEAD against the merge-base with ``base`` -- the
    changes THIS branch introduced, which is exactly a PR's scope.
    """
    proc = _git(["diff", "--name-only", "%s...HEAD" % base], repo_root)
    if proc.returncode != 0:
        raise GitScopeError(
            "git diff against %r failed: %s" % (base, (proc.stderr or "").strip())
        )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


@dataclass
class DiffScope:
    """Which IaC files are in scope for a diff-only run, relative to the SCAN root."""

    base: str
    changed_iac_files: Set[str]  # scan-root-relative, normalized
    all_iac_files: Set[str]  # every IaC file under the scan root, normalized
    changed_non_iac: List[str]  # changed files that are not IaC (informational)

    @property
    def scanned_count(self) -> int:
        return len(self.changed_iac_files)

    @property
    def skipped_count(self) -> int:
        # IaC files present in the tree but NOT changed by this branch.
        return len(self.all_iac_files - self.changed_iac_files)


def _rel_to_scan_root(repo_rel_path: str, repo_root: str, scan_root: str) -> Optional[str]:
    """Map a repo-root-relative path to a scan-root-relative one, or None if it
    lies outside the scan root."""
    abs_path = os.path.normpath(os.path.join(repo_root, repo_rel_path))
    scan_abs = os.path.abspath(scan_root)
    rel = os.path.relpath(abs_path, scan_abs)
    if rel.startswith(".."):
        return None
    return normalize_path(rel)


def _all_iac_under(scan_root: str) -> Set[str]:
    found: Set[str] = set()
    scan_abs = os.path.abspath(scan_root)
    for dirpath, dirnames, filenames in os.walk(scan_abs):
        # Skip the usual noise; .terraform can be huge and holds no source.
        dirnames[:] = [d for d in dirnames if d not in (".git", ".terraform")]
        for name in filenames:
            if is_iac_file(name):
                rel = os.path.relpath(os.path.join(dirpath, name), scan_abs)
                found.add(normalize_path(rel))
    return found


def compute_diff_scope(scan_root: str, base: Optional[str] = None) -> DiffScope:
    """Resolve the base, diff it, and project changed IaC files onto the scan root."""
    repo_root = repo_toplevel(scan_root)
    resolved_base = resolve_base(base, repo_root)
    changed = changed_files(resolved_base, repo_root)

    changed_iac: Set[str] = set()
    changed_non_iac: List[str] = []
    for repo_rel in changed:
        scan_rel = _rel_to_scan_root(repo_rel, repo_root, scan_root)
        if scan_rel is None:
            continue  # outside the scan root -> irrelevant to this scan
        if is_iac_file(scan_rel):
            changed_iac.add(scan_rel)
        else:
            changed_non_iac.append(scan_rel)
    return DiffScope(
        base=resolved_base,
        changed_iac_files=changed_iac,
        all_iac_files=_all_iac_under(scan_root),
        changed_non_iac=sorted(changed_non_iac),
    )


@dataclass
class DiffFilterResult:
    in_scope: List[Dict[str, Any]]
    out_of_scope: List[Dict[str, Any]]  # findings on unchanged files


def apply_diff_filter(
    findings: Sequence[Dict[str, Any]], scope: DiffScope
) -> DiffFilterResult:
    """Keep only findings whose file changed on this branch.

    Findings on unchanged files are OUT of scope for a diff-only run -- and the
    report says so, so a clean diff-only run is never mistaken for a clean repo.
    """
    in_scope: List[Dict[str, Any]] = []
    out_of_scope: List[Dict[str, Any]] = []
    for finding in findings:
        file = _location_file(finding)
        (in_scope if file in scope.changed_iac_files else out_of_scope).append(finding)
    return DiffFilterResult(in_scope=in_scope, out_of_scope=out_of_scope)


# ===========================================================================
# Orchestration: apply all three filters to a merge_result, build a scope summary
# ===========================================================================


def apply_scope(
    merge_result: Dict[str, Any],
    *,
    baseline: Optional[Dict[str, Any]] = None,
    suppressions: Optional[Sequence[Suppression]] = None,
    rejected_suppressions: Optional[Sequence[RejectedSuppression]] = None,
    diff_scope: Optional[DiffScope] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Filter ``merge_result['findings']`` through baseline/suppression/diff.

    Returns ``(filtered_merge_result, scan_scope)``. ``filtered_merge_result`` is
    a shallow copy with a reduced ``findings`` list -- safe to hand straight to
    ``report.build_report``. ``scan_scope`` is the counts-and-lists summary the
    report renders so every removal is visible.

    Order matters and is deliberate: diff-scope first (define what this run is
    even looking at), then baseline (subtract accepted debt), then suppression
    (reasoned per-finding acceptance). Each stage reports against what reached it.
    """
    findings = list(merge_result.get("findings") or [])
    scope: Dict[str, Any] = {"active": False}

    if diff_scope is not None:
        result = apply_diff_filter(findings, diff_scope)
        findings = result.in_scope
        scope["active"] = True
        scope["diff"] = {
            "base": diff_scope.base,
            "filesScanned": diff_scope.scanned_count,
            "filesSkipped": diff_scope.skipped_count,
            "changedFiles": sorted(diff_scope.changed_iac_files),
            "outOfScopeFindings": len(result.out_of_scope),
        }

    if baseline is not None:
        result = apply_baseline(findings, baseline)
        findings = result.kept
        scope["active"] = True
        scope["baseline"] = {
            "suppressed": result.suppressed_count,
            "staleEntries": result.stale_count,
            "staleIds": result.stale_ids,
            "generatedAt": baseline.get("generatedAt"),
        }

    if suppressions is not None or rejected_suppressions:
        result = apply_suppressions(
            findings, suppressions or [], rejected=rejected_suppressions
        )
        findings = result.kept
        scope["active"] = True
        scope["suppression"] = {
            "suppressed": result.suppressed_count,
            "rejected": result.rejected_count,
            "items": [
                {
                    "findingId": _finding_id_of(f),
                    "ruleId": f.get("ruleId"),
                    "reason": (f.get("suppression") or {}).get("reason"),
                    "source": (f.get("suppression") or {}).get("source"),
                }
                for f in result.suppressed
            ],
            "rejectedItems": [r.to_dict() for r in result.rejected],
            "unmatched": result.unmatched_count,
            "unmatchedItems": [s.to_dict() for s in result.unmatched],
        }

    filtered = dict(merge_result)
    filtered["findings"] = findings
    return filtered, scope


# ===========================================================================
# Report wiring (standalone -- report.py is untouched; see note at bottom)
# ===========================================================================


def render_scope_section(scope: Dict[str, Any]) -> List[str]:
    """Markdown for the scan-scope summary. Empty when no filter was active.

    This is the "the user MUST see it happened" surface: diff scope, baseline
    suppression counts, and reasoned/refused suppressions, each as a line a human
    cannot miss.
    """
    if not scope or not scope.get("active"):
        return []

    lines: List[str] = ["## Scan scope", ""]

    diff = scope.get("diff")
    if diff:
        lines += [
            "**diff-only: %d file%s scanned, %d skipped** (base `%s`)."
            % (
                diff["filesScanned"],
                "" if diff["filesScanned"] == 1 else "s",
                diff["filesSkipped"],
                diff["base"],
            ),
            "",
            "> Only files changed on this branch were assessed. The %d skipped IaC "
            "file%s %s NOT scanned here -- a clean result above is NOT a clean repo. "
            "Run a full scan (no --diff-only) for whole-tree coverage."
            % (
                diff["filesSkipped"],
                "" if diff["filesSkipped"] == 1 else "s",
                "was" if diff["filesSkipped"] == 1 else "were",
            ),
            "",
        ]
        if diff.get("outOfScopeFindings"):
            lines += [
                "%d finding%s on unchanged files %s out of scope for this diff-only run."
                % (
                    diff["outOfScopeFindings"],
                    "" if diff["outOfScopeFindings"] == 1 else "s",
                    "is" if diff["outOfScopeFindings"] == 1 else "are",
                ),
                "",
            ]

    base = scope.get("baseline")
    if base:
        lines += [
            "**Baseline: %d finding%s suppressed** (pre-existing, accepted debt)."
            % (base["suppressed"], "" if base["suppressed"] == 1 else "s"),
            "",
            "> Only findings NEW since the baseline are reported above.",
            "",
        ]
        if base.get("staleEntries"):
            lines += [
                "%d baseline entr%s no longer appear (fixed or removed) and can be "
                "pruned by regenerating the baseline (`--write-baseline`)."
                % (base["staleEntries"], "y" if base["staleEntries"] == 1 else "ies"),
                "",
            ]

    sup = scope.get("suppression")
    if sup:
        lines += [
            "**Suppressed (%d, with reasons).** Reviewed, reasoned acceptances -- "
            "listed, never silently dropped." % sup["suppressed"],
            "",
        ]
        for item in sup["items"]:
            lines.append(
                "- `%s` (%s) — %s _[%s]_"
                % (
                    item["findingId"],
                    item.get("ruleId") or "?",
                    item.get("reason") or "(no reason)",
                    item.get("source") or "?",
                )
            )
        if sup["items"]:
            lines.append("")
        if sup.get("rejected"):
            lines += [
                "**%d suppression%s REJECTED for having no reason** -- the finding%s "
                "%s reported above, not hidden. A suppression without a stated reason "
                "is not an accepted risk, it is a hidden one."
                % (
                    sup["rejected"],
                    "" if sup["rejected"] == 1 else "s",
                    "" if sup["rejected"] == 1 else "s",
                    "is still" if sup["rejected"] == 1 else "are still",
                ),
                "",
            ]
            for item in sup["rejectedItems"]:
                lines.append(
                    "- `%s` (%s) — %s"
                    % (
                        item["findingId"],
                        item.get("ruleId") or "?",
                        item.get("detail") or "no reason given",
                    )
                )
            lines.append("")
        if sup.get("unmatched"):
            lines += [
                "_%d ignore-file suppression%s matched no current finding (already "
                "fixed, or a stale id) and hid nothing._"
                % (sup["unmatched"], "" if sup["unmatched"] == 1 else "s"),
                "",
            ]

    return lines


def render_markdown_with_scope(report: Dict[str, Any]) -> str:
    """``report.render_markdown`` with the scan-scope section appended.

    Kept here rather than in ``report.py`` so this workstream stays standalone
    and cannot collide with a sibling editing the report renderer. A future,
    deliberate integration point in ``report.py`` would be one guarded line in
    ``render_markdown``:

        if report.get("scanScope"):
            lines += baseline.render_scope_section(report["scanScope"])

    placed after ``_render_degradation``. Until then this wrapper is the seam.
    """
    import report as report_module

    body = report_module.render_markdown(report)
    section = render_scope_section(report.get("scanScope") or {})
    if not section:
        return body
    return body.rstrip() + "\n\n" + "\n".join(section).rstrip() + "\n"


# ===========================================================================
# End-to-end scan with scoping (what the CLI drives)
# ===========================================================================


def scan_with_scope(
    root: str,
    *,
    base: Optional[str] = None,
    diff_only: bool = False,
    baseline_path: Optional[str] = None,
    ignore_file: Optional[str] = None,
    honor_checkov_skips: bool = True,
    compliance: Optional[str] = None,
    use_fmt: bool = True,
) -> Dict[str, Any]:
    """Run the deterministic pipeline, apply scope filters, build the report.

    Mirrors ``report.scan`` but inserts the baseline/suppression/diff filter
    between ``merge`` and ``build_report`` so quick-wins, patches, and counts all
    reflect the SCOPED finding set. The scope summary is attached to the report
    under ``scanScope`` for ``render_markdown_with_scope``.
    """
    from merge_findings import merge
    from parse_iac import parse_terraform
    from patch_terraform import (
        FixCatalog,
        generate_file_patches,
        generate_security_patches,
        load_terraform_resources,
    )
    from report import FULL_PARSE_TIER, build_report
    from run_checkov import DEFAULT_FRAMEWORKS, find_checkov, run_checkov

    # parse_iac prints progress to stdout; stdout is reserved for the report, so
    # the whole data-gathering phase is redirected to stderr (diagnostics belong
    # there anyway). build_report/rendering never print, so they stay outside.
    import contextlib

    with contextlib.redirect_stdout(sys.stderr):
        checkov_result = run_checkov(root)
        parse_result = parse_terraform(root)
        merge_result = merge(checkov_result.get("findings") or [], parse_result=parse_result)

    # --- Gather scope inputs -------------------------------------------------
    diff_scope: Optional[DiffScope] = None
    if diff_only:
        diff_scope = compute_diff_scope(root, base)

    baseline_doc: Optional[Dict[str, Any]] = None
    if baseline_path:
        baseline_doc = load_baseline(baseline_path)

    suppressions: List[Suppression] = []
    rejected: List[RejectedSuppression] = []
    # Only pay for the raw Checkov re-run (reasons live only in the raw payload)
    # when the normalized adapter already told us there ARE skips to honor.
    if honor_checkov_skips and (checkov_result.get("skippedChecks") or []):
        raw = _raw_checkov_payload(root, find_checkov, DEFAULT_FRAMEWORKS)
        if raw is not None:
            acc, rej = parse_checkov_skips(raw)
            suppressions += acc
            rejected += rej
    if ignore_file and os.path.isfile(ignore_file):
        acc, rej = load_ignore_file(ignore_file)
        suppressions += acc
        rejected += rej

    have_suppression_source = bool(suppressions) or bool(rejected)

    filtered, scope = apply_scope(
        merge_result,
        baseline=baseline_doc,
        suppressions=suppressions if have_suppression_source else None,
        rejected_suppressions=rejected,
        diff_scope=diff_scope,
    )

    # --- Patches over the SCOPED findings only ------------------------------
    patches: List[Any] = []
    file_patches: List[Any] = []
    if parse_result.get("parseTier") == FULL_PARSE_TIER:
        with contextlib.redirect_stdout(sys.stderr):
            catalog = FixCatalog.load()
            resources, _ = load_terraform_resources(root)
            patches = generate_security_patches(
                root, filtered["findings"], catalog, resources, use_fmt=use_fmt
            )
            file_patches = generate_file_patches(root, patches, resources, use_fmt=use_fmt)

    report = build_report(
        filtered,
        checkov_result=checkov_result,
        parse_result=parse_result,
        patches=patches,
        file_patches=file_patches,
        root=root,
        compliance=compliance,
    )
    report["scanScope"] = scope
    return report


def _raw_checkov_payload(root: str, find_checkov, frameworks) -> Optional[Any]:
    """Run Checkov once more for the RAW JSON (skip reasons live only there).

    ``run_checkov`` normalizes away ``suppress_comment``; to honor native skips
    with their reasons we need the raw payload. Returns None if Checkov is absent
    (suppression simply contributes nothing -- never an error)."""
    binary = find_checkov()
    if not binary:
        return None
    fw = list(frameworks)
    cmd = [binary, "-d", root, "--framework", *fw, "--output", "json", "--compact"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError):
        return None
    out = (proc.stdout or "").strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


# ===========================================================================
# CLI
# ===========================================================================


def main(argv: Optional[List[str]] = None) -> int:
    """CLI for baseline / suppression / diff-only scoped scans.

    Exit codes follow the project convention where a gate applies; a
    ``--write-baseline`` run is a generator, not a gate, and exits 0 on success.
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Baseline, suppression, and PR-diff-only scoped IaC scans."
    )
    parser.add_argument("root", help="directory to scan")
    parser.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="write the current findings to FILE as an accepted-debt baseline and exit",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="subtract findings recorded in FILE; report only what is new",
    )
    parser.add_argument(
        "--diff-only",
        action="store_true",
        help="scope the report to files changed on this branch vs --base",
    )
    parser.add_argument(
        "--changed-only",
        action="store_true",
        dest="diff_only",
        help="alias for --diff-only",
    )
    parser.add_argument(
        "--base",
        metavar="REF",
        default=None,
        help="base ref for --diff-only (default: origin/main, verified not assumed)",
    )
    parser.add_argument(
        "--ignore-file",
        metavar="FILE",
        default=None,
        help="reasoned per-finding suppressions (default: %s in root)" % IGNORE_FILENAME,
    )
    parser.add_argument(
        "--no-checkov-skips",
        action="store_true",
        help="do not honor native #checkov:skip comments",
    )
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--out", help="write to this file instead of stdout")
    parser.add_argument("--no-fmt", action="store_true", help="skip terraform fmt on patches")
    parser.add_argument("--compliance", metavar="BASELINE", default=None)
    args = parser.parse_args(argv)

    # --write-baseline is a generator: run the plain scan, snapshot its findings.
    if args.write_baseline:
        try:
            from report import scan as plain_scan

            report = plain_scan(args.root, use_fmt=not args.no_fmt)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write("scan error: %s\n" % exc)
            return 2
        baseline = write_baseline(report.get("findings") or [])
        text = json.dumps(baseline, indent=2)
        _write(text, args.out or args.write_baseline)
        sys.stderr.write(
            "Wrote baseline of %d finding%s to %s\n"
            % (
                baseline["findingCount"],
                "" if baseline["findingCount"] == 1 else "s",
                args.write_baseline,
            )
        )
        return 0

    ignore_file = args.ignore_file
    if ignore_file is None:
        default_ignore = os.path.join(args.root, IGNORE_FILENAME)
        ignore_file = default_ignore if os.path.isfile(default_ignore) else None

    try:
        report = scan_with_scope(
            args.root,
            base=args.base,
            diff_only=args.diff_only,
            baseline_path=args.baseline,
            ignore_file=ignore_file,
            honor_checkov_skips=not args.no_checkov_skips,
            compliance=args.compliance,
            use_fmt=not args.no_fmt,
        )
    except GitScopeError as exc:
        sys.stderr.write("diff-only scope error: %s\n" % exc)
        return 2
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("scan error: %s\n" % exc)
        return 2

    if args.format == "json":
        text = json.dumps(report, indent=2, default=str)
    else:
        text = render_markdown_with_scope(report)
    _write(text, args.out)
    return 0


def _write(text: str, out: Optional[str]) -> None:
    payload = text if text.endswith("\n") else text + "\n"
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(payload)
    else:
        sys.stdout.write(payload)


__all__ = [
    "IAC_SUFFIXES",
    "is_iac_file",
    # baseline
    "BASELINE_SCHEMA",
    "write_baseline",
    "load_baseline",
    "baseline_ids",
    "BaselineResult",
    "apply_baseline",
    # suppression
    "CHECKOV_NO_REASON",
    "IGNORE_FILENAME",
    "SuppressionError",
    "Suppression",
    "RejectedSuppression",
    "parse_checkov_skips",
    "parse_ignore_file",
    "load_ignore_file",
    "SuppressionResult",
    "apply_suppressions",
    # diff-only
    "DEFAULT_BASE",
    "GitScopeError",
    "repo_toplevel",
    "resolve_base",
    "changed_files",
    "DiffScope",
    "compute_diff_scope",
    "DiffFilterResult",
    "apply_diff_filter",
    # orchestration
    "apply_scope",
    "render_scope_section",
    "render_markdown_with_scope",
    "scan_with_scope",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
