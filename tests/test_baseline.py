"""WS-15 tests: baseline, suppression, and PR-diff-only scoping.

The three capabilities that make this scanner adoptable on a real repo over time:

  * Baseline -- accept the pre-existing backlog, report only what is NEW, match
    on the STABLE finding id (not line numbers) so reformatting cannot resurface
    accepted debt, while a genuinely new insecure resource still surfaces.
  * Suppression -- reasoned, per-finding acceptance. A suppression with NO reason
    is rejected; suppressed findings are counted and listed, never dropped.
  * Diff-only -- scope to files changed vs a VERIFIED base (never assume main).

Most tests are pure (synthetic findings) and fast. The diff-only tests drive a
real temporary git repo (git is always present). One end-to-end test shells out
to checkov and is marked ``slow``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "skills", "iac-security-scan", "scripts")
FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")
sys.path.insert(0, SCRIPTS)

import baseline as bl  # noqa: E402
import run_checkov  # noqa: E402
from findings import generate_finding_id  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_finding(rule_id, file, address, **extra):
    """A merged-finding-shaped dict with a real, stable id."""
    resource_type = ".".join(address.split(".")[-2:-1]) or ""
    finding = {
        "id": generate_finding_id(rule_id, file, address),
        "ruleId": rule_id,
        "title": extra.pop("title", rule_id),
        "severity": extra.pop("severity", "high"),
        "location": {
            "file": file,
            "startLine": extra.pop("startLine", 1),
            "endLine": extra.pop("endLine", 5),
            "resourceAddress": address,
            "resourceType": resource_type,
            "service": resource_type.split("_")[1] if "_" in resource_type else "",
        },
    }
    finding.update(extra)
    return finding


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", repo, *args], capture_output=True, text=True, check=True
    )


@pytest.fixture
def git_repo(tmp_path):
    """A repo on ``main`` with two committed .tf files and a README."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.tf").write_text('resource "aws_s3_bucket" "a" {\n  bucket = "a"\n}\n')
    (repo / "b.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')
    (repo / "README.md").write_text("# repo\n")
    git(str(repo), "init", "-q")
    git(str(repo), "config", "user.email", "t@t.co")
    git(str(repo), "config", "user.name", "t")
    git(str(repo), "add", "-A")
    git(str(repo), "commit", "-qm", "init")
    git(str(repo), "branch", "-M", "main")
    return str(repo)


requires_checkov = pytest.mark.skipif(
    run_checkov.find_checkov() is None, reason="checkov not installed"
)


# ===========================================================================
# is_iac_file
# ===========================================================================


@pytest.mark.parametrize(
    "path,expected",
    [
        ("main.tf", True),
        ("modules/vpc/main.tf", True),
        ("providers.tf.json", True),
        ("MAIN.TF", True),
        ("README.md", False),
        ("terraform.tfstate", False),
        ("variables.tfvars", False),
        ("script.py", False),
    ],
)
def test_is_iac_file(path, expected):
    assert bl.is_iac_file(path) is expected


# ===========================================================================
# 1. BASELINE
# ===========================================================================


def test_write_baseline_captures_ids_and_readable_fields():
    findings = [
        make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x", severity="high"),
        make_finding("CKV_AWS_21", "s3.tf", "aws_s3_bucket.y", severity="low"),
    ]
    doc = bl.write_baseline(findings, generated_at="2026-01-01T00:00:00Z")
    assert doc["$schema"] == bl.BASELINE_SCHEMA
    assert doc["findingCount"] == 2
    entry = doc["findings"][0]
    assert set(entry) >= {"id", "ruleId", "file", "resourceAddress", "severity", "title"}
    assert bl.baseline_ids(doc) == {f["id"] for f in findings}


def test_write_baseline_normalizes_paths_and_dedupes():
    findings = [
        make_finding("CKV_AWS_18", "/s3.tf", "aws_s3_bucket.x"),
        make_finding("CKV_AWS_18", "/s3.tf", "aws_s3_bucket.x"),  # dup id
    ]
    doc = bl.write_baseline(findings)
    assert doc["findingCount"] == 1
    assert doc["findings"][0]["file"] == "s3.tf"  # leading slash stripped


def test_apply_baseline_reports_zero_new_on_identical_scan():
    findings = [
        make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x"),
        make_finding("CKV_AWS_21", "s3.tf", "aws_s3_bucket.y"),
    ]
    doc = bl.write_baseline(findings)
    result = bl.apply_baseline(findings, doc)
    assert result.kept == []
    assert result.suppressed_count == 2
    assert result.stale_count == 0


def test_apply_baseline_new_resource_surfaces():
    old = [make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")]
    doc = bl.write_baseline(old)
    new = make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.brand_new")
    result = bl.apply_baseline(old + [new], doc)
    assert [f["id"] for f in result.kept] == [new["id"]]
    assert result.suppressed_count == 1


def test_baseline_matches_on_id_not_line_numbers():
    """Reformatting/shifting a file must not resurface accepted debt."""
    original = make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x", startLine=10, endLine=15)
    doc = bl.write_baseline([original])
    # Same identity, different lines (the resource moved down the file).
    shifted = make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x", startLine=210, endLine=215)
    result = bl.apply_baseline([shifted], doc)
    assert result.kept == []  # still suppressed despite the line shift
    assert result.suppressed_count == 1


def test_baseline_stale_entry_when_finding_fixed():
    """A baselined finding that no longer appears is reported as stale/prunable.

    This is the mechanism that makes the fixed-then-reintroduced case behave: a
    fixed finding shows up as stale, signalling the baseline should be
    regenerated so a later reintroduction (same id) is not re-suppressed forever.
    """
    baselined = make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")
    doc = bl.write_baseline([baselined])
    # Next scan: the finding is fixed (absent). Nothing new either.
    result = bl.apply_baseline([], doc)
    assert result.kept == []
    assert result.stale_ids == [baselined["id"]]


def test_baseline_reintroduced_same_id_is_resuppressed_by_stale_baseline():
    """Documents the id-matching consequence: a stale baseline re-suppresses a
    reintroduced finding at the same address (same id). The fix is workflow --
    regenerate the baseline, which drops the stale entry."""
    baselined = make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")
    doc = bl.write_baseline([baselined])
    reintroduced = make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")
    assert reintroduced["id"] == baselined["id"]
    # With the STALE baseline still in place, it is suppressed (documented gap).
    stale_result = bl.apply_baseline([reintroduced], doc)
    assert stale_result.suppressed_count == 1
    # After regenerating the baseline post-fix (empty), it surfaces as new risk.
    regenerated = bl.write_baseline([])
    fresh_result = bl.apply_baseline([reintroduced], regenerated)
    assert [f["id"] for f in fresh_result.kept] == [reintroduced["id"]]


def test_load_baseline_rejects_non_baseline(tmp_path):
    bad = tmp_path / "nope.json"
    bad.write_text(json.dumps({"foo": "bar"}))
    with pytest.raises(ValueError):
        bl.load_baseline(str(bad))


def test_write_load_baseline_roundtrip(tmp_path):
    findings = [make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")]
    doc = bl.write_baseline(findings)
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(doc))
    loaded = bl.load_baseline(str(path))
    assert bl.baseline_ids(loaded) == bl.baseline_ids(doc)


# ===========================================================================
# 2. SUPPRESSION -- native checkov skips
# ===========================================================================


def _skip_payload(check_id, resource, file_path, comment):
    return {
        "results": {
            "skipped_checks": [
                {
                    "check_id": check_id,
                    "resource": resource,
                    "file_path": file_path,
                    "check_result": {"suppress_comment": comment},
                }
            ]
        }
    }


def test_parse_checkov_skips_honors_reasoned():
    payload = _skip_payload(
        "CKV_AWS_18", "aws_s3_bucket.x", "/s3.tf", "logging is centralized"
    )
    accepted, rejected = bl.parse_checkov_skips(payload)
    assert rejected == []
    assert len(accepted) == 1
    sup = accepted[0]
    assert sup.source == "checkov-skip"
    assert sup.reason == "logging is centralized"
    # id matches what a real merged finding would carry (path normalized)
    assert sup.finding_id == generate_finding_id("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")


@pytest.mark.parametrize("comment", ["", "   ", "No comment provided", "no comment provided"])
def test_parse_checkov_skips_rejects_reasonless(comment):
    payload = _skip_payload("CKV_AWS_18", "aws_s3_bucket.x", "/s3.tf", comment)
    accepted, rejected = bl.parse_checkov_skips(payload)
    assert accepted == []
    assert len(rejected) == 1
    assert rejected[0].source == "checkov-skip"


def test_parse_checkov_skips_handles_list_payload():
    payload = [
        _skip_payload("CKV_AWS_18", "aws_s3_bucket.x", "/s3.tf", "reason one"),
        _skip_payload("CKV_AWS_21", "aws_s3_bucket.y", "/s3.tf", "reason two"),
    ]
    accepted, rejected = bl.parse_checkov_skips(payload)
    assert len(accepted) == 2
    assert rejected == []


# ===========================================================================
# 2. SUPPRESSION -- ignore file
# ===========================================================================


def test_parse_ignore_file_reasoned_and_reasonless():
    text = (
        "# reviewed acceptances\n"
        "\n"
        "finding-aaa  legacy, tracked in JIRA-42\n"
        "finding-bbb: colon separated reason\n"
        "finding-ccc\n"  # no reason -> rejected
    )
    accepted, rejected = bl.parse_ignore_file(text)
    got = {s.finding_id: s.reason for s in accepted}
    assert got == {
        "finding-aaa": "legacy, tracked in JIRA-42",
        "finding-bbb": "colon separated reason",
    }
    assert [r.finding_id for r in rejected] == ["finding-ccc"]
    assert all(s.source == "ignore-file" for s in accepted)


def test_parse_ignore_file_treats_no_comment_as_reasonless():
    accepted, rejected = bl.parse_ignore_file("finding-xyz  No comment provided\n")
    assert accepted == []
    assert [r.finding_id for r in rejected] == ["finding-xyz"]


def test_load_ignore_file(tmp_path):
    p = tmp_path / bl.IGNORE_FILENAME
    p.write_text("finding-aaa  accepted for now\n")
    accepted, rejected = bl.load_ignore_file(str(p))
    assert len(accepted) == 1 and rejected == []


# ===========================================================================
# 2. SUPPRESSION -- apply
# ===========================================================================


def test_apply_suppressions_ignore_file_removes_and_counts():
    f1 = make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")
    f2 = make_finding("CKV_AWS_21", "s3.tf", "aws_s3_bucket.y")
    sup = bl.Suppression(finding_id=f1["id"], reason="accepted", source="ignore-file")
    result = bl.apply_suppressions([f1, f2], [sup])
    assert [f["id"] for f in result.kept] == [f2["id"]]
    assert result.suppressed_count == 1
    assert result.suppressed[0]["suppression"] == {"reason": "accepted", "source": "ignore-file"}


def test_apply_suppressions_reasonless_leaves_finding_reported():
    """The core rule: a rejected suppression hides NOTHING."""
    f1 = make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")
    rejected = [bl.RejectedSuppression(finding_id=f1["id"], source="ignore-file")]
    result = bl.apply_suppressions([f1], [], rejected=rejected)
    assert [f["id"] for f in result.kept] == [f1["id"]]  # still reported
    assert result.suppressed_count == 0
    assert result.rejected_count == 1


def test_apply_suppressions_native_skip_counted_even_when_absent():
    """A #checkov:skip removes the finding from failed_checks, so it is absent
    from the live set -- but it must still be counted and listed, never silent."""
    live = [make_finding("CKV_AWS_21", "s3.tf", "aws_s3_bucket.y")]
    native = bl.Suppression(
        finding_id=generate_finding_id("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x"),
        reason="logging centralized",
        source="checkov-skip",
        rule_id="CKV_AWS_18",
        file="s3.tf",
        resource_address="aws_s3_bucket.x",
    )
    result = bl.apply_suppressions(live, [native])
    assert [f["id"] for f in result.kept] == [live[0]["id"]]  # untouched
    assert result.suppressed_count == 1
    listed = result.suppressed[0]
    assert listed["ruleId"] == "CKV_AWS_18"
    assert listed["suppression"]["source"] == "checkov-skip"


def test_apply_suppressions_unmatched_ignore_entry():
    f1 = make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")
    sup = bl.Suppression(finding_id="finding-doesnotexist", reason="x", source="ignore-file")
    result = bl.apply_suppressions([f1], [sup])
    assert [f["id"] for f in result.kept] == [f1["id"]]
    assert result.suppressed_count == 0
    assert result.unmatched_count == 1


def test_apply_suppressions_first_reasoned_wins():
    f1 = make_finding("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")
    s1 = bl.Suppression(finding_id=f1["id"], reason="first", source="ignore-file")
    s2 = bl.Suppression(finding_id=f1["id"], reason="second", source="ignore-file")
    result = bl.apply_suppressions([f1], [s1, s2])
    assert result.suppressed[0]["suppression"]["reason"] == "first"


# ===========================================================================
# 3. DIFF-ONLY
# ===========================================================================


def test_resolve_base_verifies_existing_ref(git_repo):
    assert bl.resolve_base("main", git_repo) == "main"


def test_resolve_base_never_assumes_main_and_suggests(git_repo):
    """Default origin/main does not resolve in a repo with no remote; we must NOT
    silently fall back -- we raise and list refs that DO resolve."""
    with pytest.raises(bl.GitScopeError) as exc:
        bl.resolve_base(None, git_repo)  # default origin/main
    msg = str(exc.value)
    assert "origin/main" in msg
    assert "main" in msg  # suggested alternative


def test_resolve_base_rejects_bogus_ref(git_repo):
    with pytest.raises(bl.GitScopeError):
        bl.resolve_base("no/such/ref", git_repo)


def test_changed_files_lists_branch_changes(git_repo):
    git(git_repo, "checkout", "-q", "-b", "feature")
    with open(os.path.join(git_repo, "a.tf"), "a") as fh:
        fh.write('\nresource "aws_s3_bucket" "new" {\n  bucket = "n"\n}\n')
    git(git_repo, "commit", "-aqm", "change a.tf")
    changed = bl.changed_files("main", git_repo)
    assert changed == ["a.tf"]


def test_compute_diff_scope_and_filter(git_repo):
    git(git_repo, "checkout", "-q", "-b", "feature")
    with open(os.path.join(git_repo, "a.tf"), "a") as fh:
        fh.write('\nresource "aws_s3_bucket" "new" {\n  bucket = "n"\n}\n')
    git(git_repo, "commit", "-aqm", "change a.tf")

    scope = bl.compute_diff_scope(git_repo, base="main")
    assert scope.base == "main"
    assert scope.changed_iac_files == {"a.tf"}
    assert scope.all_iac_files == {"a.tf", "b.tf"}
    assert scope.scanned_count == 1
    assert scope.skipped_count == 1  # b.tf unchanged

    findings = [
        make_finding("CKV_AWS_18", "a.tf", "aws_s3_bucket.a"),  # in scope
        make_finding("CKV_AWS_18", "b.tf", "aws_s3_bucket.b"),  # out of scope
    ]
    res = bl.apply_diff_filter(findings, scope)
    assert [f["location"]["file"] for f in res.in_scope] == ["a.tf"]
    assert [f["location"]["file"] for f in res.out_of_scope] == ["b.tf"]


def test_compute_diff_scope_non_iac_change_scans_nothing(git_repo):
    git(git_repo, "checkout", "-q", "-b", "docs")
    with open(os.path.join(git_repo, "README.md"), "a") as fh:
        fh.write("\nmore docs\n")
    git(git_repo, "commit", "-aqm", "docs only")
    scope = bl.compute_diff_scope(git_repo, base="main")
    assert scope.changed_iac_files == set()
    assert scope.scanned_count == 0
    assert scope.skipped_count == 2  # both .tf files skipped
    assert scope.changed_non_iac == ["README.md"]


def test_compute_diff_scope_outside_git_raises(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    with pytest.raises(bl.GitScopeError):
        bl.compute_diff_scope(str(d), base="main")


# ===========================================================================
# Orchestration + rendering
# ===========================================================================


def test_apply_scope_combines_all_three():
    findings = [
        make_finding("CKV_AWS_18", "a.tf", "aws_s3_bucket.changed_new"),  # new, in-scope
        make_finding("CKV_AWS_21", "a.tf", "aws_s3_bucket.baselined"),  # baselined
        make_finding("CKV_AWS_23", "b.tf", "aws_s3_bucket.unchanged"),  # out of diff scope
    ]
    merge_result = {"findings": findings, "summary": {}}
    doc = bl.write_baseline([findings[1]])
    sup = bl.Suppression(finding_id=findings[0]["id"], reason="accepted", source="ignore-file")

    diff_scope = bl.DiffScope(
        base="main",
        changed_iac_files={"a.tf"},
        all_iac_files={"a.tf", "b.tf"},
        changed_non_iac=[],
    )
    filtered, scope = bl.apply_scope(
        merge_result, baseline=doc, suppressions=[sup], diff_scope=diff_scope
    )
    # diff drops b.tf; baseline drops the baselined; suppression hides the new one.
    assert filtered["findings"] == []
    assert scope["diff"]["filesScanned"] == 1
    assert scope["diff"]["filesSkipped"] == 1
    assert scope["diff"]["outOfScopeFindings"] == 1
    assert scope["baseline"]["suppressed"] == 1
    assert scope["suppression"]["suppressed"] == 1


def test_apply_scope_inactive_when_no_filters():
    merge_result = {"findings": [make_finding("CKV_AWS_18", "a.tf", "aws_s3_bucket.a")]}
    filtered, scope = bl.apply_scope(merge_result)
    assert scope["active"] is False
    assert len(filtered["findings"]) == 1


def test_render_scope_section_empty_when_inactive():
    assert bl.render_scope_section({"active": False}) == []
    assert bl.render_scope_section({}) == []


def test_render_scope_section_diff_line():
    scope = {
        "active": True,
        "diff": {
            "base": "main",
            "filesScanned": 1,
            "filesSkipped": 8,
            "changedFiles": ["a.tf"],
            "outOfScopeFindings": 22,
        },
    }
    text = "\n".join(bl.render_scope_section(scope))
    assert "diff-only: 1 file scanned, 8 skipped" in text
    assert "base `main`" in text
    assert "22 findings on unchanged files" in text


def test_render_scope_section_suppression_and_rejection():
    scope = {
        "active": True,
        "suppression": {
            "suppressed": 1,
            "rejected": 1,
            "items": [
                {
                    "findingId": "finding-aaa",
                    "ruleId": "CKV_AWS_18",
                    "reason": "logging centralized",
                    "source": "checkov-skip",
                }
            ],
            "rejectedItems": [
                {"findingId": "finding-bbb", "ruleId": "CKV_AWS_21", "detail": "no reason"}
            ],
            "unmatched": 0,
            "unmatchedItems": [],
        },
    }
    text = "\n".join(bl.render_scope_section(scope))
    assert "Suppressed (1, with reasons)" in text
    assert "logging centralized" in text
    assert "REJECTED for having no reason" in text
    assert "finding-bbb" in text


def test_render_scope_section_baseline_line():
    scope = {
        "active": True,
        "baseline": {"suppressed": 26, "staleEntries": 2, "staleIds": ["x", "y"]},
    }
    text = "\n".join(bl.render_scope_section(scope))
    assert "Baseline: 26 findings suppressed" in text
    assert "2 baseline entries no longer appear" in text


def test_render_markdown_with_scope_appends_section():
    report = {
        "root": ".",
        "summary": {"total": 0, "bySeverity": {}, "quickWins": 0, "nonIaC": 0, "withDiff": 0},
        "degradation": {"degraded": False, "reasons": []},
        "findings": [],
        "quickWins": [],
        "nonIaC": [],
        "exposureChains": [],
        "suppressionLog": [],
        "injectionAttempts": [],
        "filePatches": [],
        "compliance": None,
        "complianceRequested": None,
        "verdict": "0 findings.",
        "scanScope": {
            "active": True,
            "baseline": {"suppressed": 3, "staleEntries": 0, "staleIds": []},
        },
    }
    out = bl.render_markdown_with_scope(report)
    assert "## Scan scope" in out
    assert "Baseline: 3 findings suppressed" in out


# ===========================================================================
# End-to-end (slow -- shells out to checkov)
# ===========================================================================


@pytest.mark.slow
@requires_checkov
def test_e2e_baseline_zero_new_then_new_surfaces(tmp_path):
    """Acceptance 1, end to end on tf-03: write a baseline, confirm a re-scan
    reports 0 new, then add an insecure resource and confirm ONLY it surfaces."""
    import shutil

    repo = tmp_path / "tf03"
    shutil.copytree(os.path.join(FIXTURES, "tf-03-data-lake"), repo)
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t.co", "-c", "user.name=t",
         "commit", "-qm", "init"],
        check=True,
    )

    from report import scan as plain_scan

    report = plain_scan(str(repo), use_fmt=False)
    findings = report["findings"]
    assert findings, "tf-03 should produce findings"
    doc = bl.write_baseline(findings)

    # Re-scan with the baseline: 0 new.
    rescoped = bl.scan_with_scope(
        str(repo), baseline_path=_write_json(tmp_path, "baseline.json", doc), use_fmt=False
    )
    assert rescoped["findings"] == []
    assert rescoped["scanScope"]["baseline"]["suppressed"] == len(bl.baseline_ids(doc))

    # Add an insecure resource; only IT surfaces.
    with open(repo / "s3.tf", "a") as fh:
        fh.write('\nresource "aws_s3_bucket" "brand_new_insecure" {\n  bucket = "bn"\n}\n')
    scoped2 = bl.scan_with_scope(
        str(repo), baseline_path=_write_json(tmp_path, "baseline.json", doc), use_fmt=False
    )
    addrs = {f["location"]["resourceAddress"] for f in scoped2["findings"]}
    assert addrs == {"aws_s3_bucket.brand_new_insecure"}


def _write_json(dir_path, name, obj):
    p = dir_path / name
    p.write_text(json.dumps(obj))
    return str(p)
