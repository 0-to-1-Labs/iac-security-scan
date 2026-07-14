"""Tests for the Checkov adapter (WS-2).

Two things are load-bearing here and both get explicit coverage:

1. **Path normalization.** Checkov says "/athena.tf"; the WS-1 parser says
   "athena.tf". The downstream join key is (rule, file, resourceAddress). If
   these two do not normalize to the same string, EVERY join silently produces
   zero matches and the scan looks healthy while finding nothing.

2. **The degraded path.** Checkov missing must be loud: degraded=true, an
   install hint, and zero findings that are clearly labeled as "we didn't run
   the rule engine" rather than "your code is clean".

Pinned to checkov==3.2.500.
"""

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "skills", "iac-security-scan", "scripts")
FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")
SCRIPT = os.path.join(SCRIPTS, "run_checkov.py")

sys.path.insert(0, SCRIPTS)

import run_checkov  # noqa: E402

# Pinned expectations (plan risk #10: an unpinned checkov upgrade reads as a
# regression in our code). Measured against checkov 3.2.500.
PINNED_CHECKOV_VERSION = "3.2.500"
EXPECTED_FAILED = {
    "tf-01-three-tier-webapp": 23,
    "tf-02-serverless-api": 55,
    "tf-03-data-lake": 26,
    "tf-04-container-platform": 35,
    "tf-05-cicd-pipeline": 19,
}
EXPECTED_CORPUS_TOTAL = 158
EXPECTED_DISTINCT_RULES = 56


def checkov_installed():
    return run_checkov.find_checkov() is not None


requires_checkov = pytest.mark.skipif(
    not checkov_installed(), reason="checkov not installed"
)


# ---------------------------------------------------------------------------
# Path normalization — the silent-join-breaker
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/athena.tf", "athena.tf"),  # the exact shape Checkov emits
        ("/modules/vpc/main.tf", "modules/vpc/main.tf"),
        ("athena.tf", "athena.tf"),  # the exact shape tfparse emits
        ("./athena.tf", "athena.tf"),
        ("/./athena.tf", "athena.tf"),
        ("//athena.tf", "athena.tf"),
        ("  /athena.tf  ", "athena.tf"),
        ("", ""),
        (None, ""),
    ],
)
def test_normalize_path(raw, expected):
    assert run_checkov.normalize_path(raw) == expected


def test_checkov_and_parser_paths_converge():
    """The whole point: both sides of the join land on the same string."""
    checkov_side = run_checkov.normalize_path("/athena.tf")  # checkov file_path
    parser_side = run_checkov.normalize_path("athena.tf")  # tfparse __tfmeta.filename
    assert checkov_side == parser_side == "athena.tf"


def test_normalized_path_never_leads_with_slash():
    for raw in ("/a.tf", "/deep/nested/b.tf", "///c.tf"):
        assert not run_checkov.normalize_path(raw).startswith("/")


# ---------------------------------------------------------------------------
# Resource address / type / service
# ---------------------------------------------------------------------------


def test_resource_address_joins_natively():
    """Pre-flight verified: checkov.resource == tfparse __tfmeta.path, verbatim."""
    address, rtype = run_checkov.split_resource_address("aws_athena_workgroup.main")
    assert address == "aws_athena_workgroup.main"
    assert rtype == "aws_athena_workgroup"


def test_module_resource_address():
    address, rtype = run_checkov.split_resource_address("module.vpc.aws_s3_bucket.logs")
    assert address == "module.vpc.aws_s3_bucket.logs"
    assert rtype == "aws_s3_bucket"


@pytest.mark.parametrize(
    "rtype,service",
    [
        ("aws_s3_bucket", "s3"),
        ("aws_cloudwatch_log_group", "cloudwatch"),
        ("aws_athena_workgroup", "athena"),
        ("", ""),
    ],
)
def test_service_from_resource_type(rtype, service):
    assert run_checkov.service_from_resource_type(rtype) == service


def test_finding_id_is_stable_and_spec_shaped():
    a = run_checkov.finding_id("CKV_AWS_18", "athena.tf", "aws_s3_bucket.x")
    b = run_checkov.finding_id("CKV_AWS_18", "athena.tf", "aws_s3_bucket.x")
    assert a == b
    assert a.startswith("finding-")
    assert len(a) == len("finding-") + 16
    assert a != run_checkov.finding_id("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")


# ---------------------------------------------------------------------------
# Normalization of a synthetic Checkov payload (no Checkov needed)
# ---------------------------------------------------------------------------

SAMPLE_CHECK = {
    "check_id": "CKV_AWS_159",
    "check_name": "Ensure that Athena Workgroup is encrypted",
    "check_result": {"result": "FAILED"},
    "file_path": "/athena.tf",
    "file_abs_path": "/anywhere/athena.tf",
    "file_line_range": [2, 26],
    "resource": "aws_athena_workgroup.main",
    "severity": None,
    "guideline": "https://example.invalid/g",
}


def test_normalize_check_emits_spec_shape():
    f = run_checkov.normalize_check(SAMPLE_CHECK)
    assert f["ruleId"] == "CKV_AWS_159"
    assert f["title"] == "Ensure that Athena Workgroup is encrypted"
    assert f["source"] == ["checkov"]
    assert f["location"] == {
        "file": "athena.tf",  # leading slash gone
        "startLine": 2,
        "endLine": 26,
        "resourceAddress": "aws_athena_workgroup.main",
        "resourceType": "aws_athena_workgroup",
        "service": "athena",
    }


def test_severity_is_null_never_fabricated():
    """Checkov CE emits no severity. We must not invent one or default to medium."""
    f = run_checkov.normalize_check(SAMPLE_CHECK)
    assert f["severity"] is None


def test_no_checkov_native_field_leaks_into_the_schema():
    """Risk §14.1: swapping in tfsec/Trivy must stay a one-file change."""
    f = run_checkov.normalize_check(SAMPLE_CHECK)
    leaked = {
        "check_id",
        "check_name",
        "check_result",
        "file_path",
        "file_abs_path",
        "file_line_range",
        "resource",
        "bc_check_id",
        "check_class",
        "repo_file_path",
    }
    assert not (leaked & set(f)), "Checkov field leaked into core schema"
    assert not (leaked & set(f["location"]))


def test_normalize_results_handles_list_and_dict_payloads():
    block = {
        "results": {"failed_checks": [SAMPLE_CHECK], "passed_checks": [SAMPLE_CHECK]},
        "summary": {"failed": 1, "passed": 1, "skipped": 0, "resource_count": 1},
    }
    as_dict = run_checkov.normalize_results(block)
    as_list = run_checkov.normalize_results([block])
    assert len(as_dict["failed"]) == len(as_list["failed"]) == 1
    assert len(as_dict["passed"]) == len(as_list["passed"]) == 1


# ---------------------------------------------------------------------------
# Degraded path — Checkov absent
# ---------------------------------------------------------------------------


def test_degraded_when_checkov_missing(monkeypatch, capsys, tmp_path):
    """Simulate an uninstalled Checkov. Must degrade LOUDLY, never silently."""
    monkeypatch.setattr(run_checkov, "find_checkov", lambda: None)

    result = run_checkov.run_checkov(str(tmp_path))

    assert result["degraded"] is True
    assert result["findings"] == []
    assert result["passedChecks"] == []
    assert result["toolVersion"] is None
    assert "pip install checkov==%s" % PINNED_CHECKOV_VERSION in result["installHint"]
    assert "not installed" in result["degradationReason"]

    # Loud: the install line and a DEGRADED banner go to stderr, so it survives
    # stdout being piped into a JSON consumer.
    err = capsys.readouterr().err
    assert "DEGRADED" in err
    assert "pip install checkov" in err


def test_degraded_result_is_not_confusable_with_a_clean_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(run_checkov, "find_checkov", lambda: None)
    result = run_checkov.run_checkov(str(tmp_path))
    # Zero findings AND degraded=true. A consumer that reads `degraded` cannot
    # mistake "the tool never ran" for "the code is clean".
    assert result["summary"]["failed"] == 0
    assert result["degraded"] is True
    assert result["degradationReason"]


def test_degraded_when_checkov_binary_unexecutable(monkeypatch, tmp_path):
    monkeypatch.setattr(run_checkov, "find_checkov", lambda: "/nonexistent/checkov")

    def boom(*_a, **_k):
        raise OSError("No such file or directory")

    monkeypatch.setattr(run_checkov.subprocess, "run", boom)
    result = run_checkov.run_checkov(str(tmp_path))
    assert result["degraded"] is True
    assert "pip install checkov" in result["degradationReason"]


def test_degraded_on_unparseable_output(monkeypatch, tmp_path):
    monkeypatch.setattr(run_checkov, "find_checkov", lambda: "checkov")

    class Proc:
        returncode = 0
        stdout = "not json at all"
        stderr = ""

    monkeypatch.setattr(run_checkov.subprocess, "run", lambda *a, **k: Proc())
    result = run_checkov.run_checkov(str(tmp_path))
    assert result["degraded"] is True
    assert "not valid JSON" in result["degradationReason"]


# ---------------------------------------------------------------------------
# Live Checkov against the fixture corpus
# ---------------------------------------------------------------------------


@requires_checkov
def test_quiet_flag_is_not_used():
    """--quiet silently drops passed_checks, which §7.2's compliance report needs."""
    src = open(SCRIPT).read()
    assert '"--quiet"' not in src


@requires_checkov
def test_tf03_data_lake_returns_26_findings():
    result = run_checkov.run_checkov(os.path.join(FIXTURES, "tf-03-data-lake"))
    assert result["degraded"] is False
    assert result["toolVersion"] == PINNED_CHECKOV_VERSION
    assert len(result["findings"]) == 26


@requires_checkov
def test_passed_checks_are_captured():
    """Phase 2's 'controls SATISFIED by the current IaC' is derived from these."""
    result = run_checkov.run_checkov(os.path.join(FIXTURES, "tf-03-data-lake"))
    assert len(result["passedChecks"]) > 0
    assert result["summary"]["passed"] == len(result["passedChecks"])
    passing = result["passedChecks"][0]
    assert passing["ruleId"].startswith("CKV")
    assert passing["location"]["file"]
    assert passing["severity"] is None


@requires_checkov
@pytest.mark.parametrize("fixture,expected", sorted(EXPECTED_FAILED.items()))
def test_per_fixture_finding_counts(fixture, expected):
    result = run_checkov.run_checkov(os.path.join(FIXTURES, fixture))
    assert len(result["findings"]) == expected


@requires_checkov
def test_corpus_totals():
    total, rules = 0, set()
    for fixture in EXPECTED_FAILED:
        result = run_checkov.run_checkov(os.path.join(FIXTURES, fixture))
        total += len(result["findings"])
        rules.update(f["ruleId"] for f in result["findings"])
    assert total == EXPECTED_CORPUS_TOTAL
    assert len(rules) == EXPECTED_DISTINCT_RULES


@requires_checkov
def test_every_real_finding_has_a_clean_repo_relative_path():
    """The join-key guarantee, asserted against real Checkov output."""
    result = run_checkov.run_checkov(os.path.join(FIXTURES, "tf-03-data-lake"))
    for f in result["findings"] + result["passedChecks"]:
        path = f["location"]["file"]
        assert path, "empty file path in %s" % f["ruleId"]
        assert not path.startswith("/"), path
        assert not path.startswith("./"), path
        # And it actually exists relative to the scan root.
        assert os.path.isfile(os.path.join(result["scanRoot"], path)), path


@requires_checkov
def test_no_finding_carries_a_fabricated_severity():
    result = run_checkov.run_checkov(os.path.join(FIXTURES, "tf-02-serverless-api"))
    assert all(f["severity"] is None for f in result["findings"])


@requires_checkov
def test_cli_emits_json_on_stdout_and_exits_zero():
    proc = subprocess.run(
        [sys.executable, SCRIPT, os.path.join(FIXTURES, "tf-03-data-lake")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert len(payload["findings"]) == 26
    assert payload["degraded"] is False


def test_cli_exits_2_on_bad_path():
    proc = subprocess.run(
        [sys.executable, SCRIPT, "/nonexistent/path/xyz"], capture_output=True, text=True
    )
    assert proc.returncode == 2
