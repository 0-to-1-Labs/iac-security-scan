"""WS-9 · emit_sarif.py — SARIF 2.1.0 + the CI exit-code gate (SPEC §9.2).

Three things this file exists to prove, none of them cosmetic:

  * **The output validates against the real SARIF 2.1.0 JSON schema** — not "looks
    plausible". The schema is checked in at ``tests/data/sarif-schema-2.1.0.json`` and
    every emitted log is run through ``jsonschema`` against it.

  * **Locations point at a real ``file:line``** — the whole WS-9 edit. infrabot wrote
    ``uri: finding.resourceArn`` (``sarif.ts:308``), which GitHub cannot resolve to a
    file, so the annotation never landed. We assert against the *fixture source*: the
    line the SARIF names must actually contain the resource block it claims.

  * **A degraded scan emits no SARIF at all.** No line numbers means every location
    would be a fabricated line 1 — a confident, precise, wrong annotation on a PR.
    ``emit_sarif`` raises and the CLI exits 2.
"""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "skills", "iac-security-scan", "scripts")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
SCHEMA_PATH = os.path.join(ROOT, "tests", "data", "sarif-schema-2.1.0.json")
sys.path.insert(0, SCRIPTS)

from emit_sarif import (  # noqa: E402
    DEFAULT_FLOOR,
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_FINDINGS,
    SEVERITY_TO_SECURITY_SEVERITY,
    DegradedScanError,
    create_location,
    create_rule,
    emit_sarif,
    finding_to_result,
    findings_at_or_above,
    gate_exit_code,
    meets_floor,
    severity_to_level,
    severity_to_security_severity,
    write_sarif,
)
from findings import UNMAPPED  # noqa: E402
from report import build_report, scan  # noqa: E402

FIXTURE = "tf-01-three-tier-webapp"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_finding(**kw):
    f = {
        "id": kw.pop("id", "finding-abc123"),
        "ruleId": kw.pop("ruleId", "CKV_AWS_18"),
        "title": kw.pop("title", "Ensure S3 bucket has access logging"),
        "description": kw.pop("description", "Access logging is not configured."),
        "severity": kw.pop("severity", "high"),
        "severitySource": kw.pop("severitySource", "prowler"),
        "exploitability": kw.pop("exploitability", "moderate"),
        "remediationComplexity": kw.pop("remediationComplexity", "simple"),
        "priorityScore": kw.pop("priorityScore", 80),
        "isQuickWin": kw.pop("isQuickWin", True),
        "remediationType": kw.pop("remediationType", "iac"),
        "source": kw.pop("source", ["checkov"]),
        "location": kw.pop(
            "location",
            {
                "file": "s3.tf",
                "startLine": 12,
                "endLine": 20,
                "resourceAddress": "aws_s3_bucket.data",
                "resourceType": "aws_s3_bucket",
                "service": "s3",
            },
        ),
    }
    f.update(kw)
    return f


def make_report(findings=None, *, degraded=False, tier="tfparse", checkov_degraded=False):
    findings = [make_finding()] if findings is None else findings
    return {
        "root": os.path.join(FIXTURES, FIXTURE),
        "summary": {"total": len(findings), "bySeverity": {}},
        "degradation": {
            "degraded": degraded,
            "reasons": [],
            "parseTier": tier,
            "checkovDegraded": checkov_degraded,
            "parserDegraded": tier != "tfparse",
            "patchesPossible": tier == "tfparse",
        },
        "findings": findings,
        "quickWins": [],
        "nonIaC": [],
        "verdict": "x",
    }


@pytest.fixture(scope="module")
def schema():
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def real_report():
    """A real deterministic scan of the tf-01 fixture. Slow-ish; module-scoped."""
    return scan(os.path.join(FIXTURES, FIXTURE), use_fmt=False)


def assert_valid_sarif(sarif, schema):
    import jsonschema

    jsonschema.validate(instance=sarif, schema=schema)


# ---------------------------------------------------------------------------
# 1. It validates. Actually validates — against the checked-in 2.1.0 schema.
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    def test_synthetic_report_emits_schema_valid_sarif(self, schema):
        assert_valid_sarif(emit_sarif(make_report()), schema)

    def test_empty_findings_emits_schema_valid_sarif(self, schema):
        sarif = emit_sarif(make_report([]))
        assert sarif["runs"][0]["results"] == []
        assert_valid_sarif(sarif, schema)

    def test_unmapped_severity_emits_schema_valid_sarif(self, schema):
        assert_valid_sarif(emit_sarif(make_report([make_finding(severity=UNMAPPED)])), schema)

    @pytest.mark.slow
    def test_real_scan_emits_schema_valid_sarif(self, real_report, schema):
        sarif = emit_sarif(real_report)
        assert len(sarif["runs"][0]["results"]) == len(real_report["findings"]) > 0
        assert_valid_sarif(sarif, schema)

    def test_version_and_schema_uri(self):
        sarif = emit_sarif(make_report())
        assert sarif["version"] == "2.1.0"
        assert "sarif-schema-2.1.0.json" in sarif["$schema"]

    def test_rule_index_points_at_the_right_rule(self):
        sarif = emit_sarif(
            make_report([make_finding(ruleId="CKV_AWS_18"), make_finding(id="f2", ruleId="CKV_AWS_21")])
        )
        run = sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    def test_one_rule_per_rule_id_not_per_finding(self):
        findings = [
            make_finding(id="f1", ruleId="CKV_AWS_18", location={"file": "a.tf", "startLine": 1, "endLine": 3, "resourceAddress": "aws_s3_bucket.a", "resourceType": "aws_s3_bucket", "service": "s3"}),
            make_finding(id="f2", ruleId="CKV_AWS_18", location={"file": "b.tf", "startLine": 5, "endLine": 9, "resourceAddress": "aws_s3_bucket.b", "resourceType": "aws_s3_bucket", "service": "s3"}),
        ]
        sarif = emit_sarif(make_report(findings))
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(sarif["runs"][0]["results"]) == 2


# ---------------------------------------------------------------------------
# 2. THE FIX: locations are file:line, not ARNs.
# ---------------------------------------------------------------------------


class TestLocationIsTheFix:
    def test_uri_is_a_repo_relative_file_not_an_arn(self):
        loc = create_location(make_finding(resourceArn="arn:aws:s3:::my-bucket"))
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "s3.tf"
        assert not uri.startswith("arn:")  # sarif.ts:308, the bug we came here to kill

    def test_region_carries_start_and_end_line(self):
        loc = create_location(make_finding())
        assert loc["physicalLocation"]["region"] == {"startLine": 12, "endLine": 20}

    def test_arn_survives_as_a_logical_location(self):
        """The ARN isn't wrong, it was just in the wrong field. §5's schema inversion:
        physical location = the file; logical location = the cloud resource."""
        loc = create_location(make_finding(resourceArn="arn:aws:s3:::my-bucket"))
        logical = loc["logicalLocations"]
        assert logical[0]["fullyQualifiedName"] == "arn:aws:s3:::my-bucket"
        assert logical[0]["name"] == "aws_s3_bucket.data"

    def test_no_arn_still_yields_a_logical_location(self):
        """Static scans have no ARN — nothing is deployed. It must not blow up."""
        logical = create_location(make_finding())["logicalLocations"]
        assert logical[0]["fullyQualifiedName"] == "aws_s3_bucket.data"

    def test_no_start_line_means_no_region_not_line_one(self):
        loc = create_location(
            make_finding(
                location={
                    "file": "s3.tf",
                    "startLine": None,
                    "endLine": None,
                    "resourceAddress": "aws_s3_bucket.data",
                    "resourceType": "aws_s3_bucket",
                    "service": "s3",
                }
            )
        )
        assert "region" not in loc["physicalLocation"]

    def test_end_line_before_start_line_is_dropped_not_emitted(self):
        loc = create_location(make_finding(location={**make_finding()["location"], "endLine": 3}))
        assert loc["physicalLocation"]["region"] == {"startLine": 12}

    def test_absolute_path_is_made_relative(self):
        loc = create_location(make_finding(location={**make_finding()["location"], "file": "/modules/s3.tf"}))
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "modules/s3.tf"

    def test_missing_file_is_an_error_not_a_placeholder(self):
        with pytest.raises(ValueError):
            create_location(make_finding(location={"file": "", "resourceAddress": "x"}))

    def test_uri_base_id_and_original_uri_base_ids_agree(self):
        sarif = emit_sarif(make_report())
        run = sarif["runs"][0]
        base = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"]
        assert base in run["originalUriBaseIds"]
        assert run["originalUriBaseIds"][base]["uri"].startswith("file://")

    @pytest.mark.slow
    def test_every_location_resolves_to_the_real_fixture_source(self, real_report):
        """The load-bearing assertion. For every finding: the file exists in the
        fixture, the start line is inside it, and the named resource block really is
        at that line."""
        root = os.path.join(FIXTURES, FIXTURE)
        sarif = emit_sarif(real_report)
        results = sarif["runs"][0]["results"]
        assert results

        for result, finding in zip(results, real_report["findings"]):
            physical = result["locations"][0]["physicalLocation"]
            uri = physical["artifactLocation"]["uri"]
            path = os.path.join(root, uri)
            assert os.path.isfile(path), "SARIF uri %r is not a file in the scanned tree" % uri

            source = open(path, encoding="utf-8").read().splitlines()
            start = physical["region"]["startLine"]
            end = physical["region"]["endLine"]
            assert 1 <= start <= end <= len(source)

            # The declaration line must actually declare the resource SARIF claims.
            # Strip module path and count/for_each index: aws_subnet.public[1] -> public.
            address = finding["location"]["resourceAddress"]
            kind, _, rest = address.partition(".")
            name = rest.split(".")[-1].split("[")[0]
            decl = source[start - 1]
            assert kind in decl and name in decl, (
                "SARIF points %s:%d at %r, which does not declare %s"
                % (uri, start, decl, address)
            )

    @pytest.mark.slow
    def test_no_result_location_is_an_arn(self, real_report):
        for result in emit_sarif(real_report)["runs"][0]["results"]:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert uri.endswith(".tf")


# ---------------------------------------------------------------------------
# 3. security-severity: GitHub's ranking input, seeded from rule-severity.json
# ---------------------------------------------------------------------------


class TestSecuritySeverity:
    @pytest.mark.parametrize(
        "severity,floor",
        [("critical", 9.0), ("high", 7.0), ("medium", 4.0), ("low", 0.1)],
    )
    def test_lands_in_githubs_bucket(self, severity, floor):
        value = severity_to_security_severity(severity)
        assert float(value) >= floor

    def test_ordering_is_strictly_monotonic(self):
        order = ["critical", "high", "medium", "low", "informational"]
        scores = [float(SEVERITY_TO_SECURITY_SEVERITY[s]) for s in order]
        assert scores == sorted(scores, reverse=True)
        assert len(set(scores)) == len(scores)

    def test_unmapped_gets_no_number_at_all(self):
        """Not 5.0, not 0.0. A number here is a ranking claim we cannot make."""
        assert severity_to_security_severity(UNMAPPED) is None
        rule = create_rule(make_finding(severity=UNMAPPED))
        assert "security-severity" not in rule["properties"]
        assert rule["properties"]["severityUnmapped"] is True
        assert "unmapped-severity" in rule["properties"]["tags"]

    def test_unmapped_finding_is_still_emitted_and_says_so(self):
        result = finding_to_result(make_finding(severity=UNMAPPED))
        assert "UNMAPPED" in result["message"]["text"]
        assert result["properties"]["severity"] == UNMAPPED

    @pytest.mark.parametrize(
        "severity,level",
        [
            ("critical", "error"),
            ("high", "error"),
            ("medium", "warning"),
            ("low", "note"),
            ("informational", "note"),
            (UNMAPPED, "note"),
        ],
    )
    def test_level_mapping(self, severity, level):
        assert severity_to_level(severity) == level

    def test_precision_comes_from_exploitability(self):
        assert create_rule(make_finding(exploitability="trivial"))["properties"]["precision"] == "very-high"
        assert create_rule(make_finding(exploitability="theoretical"))["properties"]["precision"] == "low"

    def test_fingerprint_is_the_stable_finding_id(self):
        result = finding_to_result(make_finding(id="finding-deadbeef"))
        assert result["partialFingerprints"]["iacSecurityScanFindingId/v1"] == "finding-deadbeef"


# ---------------------------------------------------------------------------
# 4. A degraded scan emits NO SARIF. This is the non-negotiable.
# ---------------------------------------------------------------------------


class TestDegradedScanEmitsNothing:
    @pytest.mark.parametrize("tier", ["hcl2", "regex", None])
    def test_no_line_numbers_means_no_sarif(self, tier):
        with pytest.raises(DegradedScanError) as exc:
            emit_sarif(make_report(degraded=True, tier=tier))
        assert "line numbers" in str(exc.value).lower()

    def test_missing_checkov_means_no_sarif(self):
        """A near-empty SARIF uploaded to code scanning reads as 'clean'. It isn't."""
        with pytest.raises(DegradedScanError):
            emit_sarif(make_report(degraded=True, checkov_degraded=True))

    def test_the_error_tells_you_how_to_fix_it(self):
        with pytest.raises(DegradedScanError) as exc:
            emit_sarif(make_report(degraded=True, tier="regex"))
        assert "tfparse" in str(exc.value)


# ---------------------------------------------------------------------------
# 5. Exit codes (SPEC §9.2) — the CI gate
# ---------------------------------------------------------------------------


class TestSeverityFloor:
    @pytest.mark.parametrize(
        "severity,floor,expected",
        [
            ("critical", "high", True),
            ("high", "high", True),
            ("medium", "high", False),
            ("low", "high", False),
            ("medium", "medium", True),
            ("low", "medium", False),
            ("low", "low", True),
            ("informational", "low", False),
            ("critical", "critical", True),
            ("high", "critical", False),
        ],
    )
    def test_meets_floor(self, severity, floor, expected):
        assert meets_floor(severity, floor) is expected

    def test_unmapped_never_meets_a_floor(self):
        """It has no rank. Failing the build on a data gap is as wrong as passing it
        silently — so it does not trip the gate, and the CLI says so on stderr."""
        for floor in ("critical", "high", "medium", "low"):
            assert meets_floor(UNMAPPED, floor) is False

    def test_unknown_floor_raises(self):
        with pytest.raises(ValueError):
            meets_floor("high", "extreme")

    def test_findings_at_or_above(self):
        findings = [
            make_finding(id="a", severity="critical"),
            make_finding(id="b", severity="high"),
            make_finding(id="c", severity="medium"),
            make_finding(id="d", severity=UNMAPPED),
        ]
        assert [f["id"] for f in findings_at_or_above(findings, "high")] == ["a", "b"]
        assert [f["id"] for f in findings_at_or_above(findings, "medium")] == ["a", "b", "c"]


class TestGateExitCode:
    def test_zero_when_clean_at_the_floor(self):
        report = make_report([make_finding(severity="medium")])
        assert gate_exit_code(report, "high") == EXIT_CLEAN

    def test_one_when_findings_at_the_floor(self):
        report = make_report([make_finding(severity="high")])
        assert gate_exit_code(report, "high") == EXIT_FINDINGS

    def test_one_when_findings_above_the_floor(self):
        report = make_report([make_finding(severity="critical")])
        assert gate_exit_code(report, "high") == EXIT_FINDINGS

    def test_zero_on_no_findings(self):
        assert gate_exit_code(make_report([]), DEFAULT_FLOOR) == EXIT_CLEAN

    def test_two_on_a_degraded_scan(self):
        """'Clean' is not a claim a degraded scan is entitled to make."""
        report = make_report([], degraded=True, tier="regex")
        assert gate_exit_code(report, "high") == EXIT_ERROR

    def test_unmapped_alone_does_not_trip_the_gate(self):
        report = make_report([make_finding(severity=UNMAPPED)])
        assert gate_exit_code(report, "high") == EXIT_CLEAN


# ---------------------------------------------------------------------------
# 6. End to end through the CLI — `iac-scan --severity high || exit 1`
# ---------------------------------------------------------------------------


def run_report_cli(*args, env=None):
    return subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "report.py"), *args],
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
    )


class TestCLI:
    @pytest.mark.slow
    def test_sarif_format_writes_valid_sarif_and_exits_1_on_high(self, tmp_path, schema):
        out = tmp_path / "results.sarif"
        proc = run_report_cli(
            os.path.join(FIXTURES, FIXTURE),
            "--format",
            "sarif",
            "--severity",
            "high",
            "--no-fmt",
            "--out",
            str(out),
        )
        assert proc.returncode == EXIT_FINDINGS, proc.stderr
        sarif = json.loads(out.read_text())
        assert_valid_sarif(sarif, schema)
        assert sarif["runs"][0]["results"]

    @pytest.mark.slow
    def test_clean_module_exits_0_at_the_high_floor(self, tmp_path):
        """A module with nothing at/above the floor is a passing gate."""
        (tmp_path / "main.tf").write_text(
            'resource "aws_sns_topic" "t" {\n'
            '  name              = "t"\n'
            '  kms_master_key_id = "alias/aws/sns"\n'
            "}\n"
        )
        proc = run_report_cli(str(tmp_path), "--severity", "critical", "--no-fmt")
        assert proc.returncode == EXIT_CLEAN, (proc.stdout, proc.stderr)

    @pytest.mark.slow
    def test_the_floor_changes_the_verdict_of_the_gate(self, tmp_path):
        """Same tree, two floors, two exit codes. That is the gate working."""
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
        )
        low = run_report_cli(str(tmp_path), "--severity", "low", "--no-fmt")
        critical = run_report_cli(str(tmp_path), "--severity", "critical", "--no-fmt")
        assert low.returncode == EXIT_FINDINGS, low.stderr
        assert critical.returncode == EXIT_CLEAN, critical.stderr

    @pytest.mark.slow
    def test_degraded_scan_refuses_to_write_sarif_and_exits_2(self, tmp_path):
        out = tmp_path / "results.sarif"
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')
        proc = run_report_cli(
            str(tmp_path),
            "--format",
            "sarif",
            "--no-fmt",
            "--out",
            str(out),
            env={"CHECKOV_BIN": "/nonexistent/checkov"},
        )
        assert proc.returncode == EXIT_ERROR
        assert "DEGRADED SCAN" in proc.stderr
        assert not out.exists(), "a degraded scan must not leave a SARIF file behind"


class TestWriteSarif:
    def test_round_trips(self, tmp_path):
        path = tmp_path / "out.sarif"
        write_sarif(emit_sarif(make_report()), str(path))
        assert json.loads(path.read_text())["version"] == "2.1.0"
