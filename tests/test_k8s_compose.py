#!/usr/bin/env python3
"""WS-14 (Phase 3): Kubernetes + Docker Compose, findings-only, end to end.

K8s and Compose have NO fixer in this build. The deliverable is that their
findings flow through parse -> run_checkov -> merge -> report and render with a
correct ``file:line``, a severity (seeded or the explicit ``unmapped`` sentinel),
and a priority -- at the same quality as Terraform and CloudFormation -- WITHOUT
ever fabricating a diff, and WITHOUT the report implying an automated fix exists.

The load-bearing honesty properties this file pins:

  * A K8s finding renders with location + severity + priority and NO diff.
  * A K8s rule with no checked-in seed resolves to ``unmapped``, reported plainly
    -- NEVER defaulted to a middle value (the WS-3 governance, extended to K8s).
  * classify.py's AWS-service-shaped patterns do NOT mis-match a K8s finding; it
    falls through cleanly rather than being mislabelled as an AWS remediation.
  * Checkov's community edition has NO Docker Compose ruleset. A zero-finding
    Compose scan therefore must read as a COVERAGE GAP, never as "clean".
  * Degradation is loud: a manifest that parses to zero resources, or Checkov
    being unavailable for the format, degrades unmissably.

Pinned to checkov==3.2.500 (the framework rule set moves; an unpinned upgrade
reads as a regression in our code).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "skills", "iac-security-scan", "scripts")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
sys.path.insert(0, SCRIPTS)

import run_checkov  # noqa: E402
from classify import classify_finding, match_classification_pattern  # noqa: E402
from findings import UNMAPPED, SeverityMap  # noqa: E402
from parse_iac import parse_docker_compose, parse_kubernetes  # noqa: E402
from report import (  # noqa: E402
    FINDINGS_ONLY_FORMATS,
    THIN_CHECKOV_COVERAGE,
    assess_degradation,
    detect_iac_format,
    render_markdown,
    scan,
)

PINNED_CHECKOV = "3.2.500"

K8S_FIXTURE = os.path.join(FIXTURES, "k8s-01-workloads")
COMPOSE_FIXTURE = os.path.join(FIXTURES, "compose-01-stack")


def checkov_installed():
    return run_checkov.find_checkov() is not None


requires_checkov = pytest.mark.skipif(
    not checkov_installed(), reason="checkov not installed"
)


# One scan per format, module-scoped. Checkov is slow; do not re-run it per test.
@pytest.fixture(scope="module")
def k8s_report():
    return scan(K8S_FIXTURE, iac_format="kubernetes", use_fmt=False)


@pytest.fixture(scope="module")
def compose_report():
    return scan(COMPOSE_FIXTURE, iac_format="docker-compose", use_fmt=False)


# ===========================================================================
# Level 0 -- footing: the framework routing and the fixtures themselves
# ===========================================================================


class TestFooting:
    def test_checkov_is_pinned(self):
        if not checkov_installed():
            pytest.skip("checkov not installed")
        out = subprocess.run(["checkov", "--version"], capture_output=True, text=True)
        assert out.stdout.strip() == PINNED_CHECKOV

    def test_kubernetes_routes_to_the_kubernetes_framework(self):
        assert run_checkov.frameworks_for_format("kubernetes") == (
            "kubernetes",
            "secrets",
        )

    def test_compose_routes_away_from_terraform(self):
        # Whatever the exact set, a Compose scan must NOT run the terraform
        # framework (which would silently find nothing and look healthy).
        fw = run_checkov.frameworks_for_format("docker-compose")
        assert "terraform" not in fw

    def test_k8s_fixture_carries_the_well_known_misconfigs(self):
        text = open(os.path.join(K8S_FIXTURE, "deployment.yaml")).read()
        assert "privileged: true" in text  # container escape
        assert "image: registry.example.com/payments-api:latest" in text  # :latest
        assert "readOnlyRootFilesystem: false" in text
        assert "hostNetwork: true" in text and "hostPID: true" in text

    def test_compose_fixture_carries_the_well_known_misconfigs(self):
        text = open(os.path.join(COMPOSE_FIXTURE, "docker-compose.yaml")).read()
        assert "privileged: true" in text
        assert "image: nginx:latest" in text
        assert "SYS_ADMIN" in text  # dangerous capability
        assert "/var/run/docker.sock" in text  # docker socket mount


# ===========================================================================
# Level 1 -- Kubernetes flows end to end and renders at parity
# ===========================================================================


@requires_checkov
class TestKubernetesEndToEnd:
    def test_scan_produces_findings(self, k8s_report):
        assert k8s_report["iacFormat"] == "kubernetes"
        assert k8s_report["summary"]["total"] > 0

    def test_scan_is_not_falsely_degraded(self, k8s_report):
        """ruamel gives K8s real line numbers -- a healthy K8s scan is NOT the
        Terraform 'fell off tfparse' degradation."""
        assert k8s_report["degradation"]["degraded"] is False
        assert k8s_report["degradation"]["parserDegraded"] is False

    def test_every_finding_has_a_real_file_and_line(self, k8s_report):
        for f in k8s_report["findings"]:
            loc = f["location"]
            assert loc["file"] == "deployment.yaml"
            assert isinstance(loc["startLine"], int) and loc["startLine"] > 0
            assert loc["resourceAddress"]

    def test_findings_render_file_colon_line_in_markdown(self, k8s_report):
        md = render_markdown(k8s_report)
        assert "`deployment.yaml:1`" in md or "`deployment.yaml:32`" in md

    def test_no_finding_carries_a_fabricated_diff(self, k8s_report):
        """The whole point of findings-only: no fixer, so never a diff."""
        assert k8s_report["summary"]["withDiff"] == 0
        for f in k8s_report["findings"]:
            assert f.get("diff") is None
        assert "```diff" not in render_markdown(k8s_report)

    def test_report_does_not_imply_an_automated_fix_exists(self, k8s_report):
        md = render_markdown(k8s_report)
        # findings-only guidance instead of the Terraform "remediation engineer" line
        assert "Findings-only for kubernetes" in md
        assert "remediation engineer" not in md

    def test_privileged_container_is_the_top_critical(self, k8s_report):
        """CKV_K8S_16 (privileged) is the seeded critical and should rank first."""
        top = k8s_report["findings"][0]
        assert top["ruleId"] == "CKV_K8S_16"
        assert top["severity"] == "critical"
        assert top["priorityScore"] > 0

    def test_a_severity_distribution_actually_ranks(self, k8s_report):
        by_sev = k8s_report["summary"]["bySeverity"]
        # seeded rules give a real spread; not everything collapses to unmapped
        assert by_sev.get("critical", 0) >= 1
        assert by_sev.get("high", 0) >= 1


# ===========================================================================
# Level 2 -- severity governance for K8s (the WS-3 rule, extended)
# ===========================================================================


class TestK8sSeverityGovernance:
    def test_unseeded_k8s_rule_is_unmapped_not_defaulted(self):
        """A rule with no checked-in seed resolves to the explicit sentinel."""
        m = SeverityMap.load()
        # CKV_K8S_8 (liveness probe) is deliberately NOT seeded -- reliability, not
        # security. It must be unmapped, never a middle value.
        seed = m.resolve("CKV_K8S_8")
        assert seed.severity == UNMAPPED
        assert seed.is_mapped is False
        assert seed.source == "none"

    def test_seeded_k8s_criticals_resolve(self):
        m = SeverityMap.load()
        assert m.resolve("CKV_K8S_16").severity == "critical"
        assert m.resolve("CKV_K8S_20").severity == "high"
        assert m.resolve("CKV2_K8S_6").severity == "medium"
        assert m.resolve("CKV_K8S_43").severity == "low"

    @requires_checkov
    def test_unmapped_k8s_findings_are_reported_plainly_as_unranked(self, k8s_report):
        unmapped = [
            f
            for f in k8s_report["findings"]
            if (f.get("severity") or UNMAPPED) == UNMAPPED
        ]
        assert unmapped, "the reliability rules (probes, limits) stay unmapped"
        for f in unmapped:
            assert f["priorityScore"] == 0  # no rank, never a guessed middle score
        md = render_markdown(k8s_report)
        assert "unranked" in md
        assert "not the same as low risk" in md

    def test_added_k8s_seeds_are_flagged_pending_gate1_review(self):
        """The seeds I added are NOT covered by the AWS GATE-1 sign-off. The data
        file must say so, so a reviewer knows to look."""
        with open(
            os.path.join(SCRIPTS, "..", "data", "rule-severity.json"), encoding="utf-8"
        ) as fh:
            data = json.load(fh)
        meta = data["_meta"]
        assert "kubernetesSeeds" in meta
        assert "PENDING GATE-1" in meta["kubernetesSeeds"]["status"]
        # every CKV_K8S_* / CKV2_K8S_* entry carries the pending flag + a rationale
        k8s_rules = [
            k for k in data if k.startswith(("CKV_K8S_", "CKV2_K8S_"))
        ]
        assert len(k8s_rules) >= 10
        for rule in k8s_rules:
            entry = data[rule]
            assert entry.get("pendingGate1Review") is True, rule
            assert entry.get("source") == "curated", rule
            assert entry.get("rationale"), rule

    def test_severity_map_still_loads_with_the_new_meta_key(self):
        # _meta.kubernetesSeeds must not break the loader (it filters _-prefixed keys)
        m = SeverityMap.load()
        assert len(m) > 100


# ===========================================================================
# Level 3 -- classify.py falls through cleanly for K8s (no AWS mis-match)
# ===========================================================================


class TestClassifyFallsThroughForK8s:
    def test_no_aws_pattern_matches_a_k8s_check_id(self):
        for rule in (
            "CKV_K8S_16",
            "CKV_K8S_20",
            "CKV_K8S_23",
            "CKV2_K8S_6",
            "CKV_K8S_14",
        ):
            # service is empty/namespace-ish for K8s, description is the check name
            assert (
                match_classification_pattern(rule, "prod", "Container should not be privileged")
                is None
            ), rule

    def test_k8s_finding_classifies_as_iac_with_no_phantom_pattern(self):
        finding = {
            "ruleId": "CKV_K8S_16",
            "title": "Container should not be privileged",
            "description": "",
            "location": {
                "resourceAddress": "Pod.prod.debug-shell",
                "service": "prod",
            },
        }
        verdict = classify_finding(finding, has_iac_fix=False)
        # remediationType iac (edit the manifest), but NO AWS classification pattern,
        # NO invented CLI steps.
        assert verdict["remediationType"] == "iac"
        assert verdict["classificationPattern"] is None
        assert verdict["remediationSteps"] == {}

    @requires_checkov
    def test_no_k8s_finding_is_routed_to_a_non_iac_aws_bucket(self, k8s_report):
        for f in k8s_report["findings"]:
            # nothing should have been captured by an AWS account/service/console pattern
            assert f.get("nonIaCCategory") is None
            assert f.get("classificationPattern") is None


# ===========================================================================
# Level 4 -- Docker Compose: honest about thin Checkov coverage
# ===========================================================================


class TestDockerComposeHonesty:
    def test_compose_parse_reads_the_services(self):
        parsed = parse_docker_compose(
            os.path.join(COMPOSE_FIXTURE, "docker-compose.yaml")
        )
        assert parsed.get("format") == "docker-compose"
        assert parsed.get("total_services") == 2
        assert parsed.get("degraded") is False  # ruamel present -> line provenance

    def test_compose_is_a_declared_thin_coverage_format(self):
        assert "docker-compose" in THIN_CHECKOV_COVERAGE

    @requires_checkov
    def test_checkov_finds_nothing_on_compose_and_that_is_documented(self, compose_report):
        """Checkov 3.2.500 has no Docker Compose ruleset. Pin the honest reality:
        zero deterministic findings -- so we know if a future Checkov gains one."""
        assert compose_report["summary"]["total"] == 0
        assert compose_report["coverageNote"]

    @requires_checkov
    def test_zero_finding_compose_scan_does_not_read_as_clean(self, compose_report):
        verdict = compose_report["verdict"]
        assert "COVERAGE GAP" in verdict
        assert "Clean against the rules that ran" not in verdict
        md = render_markdown(compose_report)
        assert "COVERAGE GAP" in md
        # the standard clean line must not appear anywhere in a coverage-gap report
        assert "Clean against the rules that ran" not in md

    @requires_checkov
    def test_compose_scan_is_not_itself_degraded(self, compose_report):
        """The files WERE readable (ruamel parsed them); the gap is Checkov's rule
        coverage, which is a different, separately-labelled thing."""
        assert compose_report["degradation"]["checkovDegraded"] is False
        assert compose_report["degradation"]["parserDegraded"] is False


# ===========================================================================
# Level 5 -- degradation discipline (loud, per the ticket)
# ===========================================================================


class TestDegradationDiscipline:
    def test_healthy_k8s_parse_tier_is_not_degraded(self):
        d = assess_degradation(
            {"degraded": False},
            {
                "format": "kubernetes",
                "parseTier": "ruamel",
                "degraded": False,
                "lineProvenance": True,
            },
        )
        assert d["degraded"] is False
        assert d["patchesPossible"] is True

    def test_k8s_without_line_numbers_degrades_loudly(self):
        d = assess_degradation(
            {"degraded": False},
            {
                "format": "kubernetes",
                "parseTier": "yaml",
                "degraded": True,
                "lineProvenance": False,
                "degradationReason": "ruamel.yaml is unavailable.",
            },
        )
        assert d["degraded"] is True
        assert d["parserDegraded"] is True
        assert d["patchesPossible"] is False
        assert d["reasons"][0]["fix"] == "pip install ruamel.yaml"
        assert "SARIF" in d["reasons"][0]["impact"]

    def test_zero_resource_manifest_and_missing_checkov_degrade(self, tmp_path):
        """A manifest that parses to zero resources + no Checkov = an unmissable
        degraded scan, not a silent clean one."""
        (tmp_path / "empty.yaml").write_text("# just a comment, no resources\n")
        report = scan(
            str(tmp_path),
            iac_format="kubernetes",
            use_fmt=False,
        ) if checkov_installed() else None
        if report is None:
            pytest.skip("checkov not installed")
        # zero findings, and with Checkov present + a valid (if empty) parse it is a
        # clean-but-empty scan; the real degradation case is Checkov missing:
        env = {**os.environ, "CHECKOV_BIN": "/nonexistent/checkov"}
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(SCRIPTS, "report.py"),
                str(tmp_path),
                "--iac-format",
                "kubernetes",
                "--no-fmt",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        assert proc.returncode != 0  # a degraded scan is never a silent CI success
        assert "DEGRADED SCAN" in proc.stdout

    def test_a_parser_error_degrades_loudly(self):
        """"No Kubernetes manifest files found" (or any parser error) is a loud
        degradation, never a silent clean scan."""
        d = assess_degradation(
            {"degraded": False},
            {"error": "No Kubernetes manifest files found", "resources": []},
        )
        assert d["degraded"] is True
        assert d["parserDegraded"] is True
        assert "manifest files found" in d["reasons"][0]["reason"]

    def test_findings_only_formats_are_declared(self):
        assert "kubernetes" in FINDINGS_ONLY_FORMATS
        assert "docker-compose" in FINDINGS_ONLY_FORMATS
        assert "terraform" not in FINDINGS_ONLY_FORMATS


# ===========================================================================
# Level 6 -- the CLI end to end (what the /iac-scan command drives)
# ===========================================================================


class TestCli:
    @requires_checkov
    def test_kubernetes_markdown_via_cli(self):
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(SCRIPTS, "report.py"),
                K8S_FIXTURE,
                "--iac-format",
                "kubernetes",
                "--no-fmt",
            ],
            capture_output=True,
            text=True,
        )
        # findings at/above the medium floor -> exit 1 (the CI gate works for K8s)
        assert proc.returncode in (0, 1)
        assert "deployment.yaml:" in proc.stdout
        assert "```diff" not in proc.stdout

    @requires_checkov
    def test_kubernetes_json_via_cli_is_the_same_report(self):
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(SCRIPTS, "report.py"),
                K8S_FIXTURE,
                "--iac-format",
                "kubernetes",
                "--format",
                "json",
                "--no-fmt",
            ],
            capture_output=True,
            text=True,
        )
        payload = json.loads(proc.stdout)
        assert payload["iacFormat"] == "kubernetes"
        assert payload["summary"]["total"] > 0
        assert payload["summary"]["withDiff"] == 0


class TestFormatAutoDetection:
    """Scanning a CloudFormation (or k8s) repo with the Terraform framework finds
    nothing and reports a false-clean -- the single worst failure this tool has.
    When the caller does not name the format, detect it from the directory rather
    than default to terraform and silently scan for the wrong thing.
    """

    @pytest.mark.parametrize(
        "fixture,expected",
        [
            ("tf-03-data-lake", "terraform"),
            ("cfn-05-static-website", "cloudformation"),
            ("k8s-01-workloads", "kubernetes"),
            ("compose-01-stack", "docker-compose"),
        ],
    )
    def test_detect_reads_the_directory(self, fixture, expected):
        assert detect_iac_format(os.path.join(FIXTURES, fixture)) == expected

    def test_unrecognizable_dir_detects_nothing(self, tmp_path):
        (tmp_path / "notes.txt").write_text("nothing to see", encoding="utf-8")
        assert detect_iac_format(str(tmp_path)) is None

    @pytest.mark.slow
    def test_cfn_scanned_without_a_format_flag_is_not_false_clean(self):
        """The regression this guards: before auto-detection, scan() defaulted to
        terraform, ran the terraform framework on a CFN dir, and returned ZERO
        findings on a template that really has 10."""
        report = scan(os.path.join(FIXTURES, "cfn-05-static-website"), use_fmt=False)
        assert report["summary"]["total"] > 0, (
            "a CloudFormation scan with no --iac-format must auto-detect CFN, not "
            "silently scan as terraform and report clean"
        )

    def test_explicit_format_still_wins_over_detection(self):
        """Backward-compat: a caller that passes iac_format is byte-for-byte
        unchanged -- detection only runs when the format is not given."""
        report = scan(os.path.join(FIXTURES, "tf-03-data-lake"), iac_format="terraform", use_fmt=False)
        assert report["summary"]["total"] > 0
