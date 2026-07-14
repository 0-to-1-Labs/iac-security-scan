#!/usr/bin/env python3
"""WS-12: the CloudFormation detection-recall harness.

The Terraform sibling (test_regression_harness.py) measures deterministic recall
against a checked-in answer key. This does the same for the 25 planted
CloudFormation flaws (CFN-01..CFN-05), graded against tests/data/answer-key-cfn.json.

Governance is identical to the Terraform key and non-negotiable:
  * A flaw is DETECTED only if a real finding fires with one of its mapped rule
    IDs in the stated file. All CFN flaws live in template.yaml.
  * A flaw Checkov cannot catch is recorded with a `missReason` and
    `requiresLlmLayer: true` -- never hidden, never relaxed to flatter the number.
  * Recall is a number we REPORT, printed every run.

WHY CFN RECALL IS 14/25 AND NOT HIGHER
--------------------------------------
Eleven of the twenty-five planted flaws are invisible to Checkov's CloudFormation
+ secrets frameworks. Four of those eleven are the confidently-wrong shape that is
the whole thesis of the hybrid design: Checkov EVALUATED the flawed resource and
placed the check in passed_checks --

  * CFN-02-3  SageMaker exec role, service-wildcard S3 -> CKV_AWS_107..111 PASSED
  * CFN-03-3  S3 bucket default encryption            -> CKV_AWS_19 PASSED
  * CFN-05-5  S3 public read via a separate BucketPolicy -> CKV_AWS_20/53-56 PASSED
  * CFN-02-1  SageMaker notebook internet access       -> only unrelated rules fire

The other seven are structural gaps with no CloudFormation rule at all (IoT policy
wildcards, EBS-inline encryption, SQS/EventBridge DLQ, Firehose SSE, plaintext
parameter credentials). All eleven are what the iac-security-analyst LLM pass is FOR.

Pinned to checkov==3.2.500. The framework set is cloudformation + secrets
(run_checkov.frameworks_for_format("cloudformation")); a CloudFormation scan run
under --framework terraform finds nothing.
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
ANSWER_KEY = os.path.join(ROOT, "tests", "data", "answer-key-cfn.json")
sys.path.insert(0, SCRIPTS)

import run_checkov  # noqa: E402

PINNED_CHECKOV = "3.2.500"

FIXTURE_NAMES = [
    "cfn-01-wordpress-ec2-rds",
    "cfn-02-ml-platform",
    "cfn-03-iot-ingestion",
    "cfn-04-event-driven",
    "cfn-05-static-website",
]

TOTAL_FLAWS = 25
EXPECTED_DETECTABLE = 14
EXPECTED_LLM_ONLY = 11


def load_key():
    with open(ANSWER_KEY, encoding="utf-8") as fh:
        return json.load(fh)


ANSWERS = load_key()
ALL_FLAWS = [(fixture, flaw) for fixture in FIXTURE_NAMES for flaw in ANSWERS[fixture]]
DETECTABLE = [(f, x) for f, x in ALL_FLAWS if x["detectedBy"]]
LLM_ONLY = [(f, x) for f, x in ALL_FLAWS if not x["detectedBy"]]


def checkov_installed():
    return run_checkov.find_checkov() is not None


requires_checkov = pytest.mark.skipif(
    not checkov_installed(), reason="checkov not installed"
)


@pytest.fixture(scope="module")
def scans():
    """One CloudFormation-framework Checkov pass per fixture, reused. Checkov is slow."""
    frameworks = run_checkov.frameworks_for_format("cloudformation")
    return {
        name: run_checkov.run_checkov(os.path.join(FIXTURES, name), frameworks)[
            "findings"
        ]
        for name in FIXTURE_NAMES
    }


# ===========================================================================
# Level 0 -- the harness's own footing
# ===========================================================================


class TestHarnessFooting:
    def test_checkov_is_pinned(self):
        out = subprocess.run(
            ["checkov", "--version"], capture_output=True, text=True
        )
        assert out.stdout.strip() == PINNED_CHECKOV, (
            f"answer key was graded against checkov {PINNED_CHECKOV}, found "
            f"{out.stdout.strip()}. Re-grade the key before trusting recall."
        )

    def test_answer_key_covers_all_25_planted_cfn_flaws(self):
        assert len(ALL_FLAWS) == TOTAL_FLAWS
        assert len(DETECTABLE) == EXPECTED_DETECTABLE
        assert len(LLM_ONLY) == EXPECTED_LLM_ONLY

    def test_every_llm_only_flaw_states_why_it_escapes(self):
        """A miss without a reason is a miss nobody will ever fix."""
        for _fixture, flaw in LLM_ONLY:
            assert flaw.get("missReason"), f"{flaw['id']} has no missReason"
            assert flaw.get("requiresLlmLayer") is True

    def test_all_flaws_are_located_in_template_yaml(self):
        for _fixture, flaw in ALL_FLAWS:
            assert flaw["file"] == "template.yaml"


# ===========================================================================
# Level 1 -- DETECTION. The recall number.
# ===========================================================================


class TestDetectionRecall:
    @requires_checkov
    @pytest.mark.parametrize(
        "fixture,flaw", DETECTABLE, ids=[x["id"] for _f, x in DETECTABLE]
    )
    def test_planted_flaw_is_detected(self, fixture, flaw, scans):
        """A regression here is a HARD FAILURE: we stopped finding a real flaw."""
        hits = [
            f
            for f in scans[fixture]
            if f["ruleId"] in flaw["detectedBy"]
            and f["location"]["file"] == flaw["file"]
        ]
        assert hits, (
            f"{flaw['id']} NOT DETECTED: {flaw['flaw']}\n"
            f"  expected one of {flaw['detectedBy']} in {flaw['file']}\n"
            f"  This flaw was detected when the key was graded. We have regressed."
        )

    @requires_checkov
    @pytest.mark.parametrize(
        "fixture,flaw", LLM_ONLY, ids=[x["id"] for _f, x in LLM_ONLY]
    )
    def test_known_checkov_blind_spot_is_still_blind(self, fixture, flaw, scans):
        """If Checkov ever starts catching one of these, that is GOOD NEWS -- and
        this test fails loudly so the answer key gets promoted rather than quietly
        crediting a now-deterministic flaw to the LLM layer."""
        hits = [f for f in scans[fixture] if f["location"]["file"] == flaw["file"]]
        by_rule = {f["ruleId"] for f in hits}
        assert not (by_rule & set(flaw.get("detectedBy") or [])), (
            f"{flaw['id']}: checkov now detects this. Promote it in answer-key-cfn.json."
        )

    @requires_checkov
    def test_recall_is_reported_as_a_number(self, scans, capsys):
        found, missed = [], []
        for fixture, flaw in DETECTABLE:
            hits = [
                f
                for f in scans[fixture]
                if f["ruleId"] in flaw["detectedBy"]
                and f["location"]["file"] == flaw["file"]
            ]
            (found if hits else missed).append(flaw["id"])

        pct = 100.0 * len(found) / TOTAL_FLAWS
        with capsys.disabled():
            print(
                f"\n\n  CFN DETECTION RECALL (deterministic layer, checkov {PINNED_CHECKOV})"
            )
            print(f"     {len(found)}/{TOTAL_FLAWS} planted CloudFormation flaws = {pct:.0f}%")
            print(f"     {len(LLM_ONLY)}/{TOTAL_FLAWS} require the LLM layer:")
            for _f, flaw in LLM_ONLY:
                tag = "EVALUATED-AND-PASSED" if "EVALUATED-AND-PASSED" in (
                    flaw.get("missReason") or ""
                ) else "no rule"
                print(f"        {flaw['id']}  [{tag}]  {flaw['flaw']}")
            if missed:
                print(f"     REGRESSION -- detected when graded, now missing: {missed}")
            print()

        assert not missed, f"detection regression on {missed}"
        assert len(found) == EXPECTED_DETECTABLE


# ===========================================================================
# Level 2 -- the adapter routes CFN correctly and finds things
# ===========================================================================


class TestFrameworkRouting:
    def test_cloudformation_routes_to_the_cloudformation_framework(self):
        assert run_checkov.frameworks_for_format("cloudformation") == (
            "cloudformation",
            "secrets",
        )

    def test_unknown_format_falls_back_to_terraform_default(self):
        assert run_checkov.frameworks_for_format(None) == run_checkov.DEFAULT_FRAMEWORKS
        assert run_checkov.frameworks_for_format("nope") == run_checkov.DEFAULT_FRAMEWORKS

    @requires_checkov
    def test_cfn_scan_returns_findings_on_every_fixture(self, scans):
        counts = {name: len(scans[name]) for name in FIXTURE_NAMES}
        total = sum(counts.values())
        for name, n in counts.items():
            assert n > 0, f"{name}: cloudformation scan returned zero findings"
        # Corpus total is a pinned expectation (guards a silent framework revert).
        assert total == 66, counts

    @requires_checkov
    def test_cfn_paths_are_repo_relative(self, scans):
        for name in FIXTURE_NAMES:
            for f in scans[name]:
                path = f["location"]["file"]
                assert path and not path.startswith("/") and not path.startswith("./")
                assert os.path.isfile(os.path.join(FIXTURES, name, path)), path
