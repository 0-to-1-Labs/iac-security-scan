"""WS-7 · report.py — Markdown + JSON (SPEC §9.1).

The two invariants that matter more than the formatting:

  * **A degraded scan cannot render a report that looks clean.** Checkov missing,
    or the parser fallen off tfparse, and the user must be unable to miss it.
  * **A finding you can't patch is not a finding you hide** (§6.4).
"""

import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "skills", "iac-security-scan", "scripts")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
sys.path.insert(0, SCRIPTS)

from findings import is_quick_win  # noqa: E402
from patch_terraform import PatchChange, TerraformPatch  # noqa: E402
from report import (  # noqa: E402
    SECTION_ORDER,
    assess_degradation,
    build_report,
    derive_complexity,
    diffs_by_finding,
    is_mechanically_simple,
    render_markdown,
    scan,
    verdict_line,
)

TF_FIXTURES = [
    "tf-01-three-tier-webapp",
    "tf-02-serverless-api",
    "tf-03-data-lake",
    "tf-04-container-platform",
    "tf-05-cicd-pipeline",
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_finding(**kw):
    f = {
        "id": kw.pop("id", "finding-1"),
        "ruleId": kw.pop("ruleId", "CKV_AWS_1"),
        "title": kw.pop("title", "Something is wrong"),
        "description": "",
        "severity": kw.pop("severity", "high"),
        "exploitability": "moderate",
        "remediationComplexity": kw.pop("remediationComplexity", "moderate"),
        "priorityScore": kw.pop("priorityScore", 60),
        "isQuickWin": kw.pop("isQuickWin", False),
        "source": ["checkov"],
        "location": {
            "file": "main.tf",
            "startLine": 12,
            "endLine": 20,
            "resourceAddress": kw.pop("address", "aws_s3_bucket.data"),
            "resourceType": "aws_s3_bucket",
            "service": kw.pop("service", "s3"),
        },
    }
    f.update(kw)
    return f


def make_patch(finding_id, rule_id="CKV_AWS_1", change_type="add"):
    change = PatchChange(
        type=change_type,
        kind="attribute",
        path="acl",
        description="set acl",
        findingIds=[finding_id],
        newValue="private",
        ruleId=rule_id,
    )
    return TerraformPatch(
        file="main.tf",
        resourceType="aws_s3_bucket",
        resourceName="data",
        address="aws_s3_bucket.data",
        changes=[change],
        diff="--- a/main.tf\n+++ b/main.tf\n@@ -12,3 +12,4 @@\n+  acl = \"private\"\n",
        findingIds=[finding_id],
        ruleIds=[rule_id],
        severity="high",
        autoApplicable=True,
    )


def merged(findings, **kw):
    result = {
        "findings": findings,
        "exposureChains": [],
        "suppressionLog": [],
        "injectionAttempts": [],
        "summary": {"total": len(findings)},
    }
    result.update(kw)
    return result


CLEAN_CHECKOV = {"degraded": False, "findings": []}
CLEAN_PARSE = {"parseTier": "tfparse", "degraded": False, "resources": []}


# ---------------------------------------------------------------------------
# remediationComplexity derivation — why quick wins are not permanently empty
# ---------------------------------------------------------------------------


class TestDeriveComplexity:
    def test_raw_merge_output_yields_zero_quick_wins(self):
        """The bug WS-4 flagged: default 'moderate' + is_quick_win needs 'simple'."""
        f = make_finding(severity="critical")
        assert is_quick_win(f["severity"], f["remediationComplexity"]) is False

    def test_additive_deterministic_patch_makes_a_finding_simple(self):
        f = make_finding(severity="high")
        derive_complexity([f], [make_patch(f["id"])])
        assert f["remediationComplexity"] == "simple"
        assert f["remediationComplexitySource"] == "fix-catalog"
        assert f["isQuickWin"] is True

    def test_a_modifying_patch_is_not_simple(self):
        """Overriding a value the author chose IS the judgment call 'simple' denies."""
        f = make_finding(severity="high")
        derive_complexity([f], [make_patch(f["id"], change_type="modify")])
        assert f["remediationComplexity"] == "moderate"
        assert f["isQuickWin"] is False

    def test_no_patch_is_not_simple(self):
        f = make_finding(severity="high")
        derive_complexity([f], [])
        assert f["remediationComplexity"] == "moderate"
        assert f["isQuickWin"] is False

    def test_never_downgrades_an_explicit_llm_judgment(self):
        f = make_finding(severity="high", remediationComplexity="complex")
        derive_complexity([f], [make_patch(f["id"])])
        assert f["remediationComplexity"] == "complex"
        assert "remediationComplexitySource" not in f

    def test_medium_severity_with_a_simple_fix_is_still_not_a_quick_win(self):
        """The bar is not lowered: quick win == (critical|high) AND simple."""
        f = make_finding(severity="medium")
        derive_complexity([f], [make_patch(f["id"])])
        assert f["remediationComplexity"] == "simple"
        assert f["isQuickWin"] is False

    def test_promotion_rescores_priority(self):
        f = make_finding(severity="high", priorityScore=0)
        derive_complexity([f], [make_patch(f["id"])])
        assert f["priorityScore"] > 0

    def test_is_mechanically_simple(self):
        add = PatchChange(type="add", kind="attribute", path="a", description="")
        mod = PatchChange(type="modify", kind="attribute", path="a", description="")
        assert is_mechanically_simple([add]) is True
        assert is_mechanically_simple([add, add]) is True
        assert is_mechanically_simple([add, mod]) is False
        assert is_mechanically_simple([]) is False


# ---------------------------------------------------------------------------
# Degradation — the correctness requirement
# ---------------------------------------------------------------------------


class TestDegradationDetection:
    def test_clean_scan_is_not_degraded(self):
        assert assess_degradation(CLEAN_CHECKOV, CLEAN_PARSE)["degraded"] is False

    def test_missing_checkov_is_degraded(self):
        d = assess_degradation(
            {"degraded": True, "degradationReason": "Checkov is not installed.", "installHint": "pip install checkov"},
            CLEAN_PARSE,
        )
        assert d["degraded"] is True
        assert d["checkovDegraded"] is True
        assert d["reasons"][0]["source"] == "checkov"

    @pytest.mark.parametrize("tier", ["hcl2", "regex"])
    def test_parser_fallback_is_degraded(self, tier):
        d = assess_degradation(CLEAN_CHECKOV, {"parseTier": tier, "degraded": True})
        assert d["degraded"] is True
        assert d["parserDegraded"] is True
        assert d["patchesPossible"] is False
        # no line numbers -> no SARIF, no patches. Say it.
        assert "SARIF" in d["reasons"][0]["impact"]

    def test_both_layers_degraded_reports_both(self):
        d = assess_degradation({"degraded": True}, {"parseTier": "regex", "degraded": True})
        assert len(d["reasons"]) == 2
        assert {r["source"] for r in d["reasons"]} == {"checkov", "parser"}


class TestDegradedReportCannotLookClean:
    """THE test. A scan that found nothing because it could not read the files must
    never look like a scan that found nothing because the files were clean."""

    def _degraded_report(self, checkov=None, parse=None):
        return build_report(
            merged([]),
            checkov_result=checkov or {"degraded": True, "degradationReason": "Checkov is not installed.", "installHint": "pip install checkov==3.2.500"},
            parse_result=parse or CLEAN_PARSE,
        )

    def test_zero_finding_degraded_scan_never_renders_the_clean_verdict(self):
        clean = build_report(merged([]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE)
        degraded = self._degraded_report()

        assert clean["verdict"] == "0 findings. Clean against the rules that ran."
        assert degraded["verdict"] != clean["verdict"]
        assert "DEGRADED" in degraded["verdict"]
        assert "NOT a clean result" in degraded["verdict"]

    def test_the_word_clean_never_appears_reassuringly_in_a_degraded_report(self):
        md = render_markdown(self._degraded_report())
        assert "Clean against the rules that ran" not in md
        # every mention of "clean" in a degraded report is a denial of cleanliness
        for line in md.splitlines():
            if "clean" in line.lower():
                assert "NOT" in line or "not" in line, line

    def test_degraded_banner_is_unmissable(self):
        md = render_markdown(self._degraded_report())
        assert "⚠️ THIS WAS A DEGRADED SCAN" in md
        assert "## Degradation & scan integrity" in md
        # the flag is on the verdict line too — section 1, the line everyone reads
        assert "DEGRADED SCAN" in md.split("## Quick wins")[0]

    def test_degraded_empty_sections_do_not_read_as_reassurance(self):
        md = render_markdown(self._degraded_report())
        head = md.split("## Degradation")[0]
        assert "No critical or high findings" not in head
        assert "Every finding above is addressable" not in head
        assert head.count("Do not read this as clean.") >= 1

    def test_parser_fallback_alone_also_degrades_the_report(self):
        report = self._degraded_report(
            checkov=CLEAN_CHECKOV, parse={"parseTier": "hcl2", "degraded": True, "degradationReason": "Fell back to python-hcl2."}
        )
        md = render_markdown(report)
        assert "DEGRADED" in report["verdict"]
        assert "⚠️ THIS WAS A DEGRADED SCAN" in md
        assert "pip install tfparse" in md

    def test_a_degraded_scan_with_findings_still_flags_the_verdict(self):
        report = build_report(
            merged([make_finding()]),
            checkov_result=CLEAN_CHECKOV,
            parse_result={"parseTier": "regex", "degraded": True},
        )
        assert report["verdict"].startswith("DEGRADED SCAN")
        assert "Coverage is incomplete" in report["verdict"]

    def test_cli_exit_code_is_nonzero_on_a_degraded_scan(self, tmp_path):
        """A degraded scan is not a silent CI success."""
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')
        proc = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "report.py"), str(tmp_path), "--no-fmt"],
            capture_output=True,
            text=True,
            env={**os.environ, "CHECKOV_BIN": "/nonexistent/checkov"},
        )
        assert proc.returncode != 0
        assert "DEGRADED SCAN" in proc.stdout


class TestSuppressionSurfacing:
    """WS-4's suppressionLog: a model that tried to talk the scan out of a finding
    is something the user must see."""

    def test_suppression_requests_render_even_on_a_healthy_scan(self):
        report = build_report(
            merged(
                [make_finding()],
                suppressionLog=[{"findingId": "finding-1", "reason": "model claimed false positive"}],
            ),
            checkov_result=CLEAN_CHECKOV,
            parse_result=CLEAN_PARSE,
        )
        md = render_markdown(report)
        assert report["degradation"]["degraded"] is False
        assert "Suppression requests (1)" in md
        assert "model claimed false positive" in md
        assert "cannot be argued with" in md

    def test_injection_attempts_render(self):
        report = build_report(
            merged([make_finding()], injectionAttempts=[{"findingId": "finding-1", "reason": "instruction override in enrichment"}]),
            checkov_result=CLEAN_CHECKOV,
            parse_result=CLEAN_PARSE,
        )
        md = render_markdown(report)
        assert "Prompt-injection attempts (1)" in md

    def test_no_integrity_section_when_there_is_nothing_to_say(self):
        md = render_markdown(build_report(merged([make_finding()]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE))
        assert "## Degradation & scan integrity" not in md


# ---------------------------------------------------------------------------
# §9.1 structure
# ---------------------------------------------------------------------------


class TestSectionOrder:
    def _sections(self, md):
        return [line for line in md.splitlines() if line.startswith("## ")]

    def test_order_is_the_spec_order(self):
        report = build_report(
            merged(
                [
                    make_finding(id="f1", severity="high"),
                    make_finding(id="f2", ruleId="CKV_AWS_999", service="guardduty", title="GuardDuty is not enabled", severity="medium"),
                ],
                suppressionLog=[{"findingId": "f1", "reason": "x"}],
            ),
            checkov_result={"degraded": True, "degradationReason": "gone", "installHint": "pip install checkov"},
            parse_result=CLEAN_PARSE,
            compliance="800-53",
        )
        sections = self._sections(render_markdown(report))
        assert sections == list(SECTION_ORDER)

    def test_compliance_section_only_with_the_flag(self):
        base = merged([make_finding()])
        without = render_markdown(build_report(base, checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE))
        with_flag = render_markdown(
            build_report(base, checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE, compliance="800-53")
        )
        assert "## Compliance coverage" not in without
        assert "## Compliance coverage" in with_flag

    def test_compliance_section_declares_the_gap_and_maps_nothing(self):
        md = render_markdown(
            build_report(merged([make_finding()]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE, compliance="800-53")
        )
        block = md.split("## Compliance coverage")[1]
        assert "Not available in this build" in block
        assert "AC-" not in block and "SC-" not in block  # never a guessed control ID

    def test_verdict_is_one_line_in_the_spec_format(self):
        report = build_report(
            merged(
                [
                    make_finding(id="a", severity="critical"),
                    make_finding(id="b", severity="high"),
                    make_finding(id="c", severity="medium"),
                ]
            ),
            checkov_result=CLEAN_CHECKOV,
            parse_result=CLEAN_PARSE,
        )
        assert "\n" not in report["verdict"]
        assert report["verdict"] == "3 findings: 1 critical, 1 high, 1 medium. 0 quick wins."

    def test_verdict_counts_quick_wins(self):
        f = make_finding(severity="high")
        report = build_report(
            merged([f]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE, patches=[make_patch(f["id"])]
        )
        assert report["verdict"].endswith("1 quick win.")


class TestNonIaCSection:
    """§6.4 — the finding still appears, with the command, just no diff."""

    def test_non_iac_finding_gets_its_cli_command_and_no_diff(self):
        f = make_finding(ruleId="CKV_AWS_999", service="guardduty", title="GuardDuty is not enabled")
        report = build_report(merged([f]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE)
        md = render_markdown(report)

        assert len(report["nonIaC"]) == 1
        block = md.split("## Not fixable in IaC")[1]
        assert "aws guardduty create-detector" in block
        assert "```diff" not in block
        assert report["nonIaC"][0]["diff"] is None

    def test_non_iac_finding_is_still_ranked_in_findings_by_priority(self):
        """A finding you can't patch is not a finding you hide."""
        f = make_finding(ruleId="CKV_AWS_999", service="guardduty", title="GuardDuty is not enabled")
        md = render_markdown(build_report(merged([f]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE))
        priority_block = md.split("## Findings by priority")[1].split("## Not fixable in IaC")[0]
        assert "CKV_AWS_999" in priority_block
        assert "Not fixable in IaC" in priority_block  # cross-referenced, not dropped

    def test_console_finding_renders_numbered_steps(self):
        f = make_finding(ruleId="CKV_AWS_998", service="support", title="No Business support plan")
        md = render_markdown(build_report(merged([f]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE))
        block = md.split("## Not fixable in IaC")[1]
        assert "Support Center" in block
        assert "```bash" not in block

    def test_a_patchable_rule_is_never_routed_non_iac(self):
        f = make_finding(ruleId="CKV2_AWS_11", service="vpc", title="Ensure VPC flow logging is enabled")
        report = build_report(
            merged([f]),
            checkov_result=CLEAN_CHECKOV,
            parse_result=CLEAN_PARSE,
            patches=[make_patch(f["id"], rule_id="CKV2_AWS_11")],
        )
        assert report["nonIaC"] == []
        assert report["findings"][0]["remediationType"] == "iac"


class TestQuickWinsSection:
    def test_quick_wins_carry_diffs_inline(self):
        f = make_finding(severity="high")
        md = render_markdown(
            build_report(merged([f]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE, patches=[make_patch(f["id"])])
        )
        block = md.split("## Quick wins")[1].split("## Findings by priority")[0]
        assert "```diff" in block
        assert "acl = " in block

    def test_empty_quick_wins_explains_itself(self):
        """Silence in this section reads as 'nothing to do' — a different claim."""
        f = make_finding(severity="high")  # high, but no patch => not mechanical
        md = render_markdown(build_report(merged([f]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE))
        block = md.split("## Quick wins")[1].split("## Findings by priority")[0]
        assert "needs a judgment call" in block
        assert "1 critical/high findings" in block or "1 critical/high finding" in block


class TestFindingBlocks:
    def test_location_is_clickable_file_colon_line(self):
        md = render_markdown(build_report(merged([make_finding()]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE))
        assert "`main.tf:12`" in md

    def test_a_finding_with_no_line_says_so_rather_than_printing_zero(self):
        f = make_finding()
        f["location"]["startLine"] = 0
        md = render_markdown(
            build_report(merged([f]), checkov_result=CLEAN_CHECKOV, parse_result={"parseTier": "hcl2", "degraded": True})
        )
        assert "main.tf:0" not in md
        assert "no line -- degraded parse" in md

    def test_unenriched_finding_says_it_is_unenriched_rather_than_inventing_impact(self):
        md = render_markdown(build_report(merged([make_finding()]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE))
        assert "not enriched" in md

    def test_enriched_finding_shows_impact_and_attack_scenario(self):
        f = make_finding(businessImpact="Customer PII is exposed.", attackScenario="Attacker lists the bucket.")
        md = render_markdown(build_report(merged([f]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE))
        assert "**Impact:** Customer PII is exposed." in md
        assert "**Attack scenario:** Attacker lists the bucket." in md

    def test_unmapped_severity_is_labelled_unranked_not_low(self):
        f = make_finding(severity="unmapped", priorityScore=0)
        md = render_markdown(build_report(merged([f]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE))
        assert "unranked" in md
        assert "not the same as low risk" in md

    def test_findings_are_score_ranked(self):
        low = make_finding(id="low", priorityScore=10, severity="low")
        high = make_finding(id="high", priorityScore=90, severity="critical")
        report = build_report(merged([low, high]), checkov_result=CLEAN_CHECKOV, parse_result=CLEAN_PARSE)
        assert [f["id"] for f in report["findings"]] == ["high", "low"]

    def test_diffs_by_finding_maps_a_shared_resource_patch_to_each_finding(self):
        patch = make_patch("f1")
        patch.findingIds = ["f1", "f2"]
        mapping = diffs_by_finding([patch])
        assert mapping["f1"] == mapping["f2"] == patch.diff


# ---------------------------------------------------------------------------
# The real corpus (§9.1 acceptance)
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestAgainstFixtures:
    @pytest.mark.parametrize("fixture", TF_FIXTURES)
    def test_report_renders_in_spec_order(self, fixture):
        report = scan(os.path.join(FIXTURES, fixture), use_fmt=False)
        md = render_markdown(report)
        sections = [line for line in md.splitlines() if line.startswith("## ")]
        expected = [s for s in SECTION_ORDER if s != "## Compliance coverage"]
        assert sections == [s for s in expected if s in sections]
        assert sections[:4] == list(SECTION_ORDER[:4])
        assert report["degradation"]["degraded"] is False
        assert report["summary"]["total"] > 0

    @pytest.mark.parametrize("fixture", TF_FIXTURES)
    def test_findings_with_a_deterministic_fix_carry_a_diff(self, fixture):
        report = scan(os.path.join(FIXTURES, fixture), use_fmt=False)
        assert report["summary"]["withDiff"] > 0
        assert report["filePatches"]

    @pytest.mark.parametrize("fixture", ["tf-01-three-tier-webapp", "tf-04-container-platform", "tf-05-cicd-pipeline"])
    def test_quick_wins_are_non_empty(self, fixture):
        """Honestly non-empty: a high/critical finding with an additive catalog patch.

        tf-02 and tf-03 are deliberately absent. Their only high findings are IAM
        wildcard-policy findings (CKV_AWS_287/288/289/290/355), whose fix is a
        usage-analysis decision, not a mechanical patch. See
        ``test_tf02_tf03_have_no_honest_quick_wins`` — the section is empty there
        because it is *true* that there is nothing to fix before lunch, and the
        report says so in words rather than padding the list.
        """
        report = scan(os.path.join(FIXTURES, fixture), use_fmt=False)
        assert report["quickWins"], "expected at least one honest quick win"
        for win in report["quickWins"]:
            assert win["severity"] in ("critical", "high")
            assert win["remediationComplexity"] == "simple"
            assert win["diff"], "a quick win with no diff is not a quick win"
        assert "```diff" in render_markdown(report).split("## Quick wins")[1].split("## Findings")[0]

    @pytest.mark.parametrize("fixture", ["tf-02-serverless-api", "tf-03-data-lake"])
    def test_tf02_tf03_have_no_honest_quick_wins(self, fixture):
        """Pins the honest gap so nobody 'fixes' it by lowering the bar.

        If a future fix-catalog rule makes one of these mechanically patchable,
        this test fails and should be MOVED to the list above — not deleted.
        """
        report = scan(os.path.join(FIXTURES, fixture), use_fmt=False)
        high = [f for f in report["findings"] if f["severity"] in ("critical", "high")]
        assert high, "the fixture does have high findings"
        assert all(f["ruleId"].startswith("CKV_AWS_28") or f["ruleId"] in ("CKV_AWS_290", "CKV_AWS_355") for f in high)
        assert report["quickWins"] == []
        block = render_markdown(report).split("## Quick wins")[1].split("## Findings by priority")[0]
        assert "needs a judgment call" in block

    def test_killing_checkov_degrades_a_real_fixture_scan(self, monkeypatch):
        monkeypatch.setenv("CHECKOV_BIN", "/nonexistent/checkov")
        report = scan(os.path.join(FIXTURES, "tf-01-three-tier-webapp"), use_fmt=False)
        md = render_markdown(report)
        assert report["degradation"]["checkovDegraded"] is True
        assert report["summary"]["total"] == 0
        assert "⚠️ THIS WAS A DEGRADED SCAN" in md
        assert "NOT a clean result" in report["verdict"]

    def test_forcing_hcl2_degrades_a_real_fixture_scan(self, monkeypatch):
        monkeypatch.setenv("IAC_PARSER_FORCE_TIER", "hcl2")
        report = scan(os.path.join(FIXTURES, "tf-01-three-tier-webapp"), use_fmt=False)
        md = render_markdown(report)
        assert report["degradation"]["parserDegraded"] is True
        assert report["degradation"]["patchesPossible"] is False
        # no line numbers -> no patches at all, and the report must not pretend
        assert report["filePatches"] == []
        assert report["summary"]["withDiff"] == 0
        assert "⚠️ THIS WAS A DEGRADED SCAN" in md
        assert "DEGRADED SCAN" in report["verdict"]

    def test_non_iac_findings_appear_with_steps_and_no_diff(self):
        report = scan(os.path.join(FIXTURES, "tf-04-container-platform"), use_fmt=False)
        assert report["nonIaC"], "tf-04 plants a VPC-flow-logs finding (CKV2_AWS_11)"
        block = render_markdown(report).split("## Not fixable in IaC")[1]
        assert "```diff" not in block
        assert "aws ec2 create-flow-logs" in block
        for f in report["nonIaC"]:
            assert f["diff"] is None
            assert f["remediationSteps"]

    def test_json_format_is_the_same_report(self):
        report = scan(os.path.join(FIXTURES, "tf-01-three-tier-webapp"), use_fmt=False)
        import json

        round_tripped = json.loads(json.dumps(report, default=str))
        assert round_tripped["verdict"] == report["verdict"]
        assert len(round_tripped["findings"]) == len(report["findings"])
