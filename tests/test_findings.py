"""WS-3 tests: the trust core.

Covers the severity resolution chain, priorityScore, isQuickWin, finding-ID
generation, and -- the one that matters most -- that an unmapped rule resolves to
the explicit ``unmapped`` sentinel and is NEVER quietly defaulted to a middle
severity.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "skills", "iac-security-scan", "scripts")
DATA = os.path.join(REPO_ROOT, "skills", "iac-security-scan", "data")
FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")
sys.path.insert(0, SCRIPTS)

from findings import (  # noqa: E402
    COMPLEXITY_MULTIPLIER,
    EXPLOITABILITY_MULTIPLIER,
    SEVERITIES,
    SEVERITY_WEIGHT,
    UNMAPPED,
    Finding,
    Location,
    SeverityAdjustmentError,
    SeverityMap,
    adjust_severity,
    build_finding,
    generate_finding_id,
    is_quick_win,
    priority_score,
)

SEVERITY_MAP_PATH = os.path.join(DATA, "rule-severity.json")


@pytest.fixture(scope="session")
def severity_map() -> SeverityMap:
    return SeverityMap.load(SEVERITY_MAP_PATH)


@pytest.fixture(scope="session")
def raw_severity_map() -> dict:
    with open(SEVERITY_MAP_PATH, encoding="utf-8") as fh:
        data = json.load(fh)
    return {k: v for k, v in data.items() if not k.startswith(("_", "$"))}


def loc(**kw) -> Location:
    base = dict(
        file="s3.tf",
        startLine=1,
        endLine=10,
        resourceAddress="aws_s3_bucket.data_lake",
        resourceType="aws_s3_bucket",
        service="s3",
    )
    base.update(kw)
    return Location(**base)


# ---------------------------------------------------------------------------
# The gate: unmapped is explicit, never a defaulted middle value
# ---------------------------------------------------------------------------


class TestUnmappedIsNeverDefaulted:
    """THE governance test. If this ever goes green-by-relaxation, the product lies."""

    def test_unknown_rule_resolves_to_unmapped_sentinel(self, severity_map):
        seed = severity_map.resolve("CKV_AWS_DOES_NOT_EXIST_9999")
        assert seed.severity == UNMAPPED
        assert seed.is_mapped is False
        assert seed.source == "none"
        assert seed.rationale  # states plainly why, for the report

    def test_unmapped_is_never_a_middle_severity(self, severity_map):
        """The failure mode we are defending against: a silent default to 'medium'."""
        seed = severity_map.resolve("CKV_AWS_NOT_SEEDED")
        assert seed.severity not in SEVERITIES
        assert seed.severity != "medium"
        assert seed.severity == UNMAPPED

    def test_unmapped_finding_scores_zero_and_is_not_a_quick_win(self, severity_map):
        f = build_finding(
            rule_id="CKV_AWS_NOT_SEEDED",
            title="Some unseeded rule",
            location=loc(),
            severity_map=severity_map,
            exploitability="trivial",
            remediation_complexity="simple",
        )
        assert f.severity == UNMAPPED
        assert f.is_unmapped is True
        # Unranked, not "low risk". Zero means "we do not know", and the reporter
        # must present it as unmapped rather than sorting it to the bottom as fact.
        assert f.priorityScore == 0
        assert f.isQuickWin is False

    def test_llm_cannot_invent_a_severity_for_an_unmapped_rule(self, severity_map):
        """The model may ADJUST a real seed. It may not CREATE one."""
        seed = severity_map.resolve("CKV_AWS_NOT_SEEDED")
        with pytest.raises(SeverityAdjustmentError, match="cannot adjust an unmapped rule"):
            adjust_severity(seed, "critical", "It looks scary to me.")

    def test_priority_score_of_unmapped_severity_is_zero(self):
        assert priority_score(UNMAPPED, "trivial", "simple") == 0

    def test_is_quick_win_false_for_unmapped(self):
        assert is_quick_win(UNMAPPED, "simple") is False


# ---------------------------------------------------------------------------
# The severity map itself
# ---------------------------------------------------------------------------


class TestSeverityMapData:
    def test_every_rule_firing_on_the_corpus_is_seeded(self, severity_map):
        """Acceptance: every rule the scanner actually emits resolves to a real seed.

        Uses the checked-in expectation of the 56 firing rule IDs. If Checkov's rule
        set moves and a new rule fires, this test must fail loudly rather than let an
        unseeded rule reach a user's report.
        """
        for rule_id in FIRING_RULES_ON_CORPUS:
            seed = severity_map.resolve(rule_id)
            assert seed.is_mapped, f"{rule_id} fires on the corpus but has no seed"
            assert seed.severity in SEVERITIES
            assert seed.rationale, f"{rule_id} has no rationale -- unauditable"

    def test_all_severities_are_valid(self, raw_severity_map):
        for rule_id, entry in raw_severity_map.items():
            assert entry["severity"] in SEVERITIES, rule_id

    def test_all_sources_are_declared_and_valid(self, raw_severity_map):
        for rule_id, entry in raw_severity_map.items():
            assert entry["source"] in (
                "checkov-metadata",
                "prowler",
                "curated",
                "gate1-reviewed",
            ), rule_id

    def test_gate1_reviewed_rules_record_what_they_overrode(self, raw_severity_map):
        """A human override is the strongest authority in the file, so it must show
        its work: what the severity was before, and why it moved."""
        for rule_id, entry in raw_severity_map.items():
            if entry["source"] == "gate1-reviewed":
                assert "severityBefore" in entry, f"{rule_id} overrode a seed silently"
                assert "GATE 1" in entry["rationale"], rule_id

    def test_every_rule_has_a_rationale_a_human_can_audit(self, raw_severity_map):
        for rule_id, entry in raw_severity_map.items():
            assert entry.get("rationale", "").strip(), f"{rule_id} has no rationale"

    def test_prowler_sourced_rules_name_the_prowler_check(self, raw_severity_map):
        """A 'prowler' source claims an authority; the rationale must name it so a
        reviewer can verify the concept match rather than take it on faith."""
        for rule_id, entry in raw_severity_map.items():
            if entry["source"] == "prowler":
                assert "Prowler:" in entry["rationale"] or "Prowler " in entry["rationale"], (
                    f"{rule_id} claims source=prowler but does not name the check"
                )

    def test_rule_ids_are_well_formed(self, raw_severity_map):
        for rule_id in raw_severity_map:
            assert rule_id.startswith(("CKV_AWS_", "CKV2_AWS_", "IACSEC-")), rule_id

    def test_map_is_not_writable_at_runtime(self, severity_map):
        """There is no API to add a seed. Resolution is read-only, by construction."""
        assert not hasattr(severity_map, "add")
        assert not hasattr(severity_map, "set")
        assert not hasattr(severity_map, "__setitem__")


# ---------------------------------------------------------------------------
# Severity resolution chain
# ---------------------------------------------------------------------------


class TestSeverityResolutionChain:
    def test_seed_is_applied_from_the_checked_in_map(self, severity_map):
        f = build_finding(
            rule_id="CKV_AWS_18",
            title="S3 bucket has no access logging configured",
            location=loc(),
            severity_map=severity_map,
        )
        assert f.severity == "medium"
        assert f.severitySource == "prowler"
        assert f.severityAdjustedFrom is None

    def test_llm_may_adjust_one_level_up_with_a_reason(self, severity_map):
        seed = severity_map.resolve("CKV_AWS_18")  # medium
        f = build_finding(
            rule_id="CKV_AWS_18",
            title="S3 access logging",
            location=loc(resourceAddress="aws_s3_bucket.phi_backups"),
            severity_map=severity_map,
        )
        f.apply_severity_adjustment(seed, "high", "Bucket is named phi-backups; PHI at rest.")
        assert f.severity == "high"
        assert f.severityAdjustedFrom == "medium"
        assert "phi" in f.severityAdjustmentReason.lower()

    def test_llm_may_adjust_one_level_down(self, severity_map):
        seed = severity_map.resolve("CKV_AWS_18")  # medium
        out = adjust_severity(seed, "low", "Bucket holds only public website assets.")
        assert out["severity"] == "low"
        assert out["severityAdjustedFrom"] == "medium"

    def test_adjustment_is_capped_at_one_level(self, severity_map):
        seed = severity_map.resolve("CKV_AWS_20")  # critical
        with pytest.raises(SeverityAdjustmentError, match="cap is 1"):
            adjust_severity(seed, "low", "I think this is fine actually.")

    def test_adjustment_requires_a_written_justification(self, severity_map):
        seed = severity_map.resolve("CKV_AWS_18")
        with pytest.raises(SeverityAdjustmentError, match="written justification"):
            adjust_severity(seed, "high", "   ")

    def test_adjustment_rejects_a_bogus_severity(self, severity_map):
        seed = severity_map.resolve("CKV_AWS_18")
        with pytest.raises(SeverityAdjustmentError, match="invalid severity"):
            adjust_severity(seed, "extremely-bad", "reason")

    def test_adjustment_rescores_priority(self, severity_map):
        seed = severity_map.resolve("CKV_AWS_18")  # medium
        f = build_finding(
            rule_id="CKV_AWS_18",
            title="t",
            location=loc(),
            severity_map=severity_map,
            exploitability="complex",
            remediation_complexity="simple",
        )
        assert f.priorityScore == 90  # medium: 60 * 1.0 * 1.5
        assert f.isQuickWin is False  # medium is never a quick win
        f.apply_severity_adjustment(seed, "high", "Sensitive data.")
        assert f.priorityScore == 100  # high: 80 * 1.0 * 1.5 = 120 -> clamped
        assert f.isQuickWin is True  # high + simple


# ---------------------------------------------------------------------------
# priorityScore -- ported verbatim from assessment.ts:1970-2011
# ---------------------------------------------------------------------------


class TestPriorityScore:
    def test_weights_match_the_ported_source(self):
        assert SEVERITY_WEIGHT == {
            "critical": 100,
            "high": 80,
            "medium": 60,
            "low": 40,
            "informational": 20,
        }
        assert EXPLOITABILITY_MULTIPLIER == {
            "trivial": 1.5,
            "moderate": 1.2,
            "complex": 1.0,
            "theoretical": 0.8,
        }
        assert COMPLEXITY_MULTIPLIER == {"simple": 1.5, "moderate": 1.0, "complex": 0.7}

    @pytest.mark.parametrize(
        "severity,exploitability,complexity,expected",
        [
            # 100 * 1.5 * 1.5 = 225 -> clamped to 100
            ("critical", "trivial", "simple", 100),
            # 80 * 1.2 * 1.0 = 96
            ("high", "moderate", "moderate", 96),
            # 60 * 1.0 * 0.7 = 42
            ("medium", "complex", "complex", 42),
            # 40 * 0.8 * 1.0 = 32
            ("low", "theoretical", "moderate", 32),
            # 20 * 0.8 * 0.7 = 11.2 -> 11
            ("informational", "theoretical", "complex", 11),
            # 60 * 1.2 * 1.5 = 108 -> clamped to 100
            ("medium", "moderate", "simple", 100),
            # 40 * 1.0 * 0.7 = 28
            ("low", "complex", "complex", 28),
        ],
    )
    def test_formula(self, severity, exploitability, complexity, expected):
        assert priority_score(severity, exploitability, complexity) == expected

    def test_clamped_to_0_100(self):
        assert priority_score("critical", "trivial", "simple") == 100
        assert priority_score("informational", "theoretical", "complex") >= 0

    def test_cheap_fixes_rank_up(self):
        """The complexity multiplier deliberately promotes cheap fixes -- a simple fix
        for a high finding must outrank a complex fix for the same finding."""
        simple = priority_score("high", "moderate", "simple")
        complex_ = priority_score("high", "moderate", "complex")
        assert simple > complex_

    def test_critical_resource_boost_is_15(self):
        base = priority_score("medium", "complex", "complex")  # 42
        boosted = priority_score(
            "medium", "complex", "complex", affects_critical_resource=True
        )
        assert boosted == base + 15

    def test_public_facing_boost_is_10(self):
        base = priority_score("medium", "complex", "complex")  # 42
        boosted = priority_score("medium", "complex", "complex", is_public_facing=True)
        assert boosted == base + 10

    def test_boosts_stack_and_clamp(self):
        assert (
            priority_score(
                "medium",
                "complex",
                "complex",
                affects_critical_resource=True,
                is_public_facing=True,
            )
            == 42 + 15 + 10
        )
        assert (
            priority_score(
                "critical",
                "trivial",
                "simple",
                affects_critical_resource=True,
                is_public_facing=True,
            )
            == 100
        )

    def test_verification_confirmed_boosts_15(self):
        base = priority_score("medium", "complex", "complex")  # 42
        assert priority_score("medium", "complex", "complex", verification="confirmed") == base + 15

    def test_verification_not_deployed_penalizes_20(self):
        base = priority_score("medium", "complex", "complex")  # 42
        assert (
            priority_score("medium", "complex", "complex", verification="not-deployed")
            == base - 20
        )

    def test_not_deployed_penalty_floors_at_zero(self):
        assert (
            priority_score("informational", "theoretical", "complex", verification="not-deployed")
            == 0
        )

    def test_static_only_verification_is_neutral(self):
        assert priority_score("high", "moderate", "simple", verification="static-only") == (
            priority_score("high", "moderate", "simple")
        )

    def test_threat_score_blends_70_30_when_present(self):
        # base = 60*1.0*0.7 = 42 -> 42*0.7 + 100*0.3 = 29.4 + 30 = 59.4 -> 59
        assert priority_score("medium", "complex", "complex", threat_score=100) == 59

    def test_threat_score_absent_in_static_scans(self):
        assert priority_score("medium", "complex", "complex", threat_score=None) == 42

    def test_rejects_unknown_exploitability(self):
        with pytest.raises(ValueError, match="exploitability"):
            priority_score("high", "impossible", "simple")

    def test_rejects_unknown_complexity(self):
        with pytest.raises(ValueError, match="remediationComplexity"):
            priority_score("high", "trivial", "trivial")


# ---------------------------------------------------------------------------
# isQuickWin
# ---------------------------------------------------------------------------


class TestIsQuickWin:
    @pytest.mark.parametrize("severity", ["critical", "high"])
    def test_high_severity_and_simple_is_a_quick_win(self, severity):
        assert is_quick_win(severity, "simple") is True

    @pytest.mark.parametrize("severity", ["medium", "low", "informational", UNMAPPED])
    def test_lower_severity_is_never_a_quick_win(self, severity):
        assert is_quick_win(severity, "simple") is False

    @pytest.mark.parametrize("complexity", ["moderate", "complex"])
    def test_non_simple_fix_is_never_a_quick_win(self, complexity):
        assert is_quick_win("critical", complexity) is False

    def test_finding_computes_quick_win_on_build(self, severity_map):
        f = build_finding(
            rule_id="CKV_AWS_24",  # high: SSH open to the world
            title="SG allows 0.0.0.0/0 to port 22",
            location=loc(resourceType="aws_security_group", service="ec2"),
            severity_map=severity_map,
            remediation_complexity="simple",
        )
        assert f.severity == "high"
        assert f.isQuickWin is True


# ---------------------------------------------------------------------------
# Finding ID
# ---------------------------------------------------------------------------


class TestFindingId:
    def test_format_and_length(self):
        fid = generate_finding_id("CKV_AWS_18", "s3.tf", "aws_s3_bucket.data_lake")
        assert fid.startswith("finding-")
        assert len(fid) == len("finding-") + 16

    def test_matches_the_spec_hash(self):
        import hashlib

        expected = (
            "finding-"
            + hashlib.sha256(b"CKV_AWS_18:s3.tf:aws_s3_bucket.data_lake").hexdigest()[:16]
        )
        assert generate_finding_id("CKV_AWS_18", "s3.tf", "aws_s3_bucket.data_lake") == expected

    def test_is_deterministic(self):
        a = generate_finding_id("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")
        b = generate_finding_id("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")
        assert a == b

    @pytest.mark.parametrize(
        "args",
        [
            ("CKV_AWS_21", "s3.tf", "aws_s3_bucket.x"),  # different rule
            ("CKV_AWS_18", "other.tf", "aws_s3_bucket.x"),  # different file
            ("CKV_AWS_18", "s3.tf", "aws_s3_bucket.y"),  # different resource
        ],
    )
    def test_each_component_changes_the_id(self, args):
        base = generate_finding_id("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")
        assert generate_finding_id(*args) != base

    def test_finding_derives_its_own_id(self, severity_map):
        f = build_finding(
            rule_id="CKV_AWS_18", title="t", location=loc(), severity_map=severity_map
        )
        assert f.id == generate_finding_id("CKV_AWS_18", "s3.tf", "aws_s3_bucket.data_lake")

    def test_two_rules_on_one_resource_are_distinct_findings(self, severity_map):
        a = build_finding(rule_id="CKV_AWS_18", title="t", location=loc(), severity_map=severity_map)
        b = build_finding(rule_id="CKV_AWS_21", title="t", location=loc(), severity_map=severity_map)
        assert a.id != b.id


# ---------------------------------------------------------------------------
# The schema inversion (SPEC §5)
# ---------------------------------------------------------------------------


class TestSchemaInversion:
    def test_location_is_required(self):
        with pytest.raises(TypeError):
            Finding(ruleId="CKV_AWS_18", title="t")  # type: ignore[call-arg]

    def test_location_must_be_a_location(self):
        with pytest.raises(TypeError, match="must be a Location"):
            Finding(ruleId="CKV_AWS_18", title="t", location={"file": "s3.tf"})  # type: ignore[arg-type]

    def test_location_rejects_an_empty_file(self):
        with pytest.raises(ValueError, match="location.file is required"):
            loc(file="")

    def test_location_rejects_an_empty_resource_address(self):
        with pytest.raises(ValueError, match="resourceAddress is required"):
            loc(resourceAddress="")

    def test_arn_account_and_region_are_optional_and_null_in_static_scans(self, severity_map):
        f = build_finding(
            rule_id="CKV_AWS_18", title="t", location=loc(), severity_map=severity_map
        )
        assert f.resourceArn is None
        assert f.accountId is None
        assert f.region is None
        assert f.verification == "static-only"

    def test_service_is_derived_from_resource_type(self):
        assert Location.service_from_resource_type("aws_s3_bucket") == "s3"
        assert Location.service_from_resource_type("aws_cloudwatch_log_group") == "cloudwatch"
        assert Location.service_from_resource_type("aws_lambda_function") == "lambda"

    def test_serialized_finding_carries_the_full_contract(self, severity_map):
        d = build_finding(
            rule_id="CKV_AWS_18", title="t", location=loc(), severity_map=severity_map
        ).to_dict()
        for key in (
            "id",
            "ruleId",
            "title",
            "location",
            "severity",
            "exploitability",
            "remediationComplexity",
            "priorityScore",
            "isQuickWin",
            "remediationType",
            "autoApplicable",
            "verification",
            "resourceArn",
        ):
            assert key in d, f"{key} missing from the serialized finding"
        for key in ("file", "startLine", "endLine", "resourceAddress", "resourceType", "service"):
            assert key in d["location"]


# ---------------------------------------------------------------------------
# Corpus acceptance: no rule the scanner emits may be unmapped
# ---------------------------------------------------------------------------

# The 56 rule IDs that fire across tests/fixtures/tf-01..tf-05 (158 findings),
# measured with checkov 3.2.500. Checked in so that a Checkov upgrade that
# introduces a new rule fails this suite instead of silently shipping an unmapped
# finding to a user.
FIRING_RULES_ON_CORPUS = [
    "CKV2_AWS_11", "CKV2_AWS_12", "CKV2_AWS_20", "CKV2_AWS_28", "CKV2_AWS_31",
    "CKV2_AWS_51", "CKV2_AWS_53", "CKV2_AWS_62", "CKV2_AWS_69", "CKV2_AWS_71",
    "CKV2_AWS_77", "CKV_AWS_103", "CKV_AWS_115", "CKV_AWS_116", "CKV_AWS_117",
    "CKV_AWS_119", "CKV_AWS_120", "CKV_AWS_130", "CKV_AWS_131", "CKV_AWS_136",
    "CKV_AWS_144", "CKV_AWS_145", "CKV_AWS_147", "CKV_AWS_150", "CKV_AWS_158",
    "CKV_AWS_159", "CKV_AWS_16", "CKV_AWS_161", "CKV_AWS_163", "CKV_AWS_173",
    "CKV_AWS_18", "CKV_AWS_195", "CKV_AWS_2", "CKV_AWS_21", "CKV_AWS_219",
    "CKV_AWS_225", "CKV_AWS_237", "CKV_AWS_26", "CKV_AWS_260", "CKV_AWS_272",
    "CKV_AWS_276", "CKV_AWS_287", "CKV_AWS_288", "CKV_AWS_289", "CKV_AWS_290",
    "CKV_AWS_293", "CKV_AWS_300", "CKV_AWS_316", "CKV_AWS_338", "CKV_AWS_354",
    "CKV_AWS_355", "CKV_AWS_378", "CKV_AWS_51", "CKV_AWS_76", "CKV_AWS_79",
    "CKV_AWS_91",
]


def test_firing_rule_list_is_the_measured_56():
    assert len(FIRING_RULES_ON_CORPUS) == 56
    assert len(set(FIRING_RULES_ON_CORPUS)) == 56


@pytest.mark.slow
def test_live_checkov_run_emits_no_unmapped_rule(severity_map):
    """End-to-end acceptance against the real corpus with the real Checkov.

    Skipped when checkov is not installed. This is the test that would catch a
    Checkov rule-set drift introducing a rule we have never reviewed.
    """
    if subprocess.run(["which", "checkov"], capture_output=True).returncode != 0:
        pytest.skip("checkov not installed")

    firing = set()
    for name in sorted(os.listdir(FIXTURES)):
        if not name.startswith("tf-0"):
            continue
        proc = subprocess.run(
            ["checkov", "-d", os.path.join(FIXTURES, name), "--output", "json",
             "--compact", "--quiet"],
            capture_output=True,
            text=True,
        )
        if not proc.stdout.strip():
            continue
        data = json.loads(proc.stdout)
        for block in data if isinstance(data, list) else [data]:
            if block.get("check_type") != "terraform":
                continue
            for check in block["results"]["failed_checks"]:
                firing.add(check["check_id"])
                # Checkov community edition never populates severity. If this ever
                # becomes non-None, we have a new authority and should use it.
                assert check.get("severity") is None

    unmapped = sorted(r for r in firing if not severity_map.resolve(r).is_mapped)
    assert not unmapped, f"rules fire on the corpus with no seeded severity: {unmapped}"
