"""WS-7 · classify.py — the deterministic non-IaC triage (SPEC §6.4).

The catalog is a verbatim port of infrabot's classification-patterns.ts:33-310.
These tests pin the port (group sizes, categories, match order) so a later edit
that "improves" a pattern has to do it deliberately.
"""

import os
import sys

import pytest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "skills",
        "iac-security-scan",
        "scripts",
    ),
)

from classify import (  # noqa: E402
    ACCOUNT_LEVEL_PATTERNS,
    ALL_PATTERNS,
    CONSOLE_ONLY_PATTERNS,
    MANUAL_REVIEW_PATTERNS,
    NON_IAC_CATEGORIES,
    ONE_TIME_CONFIG_PATTERNS,
    ORGANIZATIONAL_PATTERNS,
    REMEDIATION_STEPS,
    SERVICE_ENABLEMENT_PATTERNS,
    classify_finding,
    classify_findings,
    get_patterns_by_category,
    get_patterns_by_service,
    is_non_iac,
    match_classification_pattern,
    remediation_steps,
)


def finding(rule_id="CKV_AWS_1", service="s3", title="", description="", address="aws_s3_bucket.b"):
    return {
        "id": "finding-test",
        "ruleId": rule_id,
        "title": title,
        "description": description,
        "location": {
            "file": "main.tf",
            "startLine": 1,
            "endLine": 5,
            "resourceAddress": address,
            "resourceType": address.split(".")[0],
            "service": service,
        },
    }


# ---------------------------------------------------------------------------
# The port itself
# ---------------------------------------------------------------------------


class TestCatalogPort:
    def test_six_groups(self):
        groups = [
            ACCOUNT_LEVEL_PATTERNS,
            SERVICE_ENABLEMENT_PATTERNS,
            ORGANIZATIONAL_PATTERNS,
            CONSOLE_ONLY_PATTERNS,
            MANUAL_REVIEW_PATTERNS,
            ONE_TIME_CONFIG_PATTERNS,
        ]
        # Manual-review group is 7, not infrabot's 6: we added `hardcoded_secret`
        # (CKV_SECRET_*), because -- unlike infrabot -- we run Checkov's secrets
        # framework, and a committed credential is a manual rotate-and-migrate, never
        # an IaC-attribute patch.
        assert [len(g) for g in groups] == [5, 6, 3, 3, 7, 3]
        assert len(ALL_PATTERNS) == 27

    def test_all_patterns_is_the_concatenation_in_order(self):
        expected = (
            ACCOUNT_LEVEL_PATTERNS
            + SERVICE_ENABLEMENT_PATTERNS
            + ORGANIZATIONAL_PATTERNS
            + CONSOLE_ONLY_PATTERNS
            + MANUAL_REVIEW_PATTERNS
            + ONE_TIME_CONFIG_PATTERNS
        )
        assert ALL_PATTERNS == expected

    def test_every_pattern_is_well_formed(self):
        names = set()
        for pattern in ALL_PATTERNS:
            assert pattern.name not in names, "duplicate pattern name"
            names.add(pattern.name)
            assert pattern.category in NON_IAC_CATEGORIES
            assert pattern.remediationType in ("cli", "manual", "console")
            assert pattern.reason, "every pattern must say why it is not IaC"

    def test_every_pattern_has_remediation_steps(self):
        """§6.4: a non-IaC finding must arrive with the command or the steps."""
        for pattern in ALL_PATTERNS:
            steps = REMEDIATION_STEPS[pattern.name]
            assert "command" in steps or "steps" in steps

    def test_cli_patterns_get_a_command_console_and_manual_get_steps(self):
        for pattern in ALL_PATTERNS:
            steps = REMEDIATION_STEPS[pattern.name]
            if pattern.remediationType == "cli":
                assert steps.get("command", "").startswith("aws ")
            else:
                assert steps.get("steps"), pattern.name

    def test_no_llm_in_this_path(self):
        source = open(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "skills",
                "iac-security-scan",
                "scripts",
                "classify.py",
            ),
            encoding="utf-8",
        ).read()
        for forbidden in ("anthropic", "requests.post", "openai", "urllib.request"):
            assert forbidden not in source, "classification is deterministic by design"


# ---------------------------------------------------------------------------
# matchClassificationPattern (classification-patterns.ts:320-351)
# ---------------------------------------------------------------------------


class TestMatchOrder:
    def test_matches_by_check_id_regex(self):
        pattern = match_classification_pattern("iam_password_policy", "", "")
        assert pattern is not None
        assert pattern.name == "iam_password_policy"
        assert pattern.category == "account_level_settings"

    def test_check_id_regex_is_case_insensitive(self):
        assert match_classification_pattern("EC2_EBS_DEFAULT_ENCRYPTION", "", "") is not None

    def test_matches_by_service_plus_keyword(self):
        pattern = match_classification_pattern(
            "CKV_AWS_999", "guardduty", "GuardDuty is not enabled in this region"
        )
        assert pattern.name == "guardduty_enabled"
        assert pattern.remediationType == "cli"

    def test_keyword_alone_does_not_match_a_service_scoped_pattern(self):
        # "not enabled" is a guardduty keyword, but the service is wrong and every
        # pattern in the catalog is service-scoped, so nothing may fire.
        assert (
            match_classification_pattern("CKV_AWS_999", "dynamodb", "point in time recovery not enabled")
            is None
        )

    def test_unmatched_returns_none(self):
        assert match_classification_pattern("CKV_AWS_21", "s3", "Ensure S3 bucket has versioning") is None

    def test_check_id_beats_service_keyword(self):
        """Match order is: check-ID regex first, across the whole catalog."""
        # 'key.*rotation' (one_time_config, group 6) vs a service+keyword hit that
        # would be earlier in the list — the regex wins.
        pattern = match_classification_pattern("kms_cmk_rotation_enabled", "kms", "")
        assert pattern.name == "kms_rotation"


class TestGetters:
    def test_by_category(self):
        assert {p.name for p in get_patterns_by_category("console_only")} == {
            "support_plan",
            "marketplace_subscription",
            "resource_share_accept",
        }

    def test_by_service_is_case_insensitive(self):
        assert get_patterns_by_service("IAM") == get_patterns_by_service("iam")
        assert len(get_patterns_by_service("iam")) == 6

    def test_unknown_category_and_service_are_empty(self):
        assert get_patterns_by_category("nope") == []
        assert get_patterns_by_service("nope") == []


# ---------------------------------------------------------------------------
# classify_finding
# ---------------------------------------------------------------------------


class TestClassifyFinding:
    def test_unmatched_finding_defaults_to_iac(self):
        verdict = classify_finding(finding(title="Ensure S3 bucket has versioning enabled"))
        assert verdict["remediationType"] == "iac"
        assert verdict["nonIaCCategory"] is None

    def test_non_iac_finding_carries_category_reason_and_steps(self):
        verdict = classify_finding(
            finding(rule_id="CKV_AWS_999", service="guardduty", title="GuardDuty is not enabled")
        )
        assert verdict["remediationType"] == "cli"
        assert verdict["nonIaCCategory"] == "service_enablement"
        assert verdict["classificationPattern"] == "guardduty_enabled"
        assert verdict["classificationReason"]
        assert verdict["remediationSteps"]["command"].startswith("aws guardduty")

    def test_console_finding_gets_steps_not_a_command(self):
        verdict = classify_finding(
            finding(rule_id="CKV_AWS_999", service="support", title="No Business support plan")
        )
        assert verdict["remediationType"] == "console"
        assert verdict["nonIaCCategory"] == "console_only"
        assert verdict["remediationSteps"]["steps"]
        assert "command" not in verdict["remediationSteps"]

    def test_title_and_description_are_both_searched(self):
        # Checkov populates title and leaves description empty; Prowler did the reverse.
        by_title = classify_finding(finding(service="macie", title="Macie is not enabled"))
        by_desc = classify_finding(finding(service="macie", description="Macie is not enabled"))
        assert by_title["classificationPattern"] == by_desc["classificationPattern"] == "macie_enabled"

    def test_has_iac_fix_overrides_the_pattern_catalog(self):
        """Ours, not infrabot's: if we can patch it, it is IaC. Evidence > keyword.

        Infrabot classified live-account findings, where "enable VPC flow logs" is
        genuinely a CLI job. In a Terraform repo it is an `aws_flow_log` block.
        """
        f = finding(rule_id="CKV2_AWS_11", service="vpc", title="Ensure VPC flow logging is enabled")
        assert classify_finding(f)["remediationType"] == "cli"
        assert classify_finding(f, has_iac_fix=True)["remediationType"] == "iac"
        assert classify_finding(f, has_iac_fix=True)["nonIaCCategory"] is None

    def test_classify_findings_mutates_and_respects_the_fixable_set(self):
        a = finding(rule_id="CKV2_AWS_11", service="vpc", title="Ensure VPC flow logging is enabled")
        b = finding(rule_id="CKV_AWS_999", service="guardduty", title="GuardDuty is not enabled")
        classify_findings([a, b], iac_fixable_rule_ids=["CKV2_AWS_11"])
        assert a["remediationType"] == "iac" and not is_non_iac(a)
        assert b["remediationType"] == "cli" and is_non_iac(b)

    def test_missing_location_does_not_explode(self):
        verdict = classify_finding({"ruleId": "CKV_AWS_1", "title": "x"})
        assert verdict["remediationType"] == "iac"


class TestRemediationSteps:
    def test_unknown_pattern_returns_empty_never_invents_a_command(self):
        """A hallucinated `aws` command is a command someone pastes into a terminal."""
        assert remediation_steps("no_such_pattern") == {}

    def test_steps_are_static_data(self):
        assert remediation_steps("kms_rotation")["command"] == "aws kms enable-key-rotation --key-id <KEY_ID>"

    @pytest.mark.parametrize("name", [p.name for p in ALL_PATTERNS])
    def test_every_pattern_resolves(self, name):
        assert remediation_steps(name)
