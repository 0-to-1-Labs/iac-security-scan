#!/usr/bin/env python3
"""Non-IaC classification (WS-7, SPEC §6.4).

A deterministic regex catalog -- 6 groups, ~25 patterns, **no LLM** -- that
triages a finding into ``iac | cli | manual | console | hybrid`` with a
``nonIaCCategory``. Ported from infrabot ``src/agents/classification-patterns.ts``
(:33-310): the pattern data (names, regexes, services, keywords, categories,
remediation types, reasons) is carried over verbatim, and ``classify_finding``
reproduces ``matchClassificationPattern``'s match order exactly.

It is deterministic on purpose. A model that can be argued out of a finding can
be argued out of its remediation route too; this layer cannot.

Two things are ours, not infrabot's, and both are marked below:

1. **The fix-catalog override.** Infrabot classified findings from a *live
   account*, where "enable VPC flow logs" really is a CLI job. We classify
   findings from *Terraform*, where it is a resource block. So: if the
   deterministic fix catalog (WS-5) can generate a real patch for the rule, the
   finding is ``iac`` -- evidence beats heuristic. Only findings we cannot patch
   are put to the pattern catalog. See ``classify_finding(has_iac_fix=...)``.

2. **REMEDIATION_STEPS.** §6.4 requires the report to print *the CLI command or
   the console steps* for a non-IaC finding: "this one isn't a Terraform problem,
   here's the `aws` command." Infrabot's patterns carry no command text, so the
   commands are supplied here as static, checked-in data -- never model-generated,
   same governance rule as ``rule-severity.json`` and ``fix-rules.json``.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern, Sequence

# --- The five remediation routes (findings.py REMEDIATION_TYPES) ------------
REMEDIATION_TYPE_IAC = "iac"
REMEDIATION_TYPE_CLI = "cli"
REMEDIATION_TYPE_MANUAL = "manual"
REMEDIATION_TYPE_CONSOLE = "console"
REMEDIATION_TYPE_HYBRID = "hybrid"

# --- NonIaCCategory (remediation.ts:17-24), verbatim ------------------------
NON_IAC_CATEGORIES = (
    "account_level_settings",
    "service_enablement",
    "organizational_policies",
    "manual_review_required",
    "console_only",
    "one_time_configuration",
)


@dataclass(frozen=True)
class ClassificationPattern:
    """classification-patterns.ts:14-29, verbatim."""

    name: str
    category: str
    remediationType: str
    reason: str
    checkPatterns: Sequence[Pattern[str]] = field(default_factory=tuple)
    services: Sequence[str] = field(default_factory=tuple)
    descriptionKeywords: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "remediationType": self.remediationType,
            "reason": self.reason,
        }


def _rx(*patterns: str) -> Sequence[Pattern[str]]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


# ---------------------------------------------------------------------------
# Group 1 -- account-level settings (classification-patterns.ts:34-77)
# ---------------------------------------------------------------------------

ACCOUNT_LEVEL_PATTERNS: List[ClassificationPattern] = [
    ClassificationPattern(
        name="s3_account_public_access_block",
        checkPatterns=_rx(r"s3_account.*public.*access.*block", r"s3.*account.*level"),
        services=("s3",),
        descriptionKeywords=("account-level", "public access block", "account public"),
        category="account_level_settings",
        remediationType="cli",
        reason=(
            "S3 Account Public Access Block is an account-level setting configured "
            "via CLI, not per-resource IaC"
        ),
    ),
    ClassificationPattern(
        name="ebs_default_encryption",
        checkPatterns=_rx(r"ec2_ebs_default_encryption", r"ebs.*encryption.*default"),
        services=("ec2",),
        descriptionKeywords=(
            "default encryption",
            "EBS encryption by default",
            "ebs-encryption-by-default",
        ),
        category="account_level_settings",
        remediationType="cli",
        reason="EBS default encryption is an account/region-level setting",
    ),
    ClassificationPattern(
        name="iam_password_policy",
        checkPatterns=_rx(r"iam_password_policy", r"iam.*account.*password"),
        services=("iam",),
        descriptionKeywords=("password policy", "account password"),
        category="account_level_settings",
        remediationType="cli",
        reason="IAM password policy is an account-level setting",
    ),
    ClassificationPattern(
        name="account_alternate_contacts",
        checkPatterns=_rx(r"account.*alternate.*contact", r"account.*billing.*contact"),
        services=("account", "organizations"),
        descriptionKeywords=(
            "alternate contact",
            "billing contact",
            "security contact",
            "operations contact",
        ),
        category="account_level_settings",
        remediationType="cli",
        reason="AWS account alternate contacts are account-level settings",
    ),
    ClassificationPattern(
        name="ec2_serial_console",
        checkPatterns=_rx(r"ec2.*serial.*console"),
        services=("ec2",),
        descriptionKeywords=("serial console", "ec2 serial"),
        category="account_level_settings",
        remediationType="cli",
        reason="EC2 Serial Console access is an account-level setting",
    ),
]

# ---------------------------------------------------------------------------
# Group 2 -- service enablement (classification-patterns.ts:82-136)
# ---------------------------------------------------------------------------

SERVICE_ENABLEMENT_PATTERNS: List[ClassificationPattern] = [
    ClassificationPattern(
        name="guardduty_enabled",
        checkPatterns=_rx(r"guardduty.*enabled", r"guardduty_is_enabled"),
        services=("guardduty",),
        descriptionKeywords=("GuardDuty", "not enabled", "detector"),
        category="service_enablement",
        remediationType="cli",
        reason="Enabling GuardDuty is a one-time operation typically done via CLI",
    ),
    ClassificationPattern(
        name="securityhub_enabled",
        checkPatterns=_rx(r"securityhub.*enabled", r"security.*hub.*enabled"),
        services=("securityhub",),
        descriptionKeywords=("Security Hub", "not enabled", "SecurityHub"),
        category="service_enablement",
        remediationType="cli",
        reason="Enabling Security Hub is a one-time operation",
    ),
    ClassificationPattern(
        name="config_enabled",
        checkPatterns=_rx(r"config.*enabled", r"aws.*config.*recorder"),
        services=("config",),
        descriptionKeywords=("AWS Config", "config recorder", "not enabled"),
        category="service_enablement",
        remediationType="cli",
        reason="Enabling AWS Config is a one-time regional operation",
    ),
    ClassificationPattern(
        name="macie_enabled",
        checkPatterns=_rx(r"macie.*enabled"),
        services=("macie",),
        descriptionKeywords=("Macie", "not enabled"),
        category="service_enablement",
        remediationType="cli",
        reason="Enabling Macie is a one-time operation",
    ),
    ClassificationPattern(
        name="inspector_enabled",
        checkPatterns=_rx(r"inspector.*enabled"),
        services=("inspector", "inspector2"),
        descriptionKeywords=("Inspector", "not enabled"),
        category="service_enablement",
        remediationType="cli",
        reason="Enabling Inspector is a one-time operation",
    ),
    ClassificationPattern(
        name="access_analyzer_enabled",
        checkPatterns=_rx(r"accessanalyzer.*enabled", r"access.*analyzer"),
        services=("accessanalyzer",),
        descriptionKeywords=("Access Analyzer", "not enabled", "IAM Access Analyzer"),
        category="service_enablement",
        remediationType="cli",
        reason="Enabling IAM Access Analyzer is a one-time regional operation",
    ),
]

# ---------------------------------------------------------------------------
# Group 3 -- organizational policies (classification-patterns.ts:141-172)
# ---------------------------------------------------------------------------

ORGANIZATIONAL_PATTERNS: List[ClassificationPattern] = [
    ClassificationPattern(
        name="organizations_scp",
        checkPatterns=_rx(r"organizations.*scp", r"service.*control.*policy"),
        services=("organizations",),
        descriptionKeywords=("SCP", "Service Control Policy", "organization"),
        category="organizational_policies",
        remediationType="manual",
        reason="SCPs require careful planning and organizational approval",
    ),
    ClassificationPattern(
        name="organizations_policy",
        checkPatterns=_rx(r"organizations.*policy", r"tag.*policy", r"backup.*policy"),
        services=("organizations",),
        descriptionKeywords=("tag policy", "backup policy", "AI services opt-out"),
        category="organizational_policies",
        remediationType="manual",
        reason="Organization policies require organizational-level approval",
    ),
    ClassificationPattern(
        name="cloudtrail_organization",
        checkPatterns=_rx(r"cloudtrail.*organization", r"organization.*trail"),
        services=("cloudtrail",),
        descriptionKeywords=("organization trail", "organization-level"),
        category="organizational_policies",
        remediationType="manual",
        reason=(
            "Organization CloudTrail requires organizational management account access"
        ),
    ),
]

# ---------------------------------------------------------------------------
# Group 4 -- console-only (classification-patterns.ts:177-208)
# ---------------------------------------------------------------------------

CONSOLE_ONLY_PATTERNS: List[ClassificationPattern] = [
    ClassificationPattern(
        name="support_plan",
        checkPatterns=_rx(r"support.*plan"),
        services=("support",),
        descriptionKeywords=("support plan", "Business support", "Enterprise support"),
        category="console_only",
        remediationType="console",
        reason="AWS Support plan changes require console or AWS Support API",
    ),
    ClassificationPattern(
        name="marketplace_subscription",
        checkPatterns=_rx(r"marketplace"),
        services=("marketplace",),
        descriptionKeywords=("marketplace", "subscription", "third-party"),
        category="console_only",
        remediationType="console",
        reason="Marketplace subscriptions are managed via console",
    ),
    ClassificationPattern(
        name="resource_share_accept",
        checkPatterns=_rx(r"ram.*accept", r"resource.*share.*accept"),
        services=("ram",),
        descriptionKeywords=("resource share", "RAM", "accept invitation"),
        category="console_only",
        remediationType="console",
        reason="Accepting resource shares is typically done via console",
    ),
]

# ---------------------------------------------------------------------------
# Group 5 -- manual review required (classification-patterns.ts:213-268)
# ---------------------------------------------------------------------------

MANUAL_REVIEW_PATTERNS: List[ClassificationPattern] = [
    ClassificationPattern(
        name="unused_credentials",
        checkPatterns=_rx(r"iam.*unused", r"credential.*not.*used", r"accesskey.*unused"),
        services=("iam",),
        descriptionKeywords=("unused", "not used in", "days ago", "never used"),
        category="manual_review_required",
        remediationType="manual",
        reason="Unused credentials require business context review before removal",
    ),
    ClassificationPattern(
        name="overprivileged_policy",
        checkPatterns=_rx(r"iam.*overprivileged", r"policy.*star", r"wildcard.*resource"),
        services=("iam",),
        descriptionKeywords=(
            "overprivileged",
            "wildcard",
            'Resource: "*"',
            "excessive permissions",
        ),
        category="manual_review_required",
        remediationType="manual",
        reason="Overprivileged policies require usage analysis before modification",
    ),
    ClassificationPattern(
        name="inactive_user",
        checkPatterns=_rx(r"iam.*inactive", r"user.*inactive"),
        services=("iam",),
        descriptionKeywords=("inactive", "last activity", "no recent"),
        category="manual_review_required",
        remediationType="manual",
        reason="Inactive users require verification with business owners before action",
    ),
    ClassificationPattern(
        name="exposed_secrets",
        checkPatterns=_rx(r"secret.*exposed", r"credential.*exposed", r"key.*exposed"),
        services=("secretsmanager", "iam"),
        descriptionKeywords=("exposed", "leaked", "compromised", "publicly accessible"),
        category="manual_review_required",
        remediationType="manual",
        reason="Exposed secrets require immediate rotation and investigation",
    ),
    ClassificationPattern(
        # Checkov's secrets framework (CKV_SECRET_*): a credential hardcoded in the
        # source. NOT an IaC-attribute fix -- the moment it entered git history it is
        # compromised, and adding a kms_key_arn (what a naive "iac" route implies)
        # leaves it in every past commit. Rotation is the only real remediation.
        name="hardcoded_secret",
        checkPatterns=_rx(r"CKV_SECRET_\d+"),
        services=(),
        descriptionKeywords=(),
        category="manual_review_required",
        remediationType="manual",
        reason=(
            "A committed secret is compromised the moment it enters git history; "
            "no IaC attribute change removes it. Rotate and move to a secret store."
        ),
    ),
    ClassificationPattern(
        name="public_resource_review",
        checkPatterns=_rx(r"publicly.*accessible"),
        services=("s3", "ec2", "rds"),
        descriptionKeywords=("publicly accessible", "public access", "internet-facing"),
        category="manual_review_required",
        remediationType="manual",
        reason="Public resources may be intentional and require business review",
    ),
    ClassificationPattern(
        name="mfa_not_enabled",
        checkPatterns=_rx(r"iam.*mfa", r"mfa.*not.*enabled", r"root.*mfa"),
        services=("iam",),
        descriptionKeywords=("MFA", "multi-factor", "not enabled"),
        category="manual_review_required",
        remediationType="manual",
        reason="MFA setup requires user interaction and cannot be automated",
    ),
]

# ---------------------------------------------------------------------------
# Group 6 -- one-time configuration (classification-patterns.ts:273-305)
# ---------------------------------------------------------------------------

ONE_TIME_CONFIG_PATTERNS: List[ClassificationPattern] = [
    ClassificationPattern(
        name="cloudtrail_multi_region",
        checkPatterns=_rx(r"cloudtrail.*multi.*region"),
        services=("cloudtrail",),
        descriptionKeywords=("multi-region", "all regions"),
        category="one_time_configuration",
        remediationType="cli",
        reason="CloudTrail multi-region setup is typically a one-time configuration",
    ),
    ClassificationPattern(
        name="vpc_flow_logs",
        checkPatterns=_rx(r"vpc.*flow.*logs"),
        services=("vpc", "ec2"),
        descriptionKeywords=("flow logs", "VPC Flow"),
        category="one_time_configuration",
        remediationType="cli",
        reason="VPC Flow Logs can be enabled via CLI as a one-time setup",
    ),
    ClassificationPattern(
        name="kms_rotation",
        checkPatterns=_rx(r"kms.*rotation", r"key.*rotation"),
        services=("kms",),
        descriptionKeywords=("key rotation", "automatic rotation"),
        category="one_time_configuration",
        remediationType="cli",
        reason="KMS key rotation is a one-time configuration change",
    ),
]

# classification-patterns.ts:303-310
ALL_PATTERNS: List[ClassificationPattern] = (
    ACCOUNT_LEVEL_PATTERNS
    + SERVICE_ENABLEMENT_PATTERNS
    + ORGANIZATIONAL_PATTERNS
    + CONSOLE_ONLY_PATTERNS
    + MANUAL_REVIEW_PATTERNS
    + ONE_TIME_CONFIG_PATTERNS
)


# ---------------------------------------------------------------------------
# The steps a user actually has to run (§6.4). OURS, not infrabot's.
#
# Static, checked-in data. The model never writes one of these at runtime, for
# the same reason it never writes a compliance mapping: a hallucinated `aws`
# command in a security report is a command someone will paste into a terminal.
# `{resource}` is substituted with the finding's resource address.
# ---------------------------------------------------------------------------

REMEDIATION_STEPS: Dict[str, Dict[str, Any]] = {
    "hardcoded_secret": {
        "steps": [
            "Treat the credential as compromised and rotate it at the source now "
            "(the DB, the API provider, the KMS key) -- it is live in git history.",
            "Store the new value in a secret manager: "
            "`aws secretsmanager create-secret --name <app>/<key> "
            "--secret-string <NEW_VALUE>` (or an SSM SecureString parameter).",
            "Reference it from IaC instead of inlining -- "
            "`data.aws_secretsmanager_secret_version` or an SSM lookup -- so the "
            "literal never re-enters the source.",
            "Scrub the value from git history with `git filter-repo`; a revert only "
            "hides it in a new commit, it stays readable in every old one.",
        ],
        "note": (
            "Not an IaC-attribute fix: the secret is already exposed to anyone with "
            "history access, and adding encryption does not un-expose it. Rotation is "
            "the only real remediation; the store migration keeps it from recurring."
        ),
    },
    "s3_account_public_access_block": {
        "command": (
            "aws s3control put-public-access-block --account-id <ACCOUNT_ID> "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        "note": (
            "Account-wide. It overrides per-bucket settings, so confirm no bucket in "
            "this account is intentionally public first."
        ),
    },
    "ebs_default_encryption": {
        "command": "aws ec2 enable-ebs-encryption-by-default --region <REGION>",
        "note": "Per region. Existing unencrypted volumes are not retroactively encrypted.",
    },
    "iam_password_policy": {
        "command": (
            "aws iam update-account-password-policy --minimum-password-length 14 "
            "--require-symbols --require-numbers --require-uppercase-characters "
            "--require-lowercase-characters --max-password-age 90 "
            "--password-reuse-prevention 24"
        ),
        "note": "Account-level. Not expressible per-resource in Terraform.",
    },
    "account_alternate_contacts": {
        "command": (
            "aws account put-alternate-contact --alternate-contact-type SECURITY "
            "--email-address <EMAIL> --name <NAME> --title <TITLE> "
            "--phone-number <PHONE>"
        ),
        "note": "Repeat for BILLING and OPERATIONS contact types.",
    },
    "ec2_serial_console": {
        "command": "aws ec2 disable-serial-console-access --region <REGION>",
        "note": "Account/region-level toggle.",
    },
    "guardduty_enabled": {
        "command": "aws guardduty create-detector --enable --region <REGION>",
        "note": "Per region. Enable in every region you operate in, not just the default.",
    },
    "securityhub_enabled": {
        "command": "aws securityhub enable-security-hub --enable-default-standards",
        "note": "Per region.",
    },
    "config_enabled": {
        "command": (
            "aws configservice put-configuration-recorder "
            "--configuration-recorder name=default,roleARN=<ROLE_ARN> && "
            "aws configservice start-configuration-recorder "
            "--configuration-recorder-name default"
        ),
        "note": "Requires a service-linked role and a delivery channel (S3 bucket).",
    },
    "macie_enabled": {
        "command": "aws macie2 enable-macie --region <REGION>",
        "note": "Per region. Macie charges by data volume scanned -- check cost first.",
    },
    "inspector_enabled": {
        "command": (
            "aws inspector2 enable --resource-types EC2 ECR LAMBDA "
            "--account-ids <ACCOUNT_ID>"
        ),
        "note": "Per region.",
    },
    "access_analyzer_enabled": {
        "command": (
            "aws accessanalyzer create-analyzer --analyzer-name default "
            "--type ACCOUNT --region <REGION>"
        ),
        "note": "Per region. Free.",
    },
    "organizations_scp": {
        "steps": [
            "This is an organization-level control and needs a human decision, not a patch.",
            "In the management account, draft the SCP and review its blast radius against "
            "every OU it would attach to.",
            "Attach it to a test OU first. An SCP denies across every account beneath it, "
            "and a wrong one is an outage.",
            "Get organizational sign-off before attaching to production OUs.",
        ],
        "note": "SCPs require careful planning and organizational approval.",
    },
    "organizations_policy": {
        "steps": [
            "Draft the policy (tag / backup / AI opt-out) in the management account.",
            "Review its effect on every member account before attaching.",
            "Get organizational sign-off, then attach.",
        ],
        "note": "Organization policies require organizational-level approval.",
    },
    "cloudtrail_organization": {
        "steps": [
            "Requires access to the AWS Organizations management account.",
            "Create or update the trail with --is-organization-trail from the "
            "management account.",
            "Confirm the destination bucket policy permits the org-wide log delivery.",
        ],
        "note": "Cannot be done from a member account.",
    },
    "support_plan": {
        "steps": [
            "Open the AWS Console -> Support Center -> Support Plans.",
            "Select Business or Enterprise, per your incident-response commitments.",
            "This is a billing change and needs an owner's approval.",
        ],
        "note": "Console (or the Support API); not expressible in Terraform.",
    },
    "marketplace_subscription": {
        "steps": [
            "Open the AWS Console -> AWS Marketplace -> Manage subscriptions.",
            "Review the subscription and its third-party data-sharing terms.",
            "Cancel or re-subscribe as the review concludes.",
        ],
        "note": "Marketplace subscriptions are managed via the console.",
    },
    "resource_share_accept": {
        "steps": [
            "Open the AWS Console -> Resource Access Manager -> Shared with me.",
            "Verify the sharing account is one you actually trust before accepting.",
            "Accept or reject the invitation.",
        ],
        "note": "Accepting a share grants a foreign account's resources into yours. Verify first.",
    },
    "unused_credentials": {
        "steps": [
            "Pull the credential report: aws iam generate-credential-report && "
            "aws iam get-credential-report --query Content --output text | base64 -d",
            "Confirm with the owning team that the credential is genuinely unused. "
            "A quarterly batch job looks identical to an abandoned key.",
            "Deactivate first (aws iam update-access-key --status Inactive), wait a cycle, "
            "then delete.",
        ],
        "note": "Requires business context. Deleting an in-use key is an outage.",
    },
    "overprivileged_policy": {
        "steps": [
            "Pull the last-accessed data: aws iam get-service-last-accessed-details "
            "--job-id <JOB_ID> (start it with generate-service-last-accessed-details).",
            "Scope the policy down to the services and resources actually used, "
            "not to what looks tidy.",
            "Roll out to a non-production role first, then production.",
        ],
        "note": (
            "Editable in Terraform, but the *content* of the scoped-down policy is a "
            "usage-analysis decision, not a mechanical patch. We will not guess at it."
        ),
    },
    "inactive_user": {
        "steps": [
            "Confirm with the business owner that the user is genuinely inactive.",
            "Disable console access and deactivate access keys before deleting anything.",
            "Delete only after a full cycle with no reported breakage.",
        ],
        "note": "Requires verification with business owners.",
    },
    "exposed_secrets": {
        "steps": [
            "Treat as an incident. Rotate the credential NOW: it is in a file, and "
            "files get shared.",
            "Revoke the old value, then scrub it from git history "
            "(the commit is still readable until you do).",
            "Move the value to AWS Secrets Manager / SSM Parameter Store and reference "
            "it from Terraform.",
            "Audit CloudTrail for use of the exposed credential.",
        ],
        "note": "Immediate rotation and investigation. Not a patch.",
    },
    "public_resource_review": {
        "steps": [
            "Confirm with the owning team whether the public exposure is intentional "
            "(a public website bucket is not a finding; a public data bucket is a breach).",
            "If unintentional, restrict access and re-scan.",
            "If intentional, record the decision -- an undocumented intentional exposure "
            "is indistinguishable from an accident.",
        ],
        "note": "May be intentional. Requires business review.",
    },
    "mfa_not_enabled": {
        "steps": [
            "MFA enrollment is a human action; it cannot be automated from Terraform "
            "or the CLI.",
            "Enroll a hardware or virtual MFA device for the principal.",
            "For the root account, do this today and store the device somewhere a "
            "single person leaving does not lock you out.",
        ],
        "note": "Requires user interaction.",
    },
    "cloudtrail_multi_region": {
        "command": (
            "aws cloudtrail update-trail --name <TRAIL_NAME> --is-multi-region-trail "
            "--include-global-service-events"
        ),
        "note": "Also expressible in Terraform (is_multi_region_trail = true) if the "
        "trail is managed here.",
    },
    "vpc_flow_logs": {
        "command": (
            "aws ec2 create-flow-logs --resource-type VPC --resource-ids <VPC_ID> "
            "--traffic-type ALL --log-destination-type cloud-watch-logs "
            "--log-group-name <LOG_GROUP> --deliver-logs-permission-arn <ROLE_ARN>"
        ),
        "note": "Also expressible in Terraform (aws_flow_log) if the VPC is managed here.",
    },
    "kms_rotation": {
        "command": "aws kms enable-key-rotation --key-id <KEY_ID>",
        "note": "Also expressible in Terraform (enable_key_rotation = true) if the key "
        "is managed here.",
    },
}


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def match_classification_pattern(
    check_id: str, service: str, description: str
) -> Optional[ClassificationPattern]:
    """classification-patterns.ts:320-351 (``matchClassificationPattern``), verbatim.

    Match order, preserved exactly:
      1. check-ID regex
      2. service membership AND a description keyword
      3. description keyword alone, but only for patterns with no service list
    """
    service_lower = (service or "").lower()
    desc_lower = (description or "").lower()

    for pattern in ALL_PATTERNS:
        if pattern.checkPatterns and any(
            rx.search(check_id or "") for rx in pattern.checkPatterns
        ):
            return pattern

        if pattern.services and service_lower in pattern.services:
            if pattern.descriptionKeywords and any(
                kw.lower() in desc_lower for kw in pattern.descriptionKeywords
            ):
                return pattern

        if not pattern.services and pattern.descriptionKeywords:
            if any(kw.lower() in desc_lower for kw in pattern.descriptionKeywords):
                return pattern

    return None


def get_patterns_by_category(category: str) -> List[ClassificationPattern]:
    """classification-patterns.ts:356-358."""
    return [p for p in ALL_PATTERNS if p.category == category]


def get_patterns_by_service(service: str) -> List[ClassificationPattern]:
    """classification-patterns.ts:363-366."""
    service_lower = (service or "").lower()
    return [p for p in ALL_PATTERNS if service_lower in (p.services or ())]


def remediation_steps(pattern_name: str, resource_address: str = "") -> Dict[str, Any]:
    """The CLI command / console steps for a matched pattern (§6.4).

    Returns ``{}`` for an unknown pattern name rather than inventing a command.
    Silence is safer than a guess -- the same rule that governs the compliance map.
    """
    entry = REMEDIATION_STEPS.get(pattern_name)
    if not entry:
        return {}
    out: Dict[str, Any] = {}
    if "command" in entry:
        out["command"] = entry["command"].replace("{resource}", resource_address)
    if "steps" in entry:
        out["steps"] = [s.replace("{resource}", resource_address) for s in entry["steps"]]
    if "note" in entry:
        out["note"] = entry["note"]
    return out


def classify_finding(
    finding: Dict[str, Any], *, has_iac_fix: bool = False
) -> Dict[str, Any]:
    """Triage one finding into a remediation route.

    ``has_iac_fix`` -- the deterministic fix catalog (WS-5) can generate a real
    Terraform patch for this rule. OURS, not infrabot's: infrabot classified live
    account findings, we classify Terraform. "Enable VPC flow logs" is a CLI job
    against a live account and an ``aws_flow_log`` resource in a repo. If we can
    patch it, it is ``iac`` -- a generated, validated diff is stronger evidence
    than a keyword.

    Returns the fields to merge onto the finding:
      ``remediationType``, ``nonIaCCategory``, ``classificationPattern``,
      ``classificationReason``, ``remediationSteps``.
    """
    location = finding.get("location") or {}
    check_id = finding.get("ruleId") or ""
    service = location.get("service") or ""
    # Both title and description carry the keywords Checkov emits; infrabot fed a
    # single description string, so concatenate rather than lose half the signal.
    description = " ".join(
        str(finding.get(k) or "") for k in ("title", "description")
    ).strip()

    if has_iac_fix:
        return {
            "remediationType": REMEDIATION_TYPE_IAC,
            "nonIaCCategory": None,
            "classificationPattern": None,
            "classificationReason": (
                "The deterministic fix catalog generates a Terraform patch for this rule."
            ),
            "remediationSteps": {},
        }

    pattern = match_classification_pattern(check_id, service, description)
    if pattern is None:
        return {
            "remediationType": REMEDIATION_TYPE_IAC,
            "nonIaCCategory": None,
            "classificationPattern": None,
            "classificationReason": "",
            "remediationSteps": {},
        }

    return {
        "remediationType": pattern.remediationType,
        "nonIaCCategory": pattern.category,
        "classificationPattern": pattern.name,
        "classificationReason": pattern.reason,
        "remediationSteps": remediation_steps(
            pattern.name, location.get("resourceAddress") or ""
        ),
    }


def classify_findings(
    findings: Sequence[Dict[str, Any]], iac_fixable_rule_ids: Optional[Sequence[str]] = None
) -> List[Dict[str, Any]]:
    """Classify a list of findings in place, returning the same list.

    ``iac_fixable_rule_ids`` -- rule IDs the fix catalog can patch. Callers pass
    ``FixCatalog.load().rule_ids()``; report.py narrows it further to the rules
    that actually produced a patch on this tree.
    """
    fixable = set(iac_fixable_rule_ids or ())
    out: List[Dict[str, Any]] = []
    for finding in findings:
        verdict = classify_finding(
            finding, has_iac_fix=(finding.get("ruleId") or "") in fixable
        )
        finding.update(verdict)
        out.append(finding)
    return out


def is_non_iac(finding: Dict[str, Any]) -> bool:
    return (finding.get("remediationType") or "iac") != REMEDIATION_TYPE_IAC


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Classify findings into remediation routes")
    parser.add_argument("findings", help="path to a JSON file: a findings array, or a merge result")
    parser.add_argument(
        "--iac-fixable",
        default="",
        help="comma-separated rule IDs the fix catalog covers (default: the whole catalog)",
    )
    args = parser.parse_args(argv)

    with open(args.findings, encoding="utf-8") as fh:
        payload = json.load(fh)
    findings = payload["findings"] if isinstance(payload, dict) else payload

    if args.iac_fixable:
        fixable = [r.strip() for r in args.iac_fixable.split(",") if r.strip()]
    else:
        from patch_terraform import FixCatalog  # local import: only needed here

        fixable = FixCatalog.load().rule_ids()

    classify_findings(findings, fixable)
    json.dump(findings, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


__all__ = [
    "ClassificationPattern",
    "NON_IAC_CATEGORIES",
    "ACCOUNT_LEVEL_PATTERNS",
    "SERVICE_ENABLEMENT_PATTERNS",
    "ORGANIZATIONAL_PATTERNS",
    "CONSOLE_ONLY_PATTERNS",
    "MANUAL_REVIEW_PATTERNS",
    "ONE_TIME_CONFIG_PATTERNS",
    "ALL_PATTERNS",
    "REMEDIATION_STEPS",
    "match_classification_pattern",
    "get_patterns_by_category",
    "get_patterns_by_service",
    "remediation_steps",
    "classify_finding",
    "classify_findings",
    "is_non_iac",
]


if __name__ == "__main__":
    sys.exit(main())
