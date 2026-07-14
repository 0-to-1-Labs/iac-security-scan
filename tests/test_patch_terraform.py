#!/usr/bin/env python3
"""
WS-5 tests: the deterministic Terraform patcher.

Ported from infrabot's ``tests/terraform-patch.test.ts`` (481 lines), with the
parser tests re-pointed at the WS-1 parser (`parse_iac.py`) instead of the regex
parser they were written against -- and then extended with the cases the regex
parser could never have passed (heredocs, `dynamic`, `for_each`), because those
are exactly the resources it silently dropped, and a dropped resource in a
security scanner is a vulnerability nobody ever sees.

``TestNeverAutoApply`` is the load-bearing one. Read its docstring before
touching it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "skills", "iac-security-scan", "scripts")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
sys.path.insert(0, SCRIPTS)

import patch_terraform as pt  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def catalog() -> pt.FixCatalog:
    return pt.FixCatalog.load()


def write_tree(tmp_path, files: dict) -> str:
    for name, content in files.items():
        path = os.path.join(tmp_path, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return str(tmp_path)


def finding(rule_id: str, address: str, file: str = "main.tf", severity: str = "high"):
    resource_type = address.split(".")[0]
    return {
        "id": f"finding-{rule_id}-{address}",
        "ruleId": rule_id,
        "title": rule_id,
        "severity": severity,
        "location": {
            "file": file,
            "startLine": 1,
            "endLine": 1,
            "resourceAddress": address,
            "resourceType": resource_type,
            "service": resource_type.split("_")[1] if "_" in resource_type else "",
        },
    }


def change(**kwargs) -> pt.PatchChange:
    kwargs.setdefault("type", "add")
    kwargs.setdefault("kind", "attribute")
    kwargs.setdefault("path", "some_attr")
    kwargs.setdefault("description", "d")
    return pt.PatchChange(**kwargs)


# ===========================================================================
# THE SAFETY TEST. It does not get relaxed. (SPEC §6.3, IMPLEMENTATION_PLAN WS-5)
# ===========================================================================


class TestNeverAutoApply:
    """Five categories are NEVER auto-applicable:

        1. security-group CIDR narrowing
        2. IAM wildcard removal
        3. bucket-policy changes
        4. KMS key-policy changes
        5. network ACLs

    The failure mode this guards against is a production outage landing on
    somebody who never ran the scan -- an operator locked out of a box, a
    workload that lost its IAM permission, a consumer cut off from a bucket.

    So this is a hard-coded list, not a heuristic, and not a confidence
    threshold. If a future fix-catalog entry, a future model, or a future
    `--unsafe` flag ever marks one of these `autoApplicable`, this test fails
    and the build stops. It is not to be relaxed to make a feature land.
    """

    def test_every_never_category_is_blocked(self):
        for category in pt.NEVER_AUTO_APPLY_CATEGORIES:
            changes = [change(category=category)]
            blocker = pt.auto_apply_blocker(changes)
            assert blocker is not None, f"{category} produced no auto-apply blocker"
            assert pt.is_auto_applicable(changes, rule_auto=True) is False, (
                f"{category} was marked auto-applicable"
            )

    def test_every_never_resource_type_is_blocked(self):
        for resource_type in pt.NEVER_AUTO_APPLY_RESOURCE_TYPES:
            # touched as the patch target
            touching = [change(targetAddress=f"{resource_type}.example")]
            assert pt.is_auto_applicable(touching, rule_auto=True) is False, (
                f"a patch targeting {resource_type} was marked auto-applicable"
            )
            # or merely created as a companion
            creating = [
                change(
                    kind="companion",
                    targetAddress="aws_s3_bucket.benign",
                    createsResourceTypes=[resource_type],
                )
            ]
            assert pt.is_auto_applicable(creating, rule_auto=True) is False, (
                f"a patch creating {resource_type} was marked auto-applicable"
            )

    def test_every_never_attribute_is_blocked(self):
        for attr in pt.NEVER_AUTO_APPLY_ATTRIBUTES:
            changes = [change(path=attr, targetAddress="aws_s3_bucket.benign")]
            assert pt.is_auto_applicable(changes, rule_auto=True) is False, (
                f"a change to the {attr!r} attribute was marked auto-applicable"
            )

    def test_the_five_spec_categories_are_all_present(self):
        """The list is the SPEC's, not one we drifted into."""
        assert pt.NEVER_AUTO_APPLY_CATEGORIES == frozenset(
            {
                "security-group-cidr",
                "iam-wildcard",
                "bucket-policy",
                "kms-key-policy",
                "network-acl",
            }
        )

    def test_catalog_never_nominates_a_never_category(self, catalog):
        """A never-list category may not even be *nominated* as auto-applicable.

        The engine would veto it anyway, but a catalog row claiming
        `autoApplicable: true` on an SG CIDR fix is a lie in checked-in data and
        a trap for the next person who edits the engine.
        """
        for rule_id, rule in catalog.rules.items():
            if rule.get("category") in pt.NEVER_AUTO_APPLY_CATEGORIES:
                assert rule.get("autoApplicable") is False, (
                    f"{rule_id}: catalog nominates a never-auto-apply category "
                    f"({rule['category']}) as autoApplicable"
                )

    def test_sg_cidr_narrowing_on_the_real_corpus_is_diff_only(self, catalog):
        """The end-to-end version: CKV_AWS_260 fires on tf-04's internet-open
        ingress rule. The patch must exist, and must not be auto-applicable."""
        root = os.path.join(FIXTURES, "tf-04-container-platform")
        findings = [finding("CKV_AWS_260", "aws_vpc_security_group_ingress_rule.alb_http",
                            file="security-groups.tf")]
        patches = pt.generate_security_patches(root, findings, catalog, use_fmt=False)
        assert patches, "no patch generated for the SG CIDR finding"
        for patch in patches:
            assert patch.autoApplicable is False
            assert "never-auto-apply" in (patch.autoApplyBlockedBy or "")

    def test_kms_key_policy_fix_on_the_real_corpus_is_diff_only(self, catalog):
        root = os.path.join(FIXTURES, "tf-04-container-platform")
        findings = [finding("CKV_AWS_158", "aws_cloudwatch_log_group.ecs",
                            file="cloudwatch.tf")]
        patches = pt.generate_security_patches(root, findings, catalog, use_fmt=False)
        assert patches
        for patch in patches:
            assert patch.autoApplicable is False


# ===========================================================================
# Parser -- ported from terraform-patch.test.ts:16 ('Terraform Parser')
# ===========================================================================


class TestTerraformParser:
    """The ported parser suite. Same assertions, different engine underneath:
    these run against `parse_iac.py`/tfparse, not infrabot's regex.
    """

    def test_parses_a_simple_s3_bucket(self, tmp_path):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_s3_bucket" "example" {\n'
                       '  bucket = "my-bucket"\n'
                       '  acl    = "private"\n'
                       '}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        assert len(resources) == 1
        assert resources[0].resourceType == "aws_s3_bucket"
        assert resources[0].resourceName == "example"
        assert resources[0].attributes["bucket"] == "my-bucket"
        assert resources[0].attributes["acl"] == "private"

    def test_parses_multiple_resources_in_one_file(self, tmp_path):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n\n'
                       'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        assert {r.resourceName for r in resources} == {"data", "logs"}

    def test_parses_nested_blocks(self, tmp_path):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_s3_bucket" "example" {\n'
                       '  bucket = "b"\n\n'
                       '  versioning {\n    enabled = true\n  }\n'
                       '}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        assert pt._has_top_level_block(resources[0], "versioning")

    def test_handles_boolean_and_number_values(self, tmp_path):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_ebs_volume" "example" {\n'
                       '  availability_zone = "us-east-1a"\n'
                       '  size              = 100\n'
                       '  encrypted         = false\n'
                       '}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        assert resources[0].attributes["size"] == 100
        assert resources[0].attributes["encrypted"] is False

    def test_skips_comments_and_empty_lines(self, tmp_path):
        root = write_tree(tmp_path, {
            "main.tf": '# a comment\n\n'
                       '// another\n\n'
                       'resource "aws_s3_bucket" "example" {\n  bucket = "b"\n}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        assert len(resources) == 1
        assert resources[0].resourceName == "example"

    def test_captures_raw_content(self, tmp_path):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        assert "aws_s3_bucket" in resources[0].rawContent
        assert "my-bucket" in resources[0].rawContent
        assert resources[0].rawContent.rstrip().endswith("}")

    def test_every_resource_has_line_provenance(self, tmp_path):
        """No location, no patch. This is the invariant the whole file rests on."""
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_s3_bucket" "a" {\n  bucket = "a"\n}\n\n'
                       'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        for resource in resources:
            assert resource.has_provenance
            assert resource.startLine < resource.endLine


class TestParserBeatsTheRegex:
    """The cases infrabot's regex parser (terraform-patch.ts:211-330) got wrong.

    These are the reason the regex parser was not ported. Each one is a resource
    it would have mis-bounded or dropped entirely -- and a dropped resource is a
    missed vulnerability.
    """

    def test_heredoc_containing_braces(self, tmp_path):
        """A heredoc full of JSON braces destroys a brace-counting parser: it
        thinks the resource ended somewhere in the middle of the policy."""
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_iam_role" "example" {\n'
                       '  name = "r"\n\n'
                       '  assume_role_policy = <<-EOT\n'
                       '    {\n'
                       '      "Version": "2012-10-17",\n'
                       '      "Statement": [{ "Effect": "Allow" }]\n'
                       '    }\n'
                       '  EOT\n'
                       '}\n\n'
                       'resource "aws_s3_bucket" "after_the_heredoc" {\n'
                       '  bucket = "b"\n'
                       '}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        names = {r.resourceName for r in resources}
        assert "after_the_heredoc" in names, (
            "the resource following a brace-heavy heredoc was dropped"
        )
        role = next(r for r in resources if r.resourceName == "example")
        assert "EOT" in role.rawContent

    def test_for_each_expansion(self, tmp_path):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_s3_bucket" "each" {\n'
                       '  for_each = toset(["alpha", "beta"])\n'
                       '  bucket   = each.key\n'
                       '}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        assert resources, "for_each resource was dropped entirely"
        for resource in resources:
            assert resource.has_provenance

    def test_dynamic_block(self, tmp_path):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_security_group" "example" {\n'
                       '  name = "sg"\n\n'
                       '  dynamic "ingress" {\n'
                       '    for_each = var.ports\n\n'
                       '    content {\n'
                       '      from_port = ingress.value\n'
                       '      to_port   = ingress.value\n'
                       '    }\n'
                       '  }\n'
                       '}\n\n'
                       'resource "aws_s3_bucket" "after_the_dynamic" {\n'
                       '  bucket = "b"\n'
                       '}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        assert "after_the_dynamic" in {r.resourceName for r in resources}

    def test_nested_attribute_lookup_is_depth_aware(self, tmp_path):
        """`from_port` inside a `dynamic` block is not the resource's own
        attribute. A naive line scan would "find" it and patch the wrong line."""
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "example" {\n'
                       '  name = "lg"\n\n'
                       '  tags = {\n'
                       '    retention_in_days = "not-the-real-one"\n'
                       '  }\n'
                       '}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        assert pt._block_top_level_attr_line(resources[0], "retention_in_days") is None


# ===========================================================================
# Patch generation -- ported from terraform-patch.test.ts:121
# ===========================================================================


class TestPatchGeneration:
    def test_generates_a_patch_for_a_missing_attribute(self, tmp_path, catalog):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "app" {\n'
                       '  name = "/aws/app"\n'
                       '}\n'
        })
        patches = pt.generate_security_patches(
            root, [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app")], catalog,
            use_fmt=False,
        )
        assert len(patches) == 1
        assert patches[0].resourceType == "aws_cloudwatch_log_group"
        assert patches[0].resourceName == "app"
        assert patches[0].severity == "high"
        assert len(patches[0].changes) == 1
        assert patches[0].changes[0].type == "add"
        assert patches[0].changes[0].path == "retention_in_days"

    def test_marks_an_additive_single_attribute_fix_auto_applicable(self, tmp_path, catalog):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "app" {\n'
                       '  name = "/aws/app"\n'
                       '}\n'
        })
        patches = pt.generate_security_patches(
            root, [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app")], catalog,
            use_fmt=False,
        )
        assert patches[0].autoApplicable is True
        assert patches[0].autoApplyBlockedBy is None

    def test_generates_a_unified_diff(self, tmp_path, catalog):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "app" {\n'
                       '  name = "/aws/app"\n'
                       '}\n'
        })
        patches = pt.generate_security_patches(
            root, [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app")], catalog,
            use_fmt=False,
        )
        diff = patches[0].diff
        assert diff.startswith("--- a/main.tf")
        assert "+++ b/main.tf" in diff
        assert "@@" in diff
        assert "+  retention_in_days = 365" in diff

    def test_handles_multiple_findings_on_the_same_resource(self, tmp_path, catalog):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "app" {\n'
                       '  name = "/aws/app"\n'
                       '}\n'
        })
        findings = [
            finding("CKV_AWS_338", "aws_cloudwatch_log_group.app"),
            finding("CKV_AWS_158", "aws_cloudwatch_log_group.app"),
        ]
        patches = pt.generate_security_patches(root, findings, catalog, use_fmt=False)
        assert len(patches) == 1
        assert len(patches[0].changes) >= 2
        assert set(patches[0].findingIds) == {f["id"] for f in findings}
        # CKV_AWS_158 drags in a KMS key -> the whole patch drops to diff-only.
        assert patches[0].autoApplicable is False

    def test_no_patch_for_a_resource_with_no_findings(self, tmp_path, catalog):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_s3_bucket" "lonely" {\n  bucket = "b"\n}\n'
        })
        assert pt.generate_security_patches(root, [], catalog, use_fmt=False) == []

    def test_no_patch_when_the_fix_is_already_present(self, tmp_path, catalog):
        """Idempotence. Re-running the patcher on a patched tree is a no-op."""
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "app" {\n'
                       '  name              = "/aws/app"\n'
                       '  retention_in_days = 365\n'
                       '}\n'
        })
        patches = pt.generate_security_patches(
            root, [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app")], catalog,
            use_fmt=False,
        )
        assert patches == []

    def test_unknown_rule_produces_no_patch(self, tmp_path, catalog):
        """Silence beats a guess: a rule with no catalog entry gets no diff, and
        is routed to the LLM path instead of being faked here."""
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
        })
        patches = pt.generate_security_patches(
            root, [finding("CKV_AWS_999999", "aws_s3_bucket.b")], catalog, use_fmt=False
        )
        assert patches == []

    def test_expression_valued_attribute_is_not_auto_applied(self, tmp_path, catalog):
        """`retention_in_days = var.log_retention_days` is a deliberate
        parameterisation. Overwriting it with a literal is a judgement call, so
        the patch is generated but never auto-applied."""
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "app" {\n'
                       '  name              = "/aws/app"\n'
                       '  retention_in_days = var.log_retention_days\n'
                       '}\n'
        })
        patches = pt.generate_security_patches(
            root, [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app")], catalog,
            use_fmt=False,
        )
        assert len(patches) == 1
        assert patches[0].changes[0].type == "modify"
        assert patches[0].autoApplicable is False
        assert "parameterisation" in patches[0].autoApplyBlockedBy

    def test_literal_valued_attribute_is_auto_applied(self, tmp_path, catalog):
        """...but `retention_in_days = 30` is just a wrong literal. SPEC §6.3
        explicitly counts `encrypted = true` (a false->true flip) as auto."""
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "app" {\n'
                       '  name              = "/aws/app"\n'
                       '  retention_in_days = 30\n'
                       '}\n'
        })
        patches = pt.generate_security_patches(
            root, [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app")], catalog,
            use_fmt=False,
        )
        assert patches[0].changes[0].type == "modify"
        assert patches[0].autoApplicable is True


class TestApplyPatches:
    def test_applies_a_patch_to_the_tree(self, tmp_path, catalog):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "app" {\n'
                       '  name = "/aws/app"\n'
                       '}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        patches = pt.generate_security_patches(
            root, [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app")], catalog,
            resources, use_fmt=False,
        )
        result = pt.apply_patches_to_tree(root, patches, resources, use_fmt=False)
        assert result.success
        assert result.appliedCount == 1
        assert result.modifiedFiles == ["main.tf"]
        with open(os.path.join(root, "main.tf"), encoding="utf-8") as fh:
            assert "retention_in_days = 365" in fh.read()

    def test_only_auto_applicable_reports_what_it_skipped(self, tmp_path, catalog):
        """SPEC §6.3 rail 6: 'a --fix run that silently applies 4 of 11 fixes and
        says done is a liar.'"""
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "app" {\n'
                       '  name = "/aws/app"\n'
                       '}\n'
        })
        resources, _ = pt.load_terraform_resources(root)
        findings = [
            finding("CKV_AWS_338", "aws_cloudwatch_log_group.app"),   # auto
            finding("CKV_AWS_158", "aws_cloudwatch_log_group.app"),   # never (KMS)
        ]
        patches = pt.generate_security_patches(root, findings, catalog, resources,
                                               use_fmt=False)
        result = pt.apply_patches_to_tree(
            root, patches, resources, only_auto_applicable=True, use_fmt=False
        )
        assert result.skippedCount == 1
        assert result.skipped[0]["reason"]
        assert result.appliedCount == 0  # the two share one patch; it is diff-only
        with open(os.path.join(root, "main.tf"), encoding="utf-8") as fh:
            assert "kms_key_id" not in fh.read()

    def test_idempotent_reapplication(self, tmp_path, catalog):
        root = write_tree(tmp_path, {
            "main.tf": 'resource "aws_cloudwatch_log_group" "app" {\n'
                       '  name = "/aws/app"\n'
                       '}\n'
        })
        f = [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app")]
        for _ in range(2):
            resources, _ = pt.load_terraform_resources(root)
            patches = pt.generate_security_patches(root, f, catalog, resources,
                                                   use_fmt=False)
            pt.apply_patches_to_tree(root, patches, resources, use_fmt=False)
        with open(os.path.join(root, "main.tf"), encoding="utf-8") as fh:
            assert fh.read().count("retention_in_days") == 1


class TestCommitMessage:
    """terraform-patch.ts:1095 -- one commit per finding group, so a bad fix is
    one `git revert` away."""

    def test_leads_with_the_worst_severity(self):
        patches = [
            pt.TerraformPatch("a.tf", "aws_s3_bucket", "a", "aws_s3_bucket.a",
                              [change(description="fix a")], "", ["f1"], ["R1"],
                              "critical", True),
            pt.TerraformPatch("a.tf", "aws_s3_bucket", "b", "aws_s3_bucket.b",
                              [change(description="fix b")], "", ["f2"], ["R2"],
                              "low", True),
        ]
        message = pt.generate_commit_message(patches, 2, 1)
        assert message.startswith("fix: apply 1 critical security patches")
        assert "CRITICAL:" in message
        assert "aws_s3_bucket.a: fix a" in message


class TestFixCatalog:
    def test_has_thirty_rules(self, catalog):
        assert len(catalog) == 30

    def test_every_rule_declares_its_auto_apply_stance_with_a_rationale(self, catalog):
        for rule_id, rule in catalog.rules.items():
            assert isinstance(rule.get("autoApplicable"), bool), rule_id
            assert rule.get("rationale"), f"{rule_id}: no rationale for its auto stance"
            assert rule.get("category"), f"{rule_id}: no category"

    def test_rules_are_prioritised_by_measured_corpus_frequency(self, catalog):
        """The catalog is not a wishlist -- every rule is one that actually fires
        on the corpus, and each carries the count that justified its inclusion."""
        for rule_id, rule in catalog.rules.items():
            assert rule.get("corpusCount", 0) >= 1, f"{rule_id}: no measured frequency"


# ===========================================================================
# End-to-end against the real corpus. These run the real toolchain.
# ===========================================================================

TERRAFORM = shutil.which("terraform")
CHECKOV = shutil.which("checkov")


@pytest.mark.skipif(not CHECKOV, reason="checkov not installed")
class TestCorpusEndToEnd:
    """The acceptance criteria, executed rather than asserted."""

    @pytest.fixture(scope="class")
    def patched_tree(self, tmp_path_factory):
        """tf-03 is the one fixture that is already `terraform fmt` clean, which
        makes it the strict case for the fmt guarantee."""
        sys.path.insert(0, SCRIPTS)
        import run_checkov

        src = os.path.join(FIXTURES, "tf-03-data-lake")
        dst = str(tmp_path_factory.mktemp("corpus") / "tf-03")
        shutil.copytree(src, dst)

        before = run_checkov.run_checkov(dst)["findings"]
        catalog = pt.FixCatalog.load()
        resources, _ = pt.load_terraform_resources(dst)
        patches = pt.generate_security_patches(dst, before, catalog, resources)
        pt.apply_patches_to_tree(dst, patches, resources)
        after = run_checkov.run_checkov(dst)["findings"]
        return dst, before, after, patches

    def test_checkov_stops_reporting_every_fixed_finding(self, patched_tree):
        """The real proof: not 'we emitted a diff', but 'the scanner shut up'."""
        _, before, after, patches = patched_tree
        before_pairs = {(f["ruleId"], f["location"]["resourceAddress"]) for f in before}
        after_pairs = {(f["ruleId"], f["location"]["resourceAddress"]) for f in after}
        attempted = {r for p in patches for r in p.ruleIds}

        still_firing = {
            (rule, addr) for (rule, addr) in (before_pairs & after_pairs)
            if rule in attempted
        }
        assert not still_firing, (
            f"the patcher claimed to fix these, and Checkov still reports them: "
            f"{sorted(still_firing)}"
        )

    def test_every_patch_produces_a_parseable_unified_diff(self, patched_tree):
        _, _, _, patches = patched_tree
        assert patches
        for patch in patches:
            assert patch.diff.startswith("--- a/")
            assert "\n+++ b/" in patch.diff
            assert "\n@@ " in patch.diff
            assert any(l.startswith("+") and not l.startswith("+++")
                       for l in patch.diff.split("\n"))

    @pytest.mark.skipif(not TERRAFORM, reason="terraform not installed")
    def test_patched_tree_survives_terraform_fmt_check(self, patched_tree):
        root, _, _, _ = patched_tree
        proc = subprocess.run(
            ["terraform", "fmt", "-check", "-recursive", "-no-color"],
            cwd=root, capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, (
            "the patch introduced formatting terraform fmt would rewrite:\n"
            + proc.stdout
        )


# ===========================================================================
# The emitted patch set must APPLY. Proven by shelling out to `git apply`,
# because that is the only proof that counts.
# ===========================================================================


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


@pytest.mark.skipif(not CHECKOV, reason="checkov not installed")
@pytest.mark.parametrize("fixture", [
    "tf-01-three-tier-webapp",
    "tf-02-serverless-api",
    "tf-03-data-lake",
    "tf-04-container-platform",
    "tf-05-cicd-pipeline",
])
class TestEmittedPatchSetApplies:
    """A tool whose headline output is "here are the fixes" cannot emit fixes
    that do not apply.

    The per-finding diffs are each computed against the PRISTINE file, so a set
    of them touching the same file cannot be applied -- the second one fails,
    because the first shifted its line offsets:

        error: patch failed: s3.tf:248
        error: s3.tf: patch does not apply

    So `generate_file_patches()` emits one coherent diff per file, and THAT is
    what `export_patch_files`, `--fix`, and any "apply all" path consume.

    These tests do not inspect the diff text and conclude it looks right. They
    run `git apply` on it. That is the check that catches this class of bug, and
    it is the check that was missing.
    """

    @pytest.fixture
    def repo(self, fixture, tmp_path):
        import run_checkov

        root = str(tmp_path / fixture)
        shutil.copytree(os.path.join(FIXTURES, fixture), root)
        _git(root, "init", "-q")
        _git(root, "add", "-A")
        _git(root, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")

        findings = run_checkov.run_checkov(root)["findings"]
        catalog = pt.FixCatalog.load()
        resources, _ = pt.load_terraform_resources(root)
        patches = pt.generate_security_patches(root, findings, catalog, resources)
        file_patches = pt.generate_file_patches(root, patches, resources)
        return root, patches, file_patches, findings

    def test_git_apply_check_passes_on_the_emitted_set(self, repo, tmp_path):
        root, _, file_patches, _ = repo
        assert file_patches, "no patch set emitted"
        pset = str(tmp_path / "fixes.patch")
        pt.write_patch_set(file_patches, pset)

        proc = _git(root, "apply", "--check", "-v", pset)
        assert proc.returncode == 0, (
            "the emitted patch set does not apply:\n" + proc.stderr
        )

    def test_git_apply_reproduces_the_in_process_result_exactly(self, repo, tmp_path):
        """If `git apply` and `apply_patches_to_tree` disagree, the report is
        lying about one of them."""
        import run_checkov

        root, patches, file_patches, _ = repo

        # path A: git apply the emitted set
        pset = str(tmp_path / "fixes.patch")
        pt.write_patch_set(file_patches, pset)
        assert _git(root, "apply", pset).returncode == 0
        via_git = {f: open(os.path.join(root, f), encoding="utf-8").read()
                   for f in [fp.file for fp in file_patches]}
        after_git = {(f["ruleId"], f["location"]["resourceAddress"])
                     for f in run_checkov.run_checkov(root)["findings"]}

        # path B: in-process apply, from the pristine tree
        assert _git(root, "checkout", "--", ".").returncode == 0
        resources, _ = pt.load_terraform_resources(root)
        pt.apply_patches_to_tree(root, patches, resources)
        via_apply = {f: open(os.path.join(root, f), encoding="utf-8").read()
                     for f in [fp.file for fp in file_patches]}
        after_apply = {(f["ruleId"], f["location"]["resourceAddress"])
                       for f in run_checkov.run_checkov(root)["findings"]}

        assert via_git == via_apply, "git apply and apply_patches_to_tree diverged"
        assert after_git == after_apply, "the two paths leave Checkov in different states"

    def test_one_patch_per_file_not_per_resource(self, repo):
        """The structural guarantee: the emitted set never contains two diffs
        against the same file, which is the thing that made it inapplicable."""
        _, _, file_patches, _ = repo
        files = [fp.file for fp in file_patches]
        assert len(files) == len(set(files))

    def test_exported_patch_files_apply(self, repo, tmp_path):
        """`export_patch_files` is a --fix / review surface. Its output applies."""
        root, _, file_patches, _ = repo
        out = str(tmp_path / "patches")
        written = pt.export_patch_files(file_patches, out)
        assert written
        for path in written:
            proc = _git(root, "apply", "--check", path)
            assert proc.returncode == 0, (
                f"exported patch {os.path.basename(path)} does not apply:\n"
                + proc.stderr
            )
