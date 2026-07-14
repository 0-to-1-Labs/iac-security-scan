#!/usr/bin/env python3
"""
Tests for the deterministic CloudFormation patcher (WS-13).

Acceptance is MEASURED, not asserted (SPEC 6.3 / plan Phase 3):

  1. Each catalog rule produces a valid unified diff on a triggering fixture, and
     the per-file patch set passes `git apply --check` on all 5 CFN fixtures.
  2. Every fix survives cfn-lint with NO new errors vs the pristine baseline
     (some fixtures fail at baseline; we enforce no-regression, not zero).
  3. Checkov re-run on the patched template no longer reports the fixed rule on
     the patched resource. We watch it disappear.
  4. The never-auto-apply list is enforced: none of SecurityGroup CIDR, IAM
     policy/wildcard, S3 BucketPolicy, KMS key policy, or NACL is EVER
     autoApplicable. This test does not get relaxed.

The Checkov + cfn-lint passes are slow, so all per-fixture analysis is computed
ONCE and cached at module scope.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, "skills", "iac-security-scan", "scripts")
sys.path.insert(0, SCRIPTS)

import run_checkov  # noqa: E402
import patch_cloudformation as P  # noqa: E402
from patch_terraform import PatchChange  # noqa: E402


CFN_FIXTURES = sorted(
    d
    for d in glob.glob(os.path.join(ROOT, "tests", "fixtures", "cfn-*"))
    if os.path.isdir(d)
)


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


requires_checkov = pytest.mark.skipif(not _have("checkov"), reason="checkov not installed")
requires_cfn_lint = pytest.mark.skipif(not _have("cfn-lint"), reason="cfn-lint not installed")


# ===========================================================================
# Per-fixture analysis, computed once and cached
# ===========================================================================


def _cfn_lint_rules(template_path: str) -> set:
    """The set of cfn-lint rule IDs firing on a template (empty set on clean)."""
    proc = subprocess.run(
        ["cfn-lint", "--format", "json", template_path],
        capture_output=True,
        text=True,
    )
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return {"__unparseable__"}
    return {m["Rule"]["Id"] for m in data}


def _checkov_failed_by_resource(root: str) -> dict:
    """{logicalId: {ruleId, ...}} of FAILED checkov checks in a directory."""
    payload = run_checkov.run_checkov(root, framework=("cloudformation", "secrets"))
    out: dict = {}
    for f in payload.get("findings", []):
        logical = P._logical_id(f["location"]["resourceAddress"])
        out.setdefault(logical, set()).add(f["ruleId"])
    return out


class _Analysis:
    """Everything expensive about one fixture, computed once."""

    def __init__(self, fixture_dir: str):
        self.dir = fixture_dir
        self.name = os.path.basename(fixture_dir)
        self.template = os.path.join(fixture_dir, "template.yaml")

        payload = run_checkov.run_checkov(
            fixture_dir, framework=("cloudformation", "secrets")
        )
        self.findings = payload.get("findings", [])
        self.catalog = P.CFNFixCatalog.load()
        self.resources, _ = P.load_cloudformation_resources(self.template)
        self.patches = P.generate_security_patches(
            self.template, self.findings, self.catalog, self.resources
        )
        self.file_patches = P.generate_file_patches(
            fixture_dir, self.patches, self.resources
        )

        # Baseline cfn-lint (pristine) and the patched template.
        self._baseline_lint = None
        self._patched_lint = None
        self._patched_dir = None

    # --- lazily-materialised, cfn-lint/checkov-dependent bits ---

    def baseline_lint(self) -> set:
        if self._baseline_lint is None:
            self._baseline_lint = _cfn_lint_rules(self.template)
        return self._baseline_lint

    def patched_dir(self) -> str:
        """A temp copy of the fixture with ALL patches applied on disk."""
        if self._patched_dir is None:
            tmp = tempfile.mkdtemp(prefix="cfnpatch-")
            shutil.copytree(self.dir, tmp, dirs_exist_ok=True)
            P.apply_patches_to_tree(tmp, self.patches, self.resources)
            self._patched_dir = tmp
        return self._patched_dir

    def patched_template(self) -> str:
        return os.path.join(self.patched_dir(), "template.yaml")

    def patched_lint(self) -> set:
        if self._patched_lint is None:
            self._patched_lint = _cfn_lint_rules(self.patched_template())
        return self._patched_lint


_CACHE: dict = {}


def analysis(fixture_dir: str) -> _Analysis:
    if fixture_dir not in _CACHE:
        _CACHE[fixture_dir] = _Analysis(fixture_dir)
    return _CACHE[fixture_dir]


def _id(fixture_dir: str) -> str:
    return os.path.basename(fixture_dir)


# ===========================================================================
# Catalog integrity (fast, no external tools)
# ===========================================================================


class TestCatalog:
    def test_loads(self):
        cat = P.CFNFixCatalog.load()
        assert len(cat) >= 8

    def test_every_rule_well_formed(self):
        cat = P.CFNFixCatalog.load()
        for rule_id in cat.rule_ids:
            rule = cat.get(rule_id)
            assert rule["resourceTypes"], rule_id
            assert rule["changes"], rule_id
            assert "category" in rule, rule_id
            assert "autoApplicable" in rule, rule_id
            for spec in rule["changes"]:
                assert spec["kind"] in ("attribute", "block"), rule_id
                assert "name" in spec, rule_id
                if spec["kind"] == "attribute":
                    assert "value" in spec, rule_id
                else:
                    assert spec.get("body"), rule_id

    def test_rule_ids_are_checkov_shaped(self):
        cat = P.CFNFixCatalog.load()
        for rule_id in cat.rule_ids:
            assert rule_id.startswith(("CKV_AWS_", "CKV2_AWS_")), rule_id


class TestJoin:
    def test_logical_id_extraction(self):
        assert P._logical_id("AWS::S3::Bucket.WebBucket") == "WebBucket"
        assert P._logical_id("AWS::EC2::SecurityGroup.SG1") == "SG1"
        assert P._logical_id("WebBucket") == "WebBucket"
        assert P._logical_id("") == ""


# ===========================================================================
# 4. THE NEVER-AUTO-APPLY LINE (SPEC 6.3) -- this test does not get relaxed
# ===========================================================================


class TestNeverAutoApply:
    """SG CIDR, IAM, S3 BucketPolicy, KMS key policy, NACL are NEVER auto-applicable."""

    @pytest.mark.parametrize(
        "resource_type",
        [
            "AWS::EC2::SecurityGroup",  # 1. SG ingress CIDR
            "AWS::EC2::SecurityGroupIngress",
            "AWS::IAM::Role",  # 2. IAM policy/wildcard
            "AWS::IAM::Policy",
            "AWS::IAM::ManagedPolicy",
            "AWS::S3::BucketPolicy",  # 3. bucket policy
            "AWS::KMS::Key",  # 4. KMS key policy
            "AWS::EC2::NetworkAcl",  # 5. NACL
            "AWS::EC2::NetworkAclEntry",
        ],
    )
    def test_never_list_resource_types_blocked(self, resource_type):
        change = PatchChange(
            type="add", kind="attribute", path="SomeAdditiveProp",
            description="x", newValue="true", targetAddress="R",
        )
        # An otherwise-perfectly-additive change is STILL vetoed by the type.
        assert P.cfn_auto_apply_blocker([change], resource_type) is not None
        assert P.is_auto_applicable([change], resource_type, rule_auto=True) is False

    @pytest.mark.parametrize(
        "category",
        ["security-group-cidr", "iam-wildcard", "bucket-policy", "kms-key-policy", "network-acl"],
    )
    def test_never_list_categories_blocked(self, category):
        change = PatchChange(
            type="add", kind="attribute", path="X", description="x",
            newValue="true", category=category, targetAddress="R",
        )
        assert P.cfn_auto_apply_blocker([change], "AWS::S3::Bucket") is not None
        assert P.is_auto_applicable([change], "AWS::S3::Bucket", rule_auto=True) is False

    @pytest.mark.parametrize(
        "attribute",
        ["KeyPolicy", "PolicyDocument", "AssumeRolePolicyDocument",
         "SecurityGroupIngress", "CidrIp", "PubliclyAccessible"],
    )
    def test_never_list_attributes_blocked(self, attribute):
        change = PatchChange(
            type="add", kind="attribute", path=attribute, description="x",
            newValue="v", targetAddress="R",
        )
        assert P.cfn_auto_apply_blocker([change], "AWS::S3::Bucket") is not None

    def test_removal_never_auto_applies(self):
        change = PatchChange(
            type="remove", kind="attribute", path="X", description="x",
            targetAddress="R",
        )
        assert P.cfn_auto_apply_blocker([change], "AWS::S3::Bucket") is not None

    def test_overwriting_an_intrinsic_is_blocked(self):
        # A modify that would replace `!If [...]` / `!Ref x` with a literal throws
        # away a deliberate parameterisation -> not auto-applicable.
        change = PatchChange(
            type="modify", kind="attribute", path="MultiAZ", description="x",
            oldValue="MultiAZ: !If [IsProduction, true, false]", newValue="true",
            targetAddress="R",
        )
        assert P.cfn_auto_apply_blocker([change], "AWS::RDS::DBInstance") is not None

    def test_a_plain_additive_change_is_allowed(self):
        # Control: an additive scalar on an ordinary resource is auto-applicable.
        change = PatchChange(
            type="add", kind="attribute", path="StorageEncrypted", description="x",
            newValue="true", category="encryption", targetAddress="R",
        )
        assert P.cfn_auto_apply_blocker([change], "AWS::RDS::DBInstance") is None
        assert P.is_auto_applicable([change], "AWS::RDS::DBInstance", rule_auto=True) is True

    @requires_checkov
    @pytest.mark.parametrize("fixture", CFN_FIXTURES, ids=_id)
    def test_no_generated_patch_on_never_type_is_auto(self, fixture):
        """On real fixtures: no patch touching a never-list resource type is auto."""
        a = analysis(fixture)
        for patch in a.patches:
            if patch.resourceType in P.NEVER_AUTO_APPLY_RESOURCE_TYPES_CFN:
                assert patch.autoApplicable is False, (
                    f"{a.name}/{patch.logicalId} ({patch.resourceType}) "
                    "is on the never-list but was marked auto-applicable"
                )

    @requires_checkov
    def test_kms_and_public_access_rules_are_diff_only(self):
        """The two diff-only catalog rules must never be marked auto anywhere."""
        seen_kms = seen_public = False
        for fixture in CFN_FIXTURES:
            for patch in analysis(fixture).patches:
                if "CKV_AWS_7" in patch.ruleIds:  # KMS key rotation
                    seen_kms = True
                    assert patch.autoApplicable is False
                if "CKV_AWS_17" in patch.ruleIds:  # RDS PubliclyAccessible
                    seen_public = True
                    assert patch.autoApplicable is False
        assert seen_kms, "expected CKV_AWS_7 to fire somewhere in the corpus"
        assert seen_public, "expected CKV_AWS_17 to fire somewhere in the corpus"


# ===========================================================================
# 1. Valid unified diffs + git apply --check on all 5 fixtures
# ===========================================================================


def _git_apply_checks(fixture_dir: str, patch_text: str) -> subprocess.CompletedProcess:
    """git apply --check the patch against a fresh committed copy of the fixture."""
    tmp = tempfile.mkdtemp(prefix="cfngit-")
    try:
        shutil.copytree(fixture_dir, tmp, dirs_exist_ok=True)
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        subprocess.run(["git", "init", "-q"], cwd=tmp, check=True, env=env)
        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True, env=env)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp, check=True, env=env)
        patch_file = os.path.join(tmp, "fix.patch")
        with open(patch_file, "w", encoding="utf-8") as fh:
            fh.write(patch_text)
        return subprocess.run(
            ["git", "apply", "--check", "fix.patch"],
            cwd=tmp, capture_output=True, text=True, env=env,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class TestDiffValidity:
    @requires_checkov
    @pytest.mark.parametrize("fixture", CFN_FIXTURES, ids=_id)
    def test_file_patch_set_git_applies(self, fixture):
        a = analysis(fixture)
        if not a.file_patches:
            pytest.skip(f"{a.name}: no patches generated (no fixable findings)")
        combined = "".join(fp.diff for fp in a.file_patches)
        result = _git_apply_checks(fixture, combined)
        assert result.returncode == 0, (
            f"{a.name}: git apply --check failed:\n{result.stderr}\n---\n{combined}"
        )

    @requires_checkov
    @pytest.mark.parametrize("fixture", CFN_FIXTURES, ids=_id)
    def test_every_patch_has_a_diff(self, fixture):
        a = analysis(fixture)
        for patch in a.patches:
            assert patch.diff.startswith("--- a/"), patch.logicalId
            assert patch.diff.endswith("\n")
            assert patch.ruleIds


# ===========================================================================
# 2. cfn-lint: no new errors vs baseline
# ===========================================================================


class TestCfnLintNoRegression:
    @requires_checkov
    @requires_cfn_lint
    @pytest.mark.parametrize("fixture", CFN_FIXTURES, ids=_id)
    def test_no_new_lint_rules(self, fixture):
        a = analysis(fixture)
        if not a.patches:
            pytest.skip(f"{a.name}: no patches")
        base = a.baseline_lint()
        patched = a.patched_lint()
        new_rules = patched - base
        assert not new_rules, (
            f"{a.name}: patch introduced new cfn-lint rules {sorted(new_rules)} "
            f"(baseline={sorted(base)})"
        )


# ===========================================================================
# 3. Checkov closure: the fixed rule disappears on re-run
# ===========================================================================


class TestCheckovClosure:
    @requires_checkov
    @pytest.mark.parametrize("fixture", CFN_FIXTURES, ids=_id)
    def test_patched_resources_no_longer_report_fixed_rule(self, fixture):
        a = analysis(fixture)
        if not a.patches:
            pytest.skip(f"{a.name}: no patches")
        after = _checkov_failed_by_resource(a.patched_dir())
        for patch in a.patches:
            still = after.get(patch.logicalId, set())
            for rule_id in patch.ruleIds:
                assert rule_id not in still, (
                    f"{a.name}/{patch.logicalId}: {rule_id} still fires after patch"
                )


# ===========================================================================
# Corpus-wide coverage report (informational, but asserts every rule is real)
# ===========================================================================


@requires_checkov
def test_every_catalog_rule_closes_at_least_one_finding(capsys):
    """Every rule in the catalog must verifiably close a real corpus finding.

    A rule that never fires (or never closes) is dead weight and a maintenance
    liability -- WS-5's discipline: EXCLUDE what you cannot do correctly.
    """
    cat = P.CFNFixCatalog.load()
    closed_by_rule: dict = {r: 0 for r in cat.rule_ids}
    total_findings = 0
    total_closed = 0

    for fixture in CFN_FIXTURES:
        a = analysis(fixture)
        total_findings += len(a.findings)
        after = _checkov_failed_by_resource(a.patched_dir())
        for patch in a.patches:
            still = after.get(patch.logicalId, set())
            for rule_id in patch.ruleIds:
                if rule_id not in still:
                    closed_by_rule[rule_id] = closed_by_rule.get(rule_id, 0) + 1
                    total_closed += 1

    never_closed = [r for r, n in closed_by_rule.items() if n == 0]
    coverage = 100.0 * total_closed / total_findings if total_findings else 0.0

    with capsys.disabled():
        print("\n=== CFN fix-catalog coverage ===")
        print(f"catalog rules: {len(cat)}")
        print(f"total corpus findings: {total_findings}")
        print(f"findings verifiably closed: {total_closed} ({coverage:.0f}%)")
        for rule_id in cat.rule_ids:
            print(f"  {rule_id}: closed {closed_by_rule[rule_id]}")
        if never_closed:
            print(f"RULES THAT NEVER CLOSED: {never_closed}")

    assert not never_closed, f"catalog rules that never close a finding: {never_closed}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
