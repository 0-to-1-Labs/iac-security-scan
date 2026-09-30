#!/usr/bin/env python3
"""
WS-11 tests: the ``--fix`` path and its six safety rails (SPEC §6.3).

The load-bearing assertions here are the accounting ones:

  * ``TestSkipReportIsComplete`` -- applied + skipped == total, every finding
    named. "A --fix run that silently applies 4 of 11 fixes and says done is a
    liar."
  * ``TestNeverAutoApplyAccessAffecting`` -- a real SG-CIDR / IAM finding from
    tf-04 is skipped, never applied, no matter what.

Every test runs against a COPY of a fixture under a tmp git repo. Nothing here
touches ``tests/fixtures`` (WS-8 grades against it) and nothing commits into the
iac-security-scan repo itself.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "skills", "iac-security-scan", "scripts")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
sys.path.insert(0, SCRIPTS)

import fix_apply as fx  # noqa: E402
import patch_terraform as pt  # noqa: E402
import run_checkov  # noqa: E402

HAS_CHECKOV = shutil.which("checkov") is not None
HAS_TFPARSE = pt._terraform_available() or True  # parse works without terraform


#: The real validator, captured before the autouse stub below replaces it.
_REAL_VALIDATE = fx.terraform_validate_module


@pytest.fixture(autouse=True)
def _no_network_validate(monkeypatch):
    """`terraform validate` needs `terraform init`, which downloads providers.
    Keep the suite offline: stand in a validator that reports "unknown". The
    validate-specific tests override this with their own stub."""
    monkeypatch.setattr(
        fx,
        "terraform_validate_module",
        lambda module_dir, plugin_cache_dir=None: {
            "available": False, "valid": None, "error": "stubbed in tests",
        },
    )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", root, *args],
        capture_output=True,
        text=True,
        env=GIT_ENV,
        check=False,
    )


def make_repo(tmp_path, files: dict) -> str:
    """A tmp git repo whose default branch is `main`, one initial commit."""
    root = os.path.join(str(tmp_path), "repo")
    os.makedirs(root, exist_ok=True)
    for name, content in files.items():
        path = os.path.join(root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    _git(root, "init", "-q")
    _git(root, "checkout", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


def copy_fixture_repo(tmp_path, fixture: str) -> str:
    """Copy a real fixture into a fresh tmp git repo on `main`."""
    src = os.path.join(FIXTURES, fixture)
    root = os.path.join(str(tmp_path), "repo")
    shutil.copytree(src, root)
    _git(root, "init", "-q")
    _git(root, "checkout", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


def finding(rule_id, address, file, severity="high", **extra):
    resource_type = address.split(".")[0]
    f = {
        "id": f"finding-{rule_id}-{address}",
        "ruleId": rule_id,
        "title": rule_id,
        "severity": severity,
        "source": ["checkov"],
        "location": {
            "file": file,
            "startLine": 1,
            "endLine": 1,
            "resourceAddress": address,
            "resourceType": resource_type,
            "service": resource_type.split("_")[1] if "_" in resource_type else "",
        },
    }
    f.update(extra)
    return f


# A minimal two-file tree with two independent auto-applicable findings, so we
# can assert one-commit-per-group without depending on Checkov.
LOGS_TF = """resource "aws_cloudwatch_log_group" "app" {
  name = "app"
}
"""

ECR_TF = """resource "aws_ecr_repository" "app" {
  name = "app"
}
"""


def two_group_repo(tmp_path):
    return make_repo(tmp_path, {"logs.tf": LOGS_TF, "ecr.tf": ECR_TF})


TWO_GROUP_FINDINGS = [
    finding("CKV_AWS_338", "aws_cloudwatch_log_group.app", "logs.tf"),
    finding("CKV_AWS_163", "aws_ecr_repository.app", "ecr.tf"),
]


# ===========================================================================
# Rail 1: never on a dirty tree, no --force
# ===========================================================================


class TestDirtyTreeRefused:
    def test_refuses_on_modified_file(self, tmp_path):
        root = two_group_repo(tmp_path)
        with open(os.path.join(root, "logs.tf"), "a") as fh:
            fh.write("\n# local edit\n")

        result = fx.run_fix(root, TWO_GROUP_FINDINGS)

        assert result.refused is True
        assert result.branch is None
        assert not result.applied
        assert "uncommitted" in result.error
        assert "no --force" in result.error.lower()

    def test_refuses_on_untracked_file(self, tmp_path):
        root = two_group_repo(tmp_path)
        with open(os.path.join(root, "new.tf"), "w") as fh:
            fh.write('resource "aws_s3_bucket" "x" { bucket = "x" }\n')

        result = fx.run_fix(root, TWO_GROUP_FINDINGS)
        assert result.refused is True
        assert "uncommitted" in result.error

    def test_refusal_writes_nothing(self, tmp_path):
        root = two_group_repo(tmp_path)
        with open(os.path.join(root, "logs.tf"), "a") as fh:
            fh.write("\n# local edit\n")
        before = _git(root, "rev-parse", "HEAD").stdout
        branches_before = _git(root, "branch").stdout

        fx.run_fix(root, TWO_GROUP_FINDINGS)

        assert _git(root, "rev-parse", "HEAD").stdout == before
        assert _git(root, "branch").stdout == branches_before

    def test_no_force_argument_exists(self):
        with pytest.raises(SystemExit):
            fx.main(["/tmp", "--findings", "/tmp/x.json", "--force"])

    def test_refuses_outside_git_repo(self, tmp_path):
        plain = os.path.join(str(tmp_path), "plain")
        os.makedirs(plain)
        with open(os.path.join(plain, "main.tf"), "w") as fh:
            fh.write(LOGS_TF)
        result = fx.run_fix(plain, [])
        assert result.refused is True
        assert "not a git repository" in result.error


# ===========================================================================
# Rail 2: a new branch, current branch verified, never main-assuming
# ===========================================================================


class TestBranch:
    def test_creates_timestamped_branch(self, tmp_path):
        root = two_group_repo(tmp_path)
        result = fx.run_fix(root, TWO_GROUP_FINDINGS, branch_name=None)
        assert result.branch.startswith("iac-security-scan/fix-")
        assert result.branch in _git(root, "branch").stdout

    def test_original_branch_untouched(self, tmp_path):
        root = two_group_repo(tmp_path)
        main_before = _git(root, "rev-parse", "main").stdout.strip()

        result = fx.run_fix(root, TWO_GROUP_FINDINGS)

        assert result.originalBranch == "main"
        # main still points at the initial commit -- no fixes landed on it.
        assert _git(root, "rev-parse", "main").stdout.strip() == main_before

    def test_does_not_assume_main(self, tmp_path):
        """Branches from wherever the user actually is (a feature branch),
        never from a hardcoded main."""
        root = two_group_repo(tmp_path)
        _git(root, "checkout", "-q", "-b", "feature/work")
        feat_before = _git(root, "rev-parse", "HEAD").stdout.strip()

        result = fx.run_fix(root, TWO_GROUP_FINDINGS)

        assert result.originalBranch == "feature/work"
        assert result.branch.startswith("iac-security-scan/fix-")
        # the fix branch descends from feature/work, not main
        assert _git(root, "rev-parse", "feature/work").stdout.strip() == feat_before
        merge_base = _git(
            root, "merge-base", result.branch, "feature/work"
        ).stdout.strip()
        assert merge_base == feat_before

    def test_refuses_detached_head(self, tmp_path):
        root = two_group_repo(tmp_path)
        head = _git(root, "rev-parse", "HEAD").stdout.strip()
        _git(root, "checkout", "-q", head)  # detach
        result = fx.run_fix(root, TWO_GROUP_FINDINGS)
        assert result.refused is True
        assert "detached" in result.error.lower()


# ===========================================================================
# Same directory in, same directory out (ISS-01) -- and back to the branch
# ===========================================================================


DECOY_TF = """locals {
  x = 1
}
"""


class TestModuleInASubdirectory:
    """The bug: patches were generated against the module dir but applied
    against the git toplevel, so `repo/infra/main.tf`'s fix landed in
    `repo/main.tf` (corrupting it) and was reported as a success."""

    def _repo(self, tmp_path):
        return make_repo(tmp_path, {"infra/main.tf": LOGS_TF, "main.tf": DECOY_TF})

    def test_fix_lands_in_the_module_file_not_the_decoy(self, tmp_path):
        root = self._repo(tmp_path)
        module = os.path.join(root, "infra")
        findings = [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app", "main.tf")]

        result = fx.run_fix(module, findings)

        assert result.success and result.appliedCount == 1, result.error
        assert result.moduleDir == module
        assert result.repoRoot == root
        branch = result.branch
        patched = _git(root, "show", f"{branch}:infra/main.tf").stdout
        assert "retention_in_days = 365" in patched
        decoy = _git(root, "show", f"{branch}:main.tf").stdout
        assert decoy == DECOY_TF, "the decoy at the repo root must be untouched"
        touched = _git(root, "show", "--name-only", "--format=", branch).stdout.split()
        assert touched == ["infra/main.tf"]

    def test_returns_to_the_original_branch(self, tmp_path):
        root = self._repo(tmp_path)
        module = os.path.join(root, "infra")
        result = fx.run_fix(
            module, [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app", "main.tf")]
        )
        assert result.branch
        assert result.returnedToOriginalBranch is True
        assert _git(root, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "main"
        # the working tree on main still has the ORIGINAL file
        with open(os.path.join(module, "main.tf"), encoding="utf-8") as fh:
            assert fh.read() == LOGS_TF
        assert "back on `main`" in fx.format_fix_report(result)

    def test_no_same_named_file_at_root_still_works(self, tmp_path):
        """Before the fix this path failed with `No such file`."""
        root = make_repo(tmp_path, {"infra/main.tf": LOGS_TF, "README.md": "x\n"})
        result = fx.run_fix(
            os.path.join(root, "infra"),
            [finding("CKV_AWS_338", "aws_cloudwatch_log_group.app", "main.tf")],
        )
        assert result.success and result.appliedCount == 1, result.error
        assert not result.skipped

    def test_unchanged_target_is_never_reported_as_applied(self, tmp_path, monkeypatch):
        """If the patcher writes nothing git can see, the group fails loudly."""
        root = two_group_repo(tmp_path)

        real_apply = fx.TERRAFORM_BACKEND.apply

        def lying_apply(path, patches, resources, use_fmt):
            res = real_apply(path, patches, resources, use_fmt)
            # undo the write but keep claiming success
            _git(path, "checkout", "--", *res.modifiedFiles)
            return res

        monkeypatch.setattr(fx.TERRAFORM_BACKEND, "apply", lying_apply)
        result = fx.run_fix(root, TWO_GROUP_FINDINGS)
        assert result.appliedCount == 0
        assert result.branch is None
        assert all(s.reasonCode == fx.SKIP_APPLY_FAILED for s in result.skipped)
        assert any("unchanged" in s.reason for s in result.skipped)
        assert _git(root, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "main"


# ===========================================================================
# terraform validate before commit
# ===========================================================================


class TestTerraformValidateGate:
    def test_validate_failure_reverts_and_skips(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            fx, "terraform_validate_module",
            lambda module_dir, plugin_cache_dir=None: {
                "available": True, "valid": False, "error": "Unsupported argument",
            },
        )
        root = two_group_repo(tmp_path)
        result = fx.run_fix(root, TWO_GROUP_FINDINGS)
        assert result.success
        assert result.appliedCount == 0
        assert result.branch is None
        reasons = [s.reason for s in result.skipped]
        assert all("terraform validate rejected" in r for r in reasons)
        # nothing written, nothing committed, back on main
        assert _git(root, "status", "--porcelain").stdout.strip() == ""
        assert "iac-security-scan/fix-" not in _git(root, "branch").stdout
        with open(os.path.join(root, "logs.tf"), encoding="utf-8") as fh:
            assert fh.read() == LOGS_TF

    def test_validate_pass_is_recorded(self, tmp_path, monkeypatch):
        calls = []

        def ok(module_dir, plugin_cache_dir=None):
            calls.append(module_dir)
            return {"available": True, "valid": True, "error": None}

        monkeypatch.setattr(fx, "terraform_validate_module", ok)
        root = two_group_repo(tmp_path)
        result = fx.run_fix(root, TWO_GROUP_FINDINGS)
        assert result.appliedCount == 2
        assert all(g.validation == "passed" for g in result.applied)
        assert calls and all(c == root for c in calls)

    def test_no_validate_flag_skips_it(self, tmp_path, monkeypatch):
        def boom(module_dir, plugin_cache_dir=None):
            raise AssertionError("validate must not run with validate=False")

        monkeypatch.setattr(fx, "terraform_validate_module", boom)
        root = two_group_repo(tmp_path)
        result = fx.run_fix(root, TWO_GROUP_FINDINGS, validate=False)
        assert result.appliedCount == 2
        assert all("skipped" in (g.validation or "") for g in result.applied)

    def test_real_validator_runs_on_a_copy(self, tmp_path):
        """The real function copies the module and never touches it. Without
        the network `init` fails and the verdict is `None`, never False."""
        if not pt._terraform_available():
            pytest.skip("terraform not installed")
        module = str(tmp_path / "m")
        os.makedirs(module)
        with open(os.path.join(module, "main.tf"), "w", encoding="utf-8") as fh:
            fh.write('variable "x" {\n  default = 1\n}\n')
        before = sorted(os.listdir(module))
        verdict = _REAL_VALIDATE(module)
        assert verdict["available"] is True
        assert verdict["valid"] in (True, None)
        assert sorted(os.listdir(module)) == before, "the module must not gain .terraform"


# ===========================================================================
# CloudFormation --fix (ISS-10)
# ===========================================================================


SNS_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Alerts:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: alerts
"""


class TestCloudFormationFix:
    @pytest.fixture(autouse=True)
    def _needs_cfn_lint(self):
        import parse_iac

        if not parse_iac.CFNLINT_AVAILABLE:
            pytest.skip("cfn-lint not installed")

    def test_cfn_module_in_a_subdirectory(self, tmp_path):
        root = make_repo(
            tmp_path, {"stacks/template.yaml": SNS_TEMPLATE, "template.yaml": SNS_TEMPLATE}
        )
        module = os.path.join(root, "stacks")
        findings = [
            {
                "id": "f-CKV_AWS_26-Alerts",
                "ruleId": "CKV_AWS_26",
                "title": "SNS topic not encrypted",
                "severity": "high",
                "location": {
                    "file": "template.yaml",
                    "startLine": 3,
                    "endLine": 6,
                    "resourceAddress": "AWS::SNS::Topic.Alerts",
                    "resourceType": "AWS::SNS::Topic",
                    "service": "SNS",
                },
            }
        ]
        result = fx.run_fix(module, findings, iac_format="cloudformation")
        assert result.success and result.appliedCount == 1, result.error
        assert result.iacFormat == "cloudformation"
        patched = _git(root, "show", f"{result.branch}:stacks/template.yaml").stdout
        assert "KmsMasterKeyId" in patched
        assert _git(root, "show", f"{result.branch}:template.yaml").stdout == SNS_TEMPLATE
        assert "CloudFormation" in _git(root, "log", "-1", "--format=%s", result.branch).stdout
        assert _git(root, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "main"

    def test_format_is_detected_from_the_directory(self, tmp_path):
        root = make_repo(tmp_path, {"template.yaml": SNS_TEMPLATE})
        result = fx.run_fix(root, [], dry_run=True)
        assert result.iacFormat == "cloudformation"

    def test_findings_only_format_is_refused(self, tmp_path):
        root = make_repo(tmp_path, {"deploy.yaml": "apiVersion: v1\nkind: Pod\n"})
        result = fx.run_fix(root, [], iac_format="kubernetes")
        assert result.success is False
        assert "findings-only" in (result.error or "")


# ===========================================================================
# Rail 3 + 5: only auto-applicable, one commit per finding group
# ===========================================================================


class TestApplyAndCommits:
    def test_one_commit_per_group(self, tmp_path):
        root = two_group_repo(tmp_path)
        result = fx.run_fix(root, TWO_GROUP_FINDINGS)

        assert result.success
        assert len(result.applied) == 2
        # distinct commit per finding group
        hashes = {g.commitHash for g in result.applied}
        assert len(hashes) == 2 and None not in hashes

        log = _git(root, "log", "--oneline", result.branch).stdout.strip().splitlines()
        # two fix commits on top of the initial commit
        assert len(log) == 3

    def test_only_auto_applicable_applied(self, tmp_path):
        root = two_group_repo(tmp_path)
        # add a non-auto finding (CKV_AWS_136 ECR immutable tags is diff-only)
        findings = TWO_GROUP_FINDINGS + [
            finding("CKV_AWS_136", "aws_ecr_repository.app", "ecr.tf"),
        ]
        result = fx.run_fix(root, findings)

        applied_rules = {r for g in result.applied for r in g.ruleIds}
        assert "CKV_AWS_136" not in applied_rules
        skipped_rules = {s.ruleId for s in result.skipped}
        assert "CKV_AWS_136" in skipped_rules

    def test_commit_message_has_no_coauthor_line(self, tmp_path):
        root = two_group_repo(tmp_path)
        result = fx.run_fix(root, TWO_GROUP_FINDINGS)
        body = _git(root, "log", "--format=%B", result.branch).stdout
        assert "Co-Authored-By" not in body
        assert "Co-authored-by" not in body

    def test_no_auto_applicable_creates_no_branch(self, tmp_path):
        root = two_group_repo(tmp_path)
        findings = [finding("CKV_AWS_136", "aws_ecr_repository.app", "ecr.tf")]
        result = fx.run_fix(root, findings)
        assert result.success
        assert result.branch is None
        # no iac-security-scan branch was created
        assert "iac-security-scan/fix-" not in _git(root, "branch").stdout


# ===========================================================================
# Rail 4: never auto-apply an access-affecting change (real tf-04 findings)
# ===========================================================================


class TestNeverAutoApplyAccessAffecting:
    """The one that must never regress. A security-group CIDR change or an IAM
    policy change is diff-only, always, and can therefore never appear in the
    applied set -- regardless of catalog flags or model confidence."""

    def test_sg_cidr_finding_never_applied(self, tmp_path):
        root = copy_fixture_repo(tmp_path, "tf-04-container-platform")
        # CKV_AWS_260: SG ingress open to 0.0.0.0/0 -- narrowing it is access-affecting
        findings = [
            finding(
                "CKV_AWS_260",
                "aws_vpc_security_group_ingress_rule.alb_http",
                "security-groups.tf",
                severity="critical",
            )
        ]
        result = fx.run_fix(root, findings)

        applied_ids = set(result.appliedFindingIds)
        assert findings[0]["id"] not in applied_ids
        skipped = {s.id: s for s in result.skipped}
        assert findings[0]["id"] in skipped
        assert skipped[findings[0]["id"]].reasonCode == fx.SKIP_ACCESS_AFFECTING
        # and no branch/commit touched it
        assert result.branch is None

    def test_iam_finding_never_applied(self, tmp_path):
        root = copy_fixture_repo(tmp_path, "tf-04-container-platform")
        # aws_iam_role_policy is in the never-auto-apply blast radius
        findings = [
            finding(
                "CKV_AWS_290",
                "aws_iam_role_policy.ecs_task",
                "iam.tf",
                severity="high",
            )
        ]
        result = fx.run_fix(root, findings)
        assert findings[0]["id"] not in set(result.appliedFindingIds)
        assert findings[0]["id"] in {s.id for s in result.skipped}

    def test_gate_is_patch_terraform_blocker(self, tmp_path):
        """The gate is the imported auto_apply_blocker, not a local reimpl."""
        assert fx.auto_apply_blocker is pt.auto_apply_blocker


# ===========================================================================
# Rail 6: report what was skipped and why (the load-bearing one)
# ===========================================================================


class TestSkipReportIsComplete:
    def _run_on_tf04(self, tmp_path):
        root = copy_fixture_repo(tmp_path, "tf-04-container-platform")
        payload = run_checkov.run_checkov(root)
        findings = payload["findings"]
        result = fx.run_fix(root, findings)
        return findings, result

    @pytest.mark.skipif(not HAS_CHECKOV, reason="checkov not installed")
    def test_applied_plus_skipped_equals_total(self, tmp_path):
        findings, result = self._run_on_tf04(tmp_path)
        assert result.totalFindings == len(findings)
        assert result.appliedCount + result.skippedCount == len(findings)
        assert result.accounts_for_every_finding() is True

    @pytest.mark.skipif(not HAS_CHECKOV, reason="checkov not installed")
    def test_every_finding_named_exactly_once(self, tmp_path):
        findings, result = self._run_on_tf04(tmp_path)
        seen = result.appliedFindingIds + [s.id for s in result.skipped]
        assert sorted(seen) == sorted(f["id"] for f in findings)
        assert len(seen) == len(set(seen))  # no double counting

    @pytest.mark.skipif(not HAS_CHECKOV, reason="checkov not installed")
    def test_every_skip_has_a_specific_reason(self, tmp_path):
        _, result = self._run_on_tf04(tmp_path)
        for item in result.skipped:
            assert item.reasonCode in fx.SKIP_HEADINGS
            assert item.reason.strip()
            # a reason names something concrete, not just "skipped"
            assert len(item.reason) > 20

    def test_dry_run_accounting_balances(self, tmp_path):
        root = two_group_repo(tmp_path)
        findings = TWO_GROUP_FINDINGS + [
            finding("CKV_AWS_136", "aws_ecr_repository.app", "ecr.tf"),
        ]
        result = fx.run_fix(root, findings, dry_run=True)
        assert result.dryRun is True
        assert result.accounts_for_every_finding()
        # dry run writes nothing
        assert "iac-security-scan/fix-" not in _git(root, "branch").stdout

    def test_reason_codes_cover_each_bucket(self, tmp_path):
        root = copy_fixture_repo(tmp_path, "tf-04-container-platform")
        findings = [
            finding("CKV_AWS_260", "aws_vpc_security_group_ingress_rule.alb_http",
                    "security-groups.tf"),               # access-affecting
            finding("CKV_AWS_136", "aws_ecr_repository.repos[\"api\"]", "ecr.tf"),  # not-auto
            finding("CKV_AWS_999", "aws_instance.none", "main.tf"),  # no patch
            finding("CKV_AWS_1", "aws_config.acct", "main.tf",
                    remediationType="cli", nonIaCCategory="account-setting"),  # not-iac
            finding("CKV_AWS_500", "aws_lambda_function.none", "main.tf",
                    fix={"diff": "x", "confidence": "low"}),  # llm-generated
        ]
        result = fx.run_fix(root, findings)
        codes = {s.reasonCode for s in result.skipped}
        assert fx.SKIP_ACCESS_AFFECTING in codes
        assert fx.SKIP_NOT_IAC in codes
        assert fx.SKIP_LLM_GENERATED in codes
        assert fx.SKIP_NO_PATCH in codes

    def test_report_names_every_skipped_finding(self, tmp_path):
        root = two_group_repo(tmp_path)
        findings = TWO_GROUP_FINDINGS + [
            finding("CKV_AWS_136", "aws_ecr_repository.app", "ecr.tf"),
        ]
        result = fx.run_fix(root, findings)
        report = fx.format_fix_report(result)
        for item in result.skipped:
            assert item.ruleId in report
            assert item.resourceAddress in report

    def test_refusal_report_explains(self, tmp_path):
        root = two_group_repo(tmp_path)
        with open(os.path.join(root, "logs.tf"), "a") as fh:
            fh.write("\n#x\n")
        result = fx.run_fix(root, TWO_GROUP_FINDINGS)
        report = fx.format_fix_report(result)
        assert "refused" in report.lower()
        assert "uncommitted" in report


# ===========================================================================
# CLI exit codes (SPEC §9.2)
# ===========================================================================


class TestCli:
    def test_exit_1_on_refusal(self, tmp_path, capsys):
        root = two_group_repo(tmp_path)
        with open(os.path.join(root, "logs.tf"), "a") as fh:
            fh.write("\n#x\n")
        findings_path = os.path.join(str(tmp_path), "f.json")
        with open(findings_path, "w") as fh:
            json.dump({"findings": TWO_GROUP_FINDINGS}, fh)
        code = fx.main([root, "--findings", findings_path])
        assert code == 1

    def test_exit_0_on_success(self, tmp_path):
        root = two_group_repo(tmp_path)
        findings_path = os.path.join(str(tmp_path), "f.json")
        with open(findings_path, "w") as fh:
            json.dump({"findings": TWO_GROUP_FINDINGS}, fh)
        code = fx.main([root, "--findings", findings_path, "--no-validate"])
        assert code == 0

    def test_exit_2_on_missing_dir(self):
        assert fx.main(["/no/such/dir", "--findings", "/no/such.json"]) == 2
