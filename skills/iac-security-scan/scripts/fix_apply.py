#!/usr/bin/env python3
"""
WS-11: the ``--fix`` path, and its six safety rails (SPEC §6.3).

This module writes to a user's repository. Everything in it exists to make that
safe, and every rail below is load-bearing:

  1. **Never on a dirty tree.** `git status --porcelain` non-empty -> refuse and
     say why. There is no `--force`. Not "there is a `--force` you shouldn't
     use" -- there is no flag.
  2. **Always a new branch**, `iac-security-scan/fix-<timestamp>`. We verify the
     current branch and return to it; we never assume `main` and never commit to
     whatever the user happened to be standing on.
  3. **Only `autoApplicable` findings.** On the corpus that is 4 of 59 patches.
     That ratio is the design working, not a bug: additive, single-attribute,
     semantically unambiguous, or it does not land.
  4. **Never an access-affecting change** -- SG CIDR narrowing, IAM wildcard
     removal, bucket policies, KMS key policies, network ACLs. Diff-only, always,
     regardless of model confidence. The gate is `patch_terraform.auto_apply_blocker()`
     (and its CloudFormation mirror) and it is imported, never reimplemented,
     because a second copy of a safety check is a second copy that can drift.
  5. **One commit per finding group** -- one commit per resource the findings land
     on -- so a bad fix is one `git revert` away, not a wholesale rollback.
  6. **Report what was skipped and why.** A `--fix` run that silently applies 4 of
     11 fixes and says "done" is a liar. Every finding this run did not fix is
     named in the report with a specific reason. `applied + skipped == total`,
     enforced by `FixRunResult.accounts_for_every_finding()`.

Two more invariants, both added after a real bug:

  * **Patches are generated and applied against the SAME directory** -- the
    module directory the user pointed at. Every git call runs with ``-C`` that
    directory, so a module that is a subdirectory of its repository never has
    its patch applied to a same-named file at the repository root. After a
    write, git must see the target file as modified, or the group fails.
  * **A patch terraform rejects is never written.** `terraform fmt` runs on the
    patched text (patch_terraform), and when the `terraform` binary is present
    `terraform validate` runs on a temp copy of the patched module before the
    commit. A validate failure reverts the group's files and is reported.

Never runs `terraform apply`. Never `plan`s against a real backend. The only
external commands are `git`, `terraform fmt`, and `terraform init -backend=false`
+ `terraform validate` (which download providers but never read state).

Between finding groups the tree is **re-parsed**, so each group's changes are
computed against the file as it now stands. Applying group 2's patch with group
1's line numbers is how you corrupt a file, and re-parsing also means a shared
companion resource committed by group 1 (a KMS key, a log bucket) is in the
`existing` set when group 2 runs, instead of being emitted twice.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import patch_cloudformation as pc  # noqa: E402
import patch_terraform as pt  # noqa: E402

# The safety gate itself. Imported, not reimplemented (rail 4).
from patch_terraform import (  # noqa: E402
    NEVER_AUTO_APPLY_ATTRIBUTES,
    NEVER_AUTO_APPLY_CATEGORIES,
    NEVER_AUTO_APPLY_RESOURCE_TYPES,
    auto_apply_blocker,
    generate_commit_message,
)

BRANCH_PREFIX = "iac-security-scan/fix-"

TERRAFORM_TIMEOUT_SECONDS = 300

#: What a temp copy of the module must never carry (state, provider binaries).
_COPY_IGNORE = shutil.ignore_patterns(
    ".git", ".terraform", "*.tfstate", "*.tfstate.*", ".terragrunt-cache"
)


# ===========================================================================
# Skip reasons (rail 6)
# ===========================================================================

#: Machine-readable reason codes. The human string that accompanies each one is
#: specific to the finding -- "not auto-applicable" alone is not an explanation.
SKIP_ACCESS_AFFECTING = "access-affecting"
SKIP_NOT_AUTO_APPLICABLE = "not-auto-applicable"
SKIP_NO_PATCH = "no-patch-available"
SKIP_LLM_GENERATED = "llm-generated"
SKIP_NOT_IAC = "not-fixable-in-iac"
SKIP_APPLY_FAILED = "apply-failed"

SKIP_HEADINGS = {
    SKIP_ACCESS_AFFECTING: "Access-affecting -- diff-only, always (SPEC §6.3 rail 4)",
    SKIP_NOT_AUTO_APPLICABLE: "Not auto-applicable -- review the diff",
    SKIP_NO_PATCH: "No deterministic patch available",
    SKIP_LLM_GENERATED: "LLM-generated fix -- never auto-applied",
    SKIP_NOT_IAC: "Not fixable in IaC",
    SKIP_APPLY_FAILED: "Patch failed to apply",
}


@dataclass
class SkippedFinding:
    """One finding this run did NOT fix, and precisely why."""

    id: str
    ruleId: str
    file: str
    resourceAddress: str
    severity: str
    reasonCode: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "ruleId": self.ruleId,
            "file": self.file,
            "resourceAddress": self.resourceAddress,
            "severity": self.severity,
            "reasonCode": self.reasonCode,
            "reason": self.reason,
        }


@dataclass
class AppliedGroup:
    """One finding group -> one commit (rail 5)."""

    resourceAddress: str
    file: str
    ruleIds: List[str]
    findingIds: List[str]
    severity: str
    commitHash: Optional[str] = None
    modifiedFiles: List[str] = field(default_factory=list)
    #: "passed", or why validation did not run ("terraform not on PATH", ...).
    #: A group whose validation FAILED is never in the applied set.
    validation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resourceAddress": self.resourceAddress,
            "file": self.file,
            "ruleIds": list(self.ruleIds),
            "findingIds": list(self.findingIds),
            "severity": self.severity,
            "commitHash": self.commitHash,
            "modifiedFiles": list(self.modifiedFiles),
            "validation": self.validation,
        }


@dataclass
class FixRunResult:
    success: bool = False
    dryRun: bool = False
    refused: bool = False       # a rail said no; nothing was written
    error: Optional[str] = None
    repoRoot: str = ""
    moduleDir: str = ""
    iacFormat: str = "terraform"
    originalBranch: str = ""
    branch: Optional[str] = None       # None when nothing was applied
    returnedToOriginalBranch: bool = False
    totalFindings: int = 0
    applied: List[AppliedGroup] = field(default_factory=list)
    skipped: List[SkippedFinding] = field(default_factory=list)

    @property
    def appliedFindingIds(self) -> List[str]:
        return [fid for group in self.applied for fid in group.findingIds]

    @property
    def appliedCount(self) -> int:
        return len(self.appliedFindingIds)

    @property
    def skippedCount(self) -> int:
        return len(self.skipped)

    def accounts_for_every_finding(self) -> bool:
        """Rail 6, as an invariant: applied + skipped == total, no double-counting.

        If this is ever False the report is lying to someone about what is still
        broken in their infrastructure, so it is checked, not assumed.
        """
        ids = self.appliedFindingIds + [s.id for s in self.skipped]
        return len(ids) == self.totalFindings == len(set(ids))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "dryRun": self.dryRun,
            "refused": self.refused,
            "error": self.error,
            "repoRoot": self.repoRoot,
            "moduleDir": self.moduleDir,
            "iacFormat": self.iacFormat,
            "originalBranch": self.originalBranch,
            "branch": self.branch,
            "returnedToOriginalBranch": self.returnedToOriginalBranch,
            "totalFindings": self.totalFindings,
            "appliedCount": self.appliedCount,
            "skippedCount": self.skippedCount,
            "complete": self.accounts_for_every_finding(),
            "applied": [g.to_dict() for g in self.applied],
            "skipped": [s.to_dict() for s in self.skipped],
        }


# ===========================================================================
# Format backends: Terraform (patch_terraform) and CloudFormation
# (patch_cloudformation). Same rails, same gate shape, different patcher.
# ===========================================================================


@dataclass
class Backend:
    name: str
    label: str
    load_catalog: Callable[[], Any]
    load_resources: Callable[[str], Tuple[Sequence[Any], Dict[str, Any]]]
    generate_patches: Callable[[str, Sequence[Dict[str, Any]], Any, Sequence[Any], bool], List[Any]]
    blocker: Callable[[Any], Optional[str]]            # patch -> reason or None
    is_access_affecting: Callable[[Any], bool]        # patch -> label only
    apply: Callable[[str, Sequence[Any], Sequence[Any], bool], pt.PatchApplicationResult]


def _tf_is_access_affecting(patch: pt.TerraformPatch) -> bool:
    """LABEL ONLY -- which bucket a blocked patch is reported under.

    The GATE is `auto_apply_blocker()`; this function never decides whether
    something may be applied, only how to name the reason we skipped it. If it
    disagrees with the gate, the gate wins and the finding is still skipped.
    """
    for change in patch.changes:
        if change.category in NEVER_AUTO_APPLY_CATEGORIES:
            return True
        touched = set(change.createsResourceTypes)
        if change.targetAddress:
            touched.add(change.targetAddress.split(".")[0])
        if touched & NEVER_AUTO_APPLY_RESOURCE_TYPES:
            return True
        if change.path in NEVER_AUTO_APPLY_ATTRIBUTES and change.kind in (
            "attribute",
            "block",
        ):
            return True
    return False


def _cfn_is_access_affecting(patch: pc.CFNPatch) -> bool:
    if patch.resourceType in pc.NEVER_AUTO_APPLY_RESOURCE_TYPES_CFN:
        return True
    for change in patch.changes:
        if change.category in NEVER_AUTO_APPLY_CATEGORIES:
            return True
        if set(change.createsResourceTypes) & pc.NEVER_AUTO_APPLY_RESOURCE_TYPES_CFN:
            return True
        if change.path in pc.NEVER_AUTO_APPLY_ATTRIBUTES_CFN and change.kind in (
            "attribute",
            "block",
        ):
            return True
    return False


TERRAFORM_BACKEND = Backend(
    name="terraform",
    label="Terraform",
    load_catalog=pt.FixCatalog.load,
    load_resources=pt.load_terraform_resources,
    generate_patches=lambda path, findings, catalog, resources, use_fmt: (
        pt.generate_security_patches(path, findings, catalog, resources, use_fmt=use_fmt)
    ),
    blocker=lambda patch: auto_apply_blocker(patch.changes),
    is_access_affecting=_tf_is_access_affecting,
    apply=lambda path, patches, resources, use_fmt: pt.apply_patches_to_tree(
        path, patches, resources, only_auto_applicable=True, use_fmt=use_fmt
    ),
)

CLOUDFORMATION_BACKEND = Backend(
    name="cloudformation",
    label="CloudFormation",
    load_catalog=pc.CFNFixCatalog.load,
    load_resources=pc.load_cloudformation_resources,
    generate_patches=lambda path, findings, catalog, resources, use_fmt: (
        pc.generate_security_patches(path, findings, catalog, resources)
    ),
    blocker=lambda patch: pc.cfn_auto_apply_blocker(patch.changes, patch.resourceType),
    is_access_affecting=_cfn_is_access_affecting,
    apply=lambda path, patches, resources, use_fmt: pc.apply_patches_to_tree(
        path, patches, resources, only_auto_applicable=True
    ),
)

BACKENDS = {
    "terraform": TERRAFORM_BACKEND,
    "cloudformation": CLOUDFORMATION_BACKEND,
}


def backend_for(iac_format: Optional[str], path: str) -> Backend:
    """Explicit format wins; otherwise detect from the directory (report.py's
    detector, the guard against scanning a CFN dir as Terraform)."""
    fmt = (iac_format or "").lower()
    if not fmt:
        from report import detect_iac_format

        fmt = detect_iac_format(path) or "terraform"
    backend = BACKENDS.get(fmt)
    if backend is None:
        raise ValueError(
            "--fix supports terraform and cloudformation; %r is findings-only" % fmt
        )
    return backend


# ===========================================================================
# Git preconditions (rails 1 + 2)
# ===========================================================================


def repo_root(path: str) -> Optional[str]:
    proc = pt._git(path, "rev-parse", "--show-toplevel")
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def is_dirty(root: str) -> bool:
    """Rail 1. Untracked files count -- a `--fix` that clobbers an uncommitted
    `main.tf` the user forgot to `git add` is the same disaster as one that
    clobbers a tracked edit."""
    return bool(pt._git(root, "status", "--porcelain").stdout.strip())


def current_branch(root: str) -> str:
    """Rail 2. VERIFY the branch. Never assume `main` -- the user works on feature
    branches, and a tool that hardcodes `main` will one day commit to the wrong
    one and be right about it exactly never."""
    return pt._git(root, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()


def default_branch_name(now: Optional[int] = None) -> str:
    return f"{BRANCH_PREFIX}{int(now if now is not None else time.time())}"


def _check_preconditions(root: str) -> Optional[str]:
    """Return the refusal message, or None if it is safe to proceed."""
    if pt._git(root, "rev-parse", "--is-inside-work-tree").returncode != 0:
        return (
            f"{root} is not a git repository. --fix commits its changes to a new "
            "branch so you can review or revert them; it will not write to a "
            "directory it cannot do that in."
        )

    branch = current_branch(root)
    if branch == "HEAD":
        return (
            "HEAD is detached. --fix branches from where you are and returns you "
            "to it afterwards, which it cannot do from a detached HEAD. Check out "
            "a branch first."
        )

    if is_dirty(root):
        dirty = pt._git(root, "status", "--porcelain").stdout.strip().splitlines()
        listed = "\n".join(f"    {line}" for line in dirty[:10])
        more = f"\n    ...and {len(dirty) - 10} more" if len(dirty) > 10 else ""
        return (
            "Refusing to run --fix: the working tree has uncommitted changes.\n"
            f"{listed}{more}\n\n"
            "Commit or stash them first. --fix writes to your IaC files and "
            "commits them; on a dirty tree it would sweep your work into its own "
            "commit, and you could not tell its changes from yours. There is no "
            "--force (SPEC §6.3 rail 1)."
        )

    return None


# ===========================================================================
# terraform validate on a temp copy (never in place, never plan/apply)
# ===========================================================================


def terraform_validate_module(
    module_dir: str, plugin_cache_dir: Optional[str] = None
) -> Dict[str, Any]:
    """`terraform init -backend=false` + `terraform validate` on a COPY of the module.

    Returns ``{"available", "valid": True|False|None, "error"}``. ``valid`` is
    None when the answer is unknown (terraform absent, or `init` could not
    fetch providers -- it downloads them from the registry, so it needs the
    network); False only when terraform ran and rejected the module. Never
    reads state, never plans.
    """
    if shutil.which("terraform") is None:
        return {"available": False, "valid": None, "error": "terraform not on PATH"}

    env = dict(os.environ)
    env["TF_IN_AUTOMATION"] = "1"
    env["TF_INPUT"] = "0"
    if plugin_cache_dir:
        env["TF_PLUGIN_CACHE_DIR"] = plugin_cache_dir

    tmp = tempfile.mkdtemp(prefix="iac-security-scan-validate-")
    try:
        dest = os.path.join(tmp, "module")
        shutil.copytree(module_dir, dest, ignore=_COPY_IGNORE)
        try:
            init = subprocess.run(
                ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
                cwd=dest, capture_output=True, text=True,
                timeout=TERRAFORM_TIMEOUT_SECONDS, env=env,
            )
            if init.returncode != 0:
                return {
                    "available": True,
                    "valid": None,
                    "error": "terraform init failed (providers or modules could not "
                    "be resolved): %s" % (init.stderr or init.stdout).strip()[:600],
                }
            proc = subprocess.run(
                ["terraform", "validate", "-no-color"],
                cwd=dest, capture_output=True, text=True,
                timeout=TERRAFORM_TIMEOUT_SECONDS, env=env,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"available": True, "valid": None, "error": "terraform validate could not run: %s" % exc}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if proc.returncode == 0:
        return {"available": True, "valid": True, "error": None}
    return {
        "available": True,
        "valid": False,
        "error": (proc.stdout or proc.stderr or "").strip()[:2000],
    }


# ===========================================================================
# Triage (rails 3 + 4 + 6)
# ===========================================================================


def _finding_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    loc = finding.get("location") or {}
    return (
        finding.get("id", ""),
        loc.get("file", ""),
        loc.get("resourceAddress", ""),
    )


def _skip(finding: Dict[str, Any], code: str, reason: str) -> SkippedFinding:
    loc = finding.get("location") or {}
    return SkippedFinding(
        id=finding.get("id", ""),
        ruleId=finding.get("ruleId", ""),
        file=loc.get("file", ""),
        resourceAddress=loc.get("resourceAddress", ""),
        severity=finding.get("severity") or "unmapped",
        reasonCode=code,
        reason=reason,
    )


def triage(
    findings: Sequence[Dict[str, Any]],
    patches: Sequence[Any],
    backend: Backend = TERRAFORM_BACKEND,
) -> Tuple[List[Any], List[SkippedFinding]]:
    """Split every finding into (auto-applicable patch) or (skipped, with a reason).

    Every finding lands in exactly one bucket. There is no third bucket, no
    "other", and nothing falls off the end -- that is the whole point of rail 6.
    """
    by_finding: Dict[str, Any] = {}
    for patch in patches:
        for fid in patch.findingIds:
            by_finding[fid] = patch

    auto: List[Any] = []
    skipped: List[SkippedFinding] = []

    for finding in findings:
        fid = finding.get("id", "")
        patch = by_finding.get(fid)

        if patch is not None:
            blocker = backend.blocker(patch)  # THE gate (rail 4)
            if blocker is None and patch.autoApplicable:
                continue  # handled below, once per patch, not once per finding
            code = (
                SKIP_ACCESS_AFFECTING
                if backend.is_access_affecting(patch)
                else SKIP_NOT_AUTO_APPLICABLE
            )
            reason = (
                blocker
                or patch.autoApplyBlockedBy
                or "the fix catalog does not mark this rule auto-applicable; the "
                "diff is in the report -- review and apply it by hand"
            )
            skipped.append(_skip(finding, code, reason))
            continue

        remediation = finding.get("remediationType") or "iac"
        if remediation != "iac":
            category = finding.get("nonIaCCategory") or remediation
            skipped.append(
                _skip(
                    finding,
                    SKIP_NOT_IAC,
                    f"not fixable in {backend.label} (remediationType={remediation}, "
                    f"category={category}); the report carries the CLI or console "
                    "steps for it",
                )
            )
            continue

        if finding.get("fix"):
            confidence = (finding.get("fix") or {}).get("confidence", "unknown")
            skipped.append(
                _skip(
                    finding,
                    SKIP_LLM_GENERATED,
                    "the only fix available is LLM-generated (confidence="
                    f"{confidence}); --fix applies deterministic catalog patches "
                    "only. The diff is in the report -- review and apply it by hand",
                )
            )
            continue

        skipped.append(
            _skip(
                finding,
                SKIP_NO_PATCH,
                "no rule in the deterministic fix catalog covers this finding, and "
                "no LLM fix was generated for it. It must be fixed by hand",
            )
        )

    for patch in patches:
        if patch.autoApplicable and backend.blocker(patch) is None:
            auto.append(patch)

    auto.sort(key=lambda p: (p.file, p.address))
    return auto, skipped


# ===========================================================================
# The run
# ===========================================================================


def _findings_for(
    findings: Sequence[Dict[str, Any]], patch: Any
) -> List[Dict[str, Any]]:
    claimed = set(patch.findingIds)
    return [f for f in findings if f.get("id", "") in claimed]


def _commit_group(
    module_dir: str,
    branch: str,
    branch_exists: bool,
    group_patches: Sequence[Any],
    resources: Sequence[Any],
    use_fmt: bool,
    backend: Backend,
    validate: bool,
    plugin_cache_dir: Optional[str],
) -> Tuple[bool, Optional[str], List[str], Optional[str], Optional[str]]:
    """Apply + commit ONE finding group.

    Returns ``(ok, commitHash, files, error, validation)``.

    Everything here runs with ``git -C module_dir``: the patches were generated
    against ``module_dir``, so they are applied there and the same relative
    paths are what ``git add`` receives. The first group cuts the branch;
    later groups land on it as their own commits (rail 5).
    """
    if not branch_exists:
        checkout = pt._git(module_dir, "checkout", "-b", branch)
        if checkout.returncode != 0:
            return False, None, [], f"could not create branch {branch}: {checkout.stderr.strip()}", None

    applied = backend.apply(module_dir, group_patches, resources, use_fmt)
    if not applied.success or not applied.modifiedFiles:
        return False, None, [], "; ".join(applied.errors) or "patch produced no change", None

    # The write must be visible to git as a change to the TARGET file. If it is
    # not, something was written somewhere else (or nowhere) and reporting
    # success would be a lie.
    seen = pt._git(module_dir, "status", "--porcelain", "--", *applied.modifiedFiles)
    if not seen.stdout.strip():
        return (
            False, None, [],
            "the target file(s) are unchanged after patching (%s); nothing to commit"
            % ", ".join(applied.modifiedFiles),
            None,
        )

    validation: Optional[str] = "not run for %s" % backend.label
    if backend.name == "terraform":
        if not validate:
            validation = "skipped (--no-validate)"
        else:
            tf = terraform_validate_module(module_dir, plugin_cache_dir)
            if tf["valid"] is False:
                # Do not commit HCL terraform rejects. Put the files back.
                pt._git(module_dir, "checkout", "--", *applied.modifiedFiles)
                return (
                    False, None, [],
                    "terraform validate rejected the patched module (the change was "
                    "reverted, nothing was committed): %s" % tf["error"],
                    None,
                )
            validation = "passed" if tf["valid"] else "unknown: %s" % tf["error"]

    for file in applied.modifiedFiles:
        pt._git(module_dir, "add", file)

    message = generate_commit_message(
        list(group_patches), applied.appliedCount, len(applied.modifiedFiles),
        label=backend.label,
    )
    commit = pt._git(module_dir, "commit", "-m", message)
    if commit.returncode != 0:
        return False, None, [], f"commit failed: {commit.stderr.strip()}", None

    return (
        True,
        pt._git(module_dir, "rev-parse", "HEAD").stdout.strip(),
        list(applied.modifiedFiles),
        None,
        validation,
    )


def run_fix(
    path: str,
    findings: Sequence[Dict[str, Any]],
    *,
    dry_run: bool = False,
    branch_name: Optional[str] = None,
    use_fmt: bool = True,
    catalog: Optional[Any] = None,
    iac_format: Optional[str] = None,
    validate: bool = True,
) -> FixRunResult:
    """The `--fix` path. All six rails, in order.

    ``path`` is the module directory. Patches are generated against it AND
    applied to it; the git repository that contains it is only used to check
    preconditions and to report the root.
    """
    findings = list(findings)
    result = FixRunResult(dryRun=dry_run, totalFindings=len(findings))

    module_dir = os.path.abspath(path)
    root = repo_root(module_dir) or module_dir
    result.repoRoot = root
    result.moduleDir = module_dir

    # ---- rails 1 + 2: preconditions, before anything is generated ------------
    refusal = _check_preconditions(root)
    if refusal is not None:
        result.refused = True
        result.error = refusal
        return result
    result.originalBranch = current_branch(root)

    try:
        backend = backend_for(iac_format, module_dir)
    except ValueError as exc:
        result.error = str(exc)
        return result
    result.iacFormat = backend.name

    catalog = catalog or backend.load_catalog()

    try:
        resources, _ = backend.load_resources(module_dir)
        patches = backend.generate_patches(module_dir, findings, catalog, resources, use_fmt)
    except Exception as exc:  # noqa: BLE001 -- a scan error is exit 2 (SPEC §9.2)
        result.error = f"patch generation failed: {exc}"
        return result

    # ---- rails 3 + 4 + 6: triage --------------------------------------------
    auto_patches, skipped = triage(findings, patches, backend)
    result.skipped = skipped

    if dry_run:
        # Represent the would-apply set so the accounting still balances (rail 6):
        # a dry run must add up to `total` exactly as a real run does.
        for patch in auto_patches:
            result.applied.append(
                AppliedGroup(
                    resourceAddress=patch.address,
                    file=patch.file,
                    ruleIds=list(patch.ruleIds),
                    findingIds=list(patch.findingIds),
                    severity=patch.severity,
                )
            )
        result.success = True
        result.returnedToOriginalBranch = True
        return result

    if not auto_patches:
        result.success = True
        result.returnedToOriginalBranch = True
        return result

    # ---- rails 2 + 5: a new branch, one commit per finding group -------------
    branch = branch_name or default_branch_name()
    branch_exists = False
    # One provider cache for the whole run, so `terraform init` on the temp copy
    # downloads each provider once, not once per finding group.
    plugin_cache_dir = tempfile.mkdtemp(prefix="iac-security-scan-tf-cache-")

    try:
        for patch in auto_patches:
            group_findings = _findings_for(findings, patch)

            # Re-parse: the tree has moved under us if an earlier group touched this
            # file, and stale line numbers corrupt files.
            try:
                fresh_resources, _ = backend.load_resources(module_dir)
                regenerated = backend.generate_patches(
                    module_dir, group_findings, catalog, fresh_resources, use_fmt
                )
            except Exception as exc:  # noqa: BLE001
                regenerated = []
                regen_error: Optional[str] = str(exc)
            else:
                regen_error = None

            # Re-gate the regenerated patch. Same gate, no shortcuts, no "we already
            # checked" -- the tree changed, so the check runs again.
            group_patches = [
                p for p in regenerated if p.autoApplicable and backend.blocker(p) is None
            ]

            if not group_patches:
                for finding in group_findings:
                    result.skipped.append(
                        _skip(
                            finding,
                            SKIP_APPLY_FAILED,
                            "the patch could not be regenerated against the tree as it "
                            "now stands"
                            + (f": {regen_error}" if regen_error else "")
                            + " -- nothing was applied for this finding",
                        )
                    )
                continue

            ok, commit_hash, files, error, validation = _commit_group(
                module_dir, branch, branch_exists, group_patches, fresh_resources,
                use_fmt, backend, validate, plugin_cache_dir,
            )

            if not ok:
                for finding in group_findings:
                    result.skipped.append(
                        _skip(
                            finding,
                            SKIP_APPLY_FAILED,
                            f"applying the patch failed: {error or 'unknown error'}",
                        )
                    )
                if not branch_exists:
                    _abandon_branch(module_dir, branch, result.originalBranch)
                continue

            branch_exists = True
            result.branch = branch
            result.applied.append(
                AppliedGroup(
                    resourceAddress=patch.address,
                    file=patch.file,
                    ruleIds=list(patch.ruleIds),
                    findingIds=list(patch.findingIds),
                    severity=patch.severity,
                    commitHash=commit_hash,
                    modifiedFiles=files,
                    validation=validation,
                )
            )
    finally:
        shutil.rmtree(plugin_cache_dir, ignore_errors=True)

    # ---- rail 2, second half: return to where the user was --------------------
    if branch_exists:
        back = pt._git(module_dir, "checkout", result.originalBranch)
        result.returnedToOriginalBranch = back.returncode == 0
        if not result.returnedToOriginalBranch:
            result.error = (
                f"fixes are committed on `{branch}`, but returning to "
                f"`{result.originalBranch}` failed: {back.stderr.strip()}"
            )
    else:
        result.returnedToOriginalBranch = True

    result.success = True
    return result


def _abandon_branch(root: str, branch: str, original: str) -> None:
    """A failed first group must not strand the user on a half-made branch."""
    pt._git(root, "checkout", "--force", original)
    pt._git(root, "branch", "-D", branch)


# ===========================================================================
# The report (rail 6)
# ===========================================================================


def format_fix_report(result: FixRunResult) -> str:
    """*"Applied 4, 7 require review, here they are."*

    A user must be able to finish reading this and know exactly what is still
    broken. Nothing is summarised away; every skipped finding is named.
    """
    if result.refused:
        return f"# `--fix` refused\n\n{result.error}\n"

    lines: List[str] = ["# `--fix` run", ""]

    if result.error and not result.applied:
        lines += [f"**Error:** {result.error}", ""]

    total = result.totalFindings
    applied = result.appliedCount
    skipped = result.skippedCount

    if result.dryRun:
        lines.append(
            f"**Dry run** — nothing was written. Would apply **{len(result.applied)}** "
            f"of {total} findings; {skipped} require review."
        )
    elif result.branch:
        lines.append(
            f"Applied **{applied} of {total}** findings on branch "
            f"`{result.branch}` ({len(result.applied)} commit"
            f"{'s' if len(result.applied) != 1 else ''}, one per finding group). "
            f"Your branch `{result.originalBranch}` is untouched."
        )
        if result.returnedToOriginalBranch:
            lines.append(
                f"You are back on `{result.originalBranch}`. Review with "
                f"`git diff {result.originalBranch}...{result.branch}`, then merge "
                "or delete the branch."
            )
        else:
            lines.append(
                f"**You are still on `{result.branch}`** — returning to "
                f"`{result.originalBranch}` failed: {result.error}"
            )
    else:
        lines.append(
            f"Applied **0 of {total}** findings — nothing here is auto-applicable. "
            "No branch was created."
        )

    lines.append("")

    if result.applied:
        lines += ["## Applied", ""]
        for group in result.applied:
            short = (group.commitHash or "")[:8]
            validation = f" — validate: {group.validation}" if group.validation else ""
            lines.append(
                f"- `{group.resourceAddress}` ({group.severity}) — "
                f"{', '.join(group.ruleIds)} — `{short}`{validation}"
            )
        lines.append("")

    # -- the load-bearing half ------------------------------------------------
    lines += [f"## Skipped ({skipped} of {total}) — still broken", ""]
    if not result.skipped:
        lines += ["Nothing was skipped.", ""]
    else:
        lines += [
            "Every finding below was **not** fixed by this run. It is still there.",
            "",
        ]
        for code, heading in SKIP_HEADINGS.items():
            group = [s for s in result.skipped if s.reasonCode == code]
            if not group:
                continue
            lines += [f"### {heading} ({len(group)})", ""]
            for item in sorted(group, key=lambda s: (s.file, s.resourceAddress)):
                lines += [
                    f"- **{item.ruleId}** on `{item.resourceAddress}` "
                    f"({item.severity}) — `{item.file}`",
                    f"  - {item.reason}",
                ]
            lines.append("")

    if not result.accounts_for_every_finding():
        # Cannot happen by construction; if it ever does, say so loudly rather
        # than hand someone an accounting they will trust.
        lines += [
            "> **WARNING:** this run could not account for every finding "
            f"({applied} applied + {skipped} skipped != {total} total). Treat this "
            "report as incomplete and re-run the scan.",
            "",
        ]

    return "\n".join(lines)


# ===========================================================================
# CLI
# ===========================================================================


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Apply auto-applicable Terraform or CloudFormation security fixes on a "
            "new branch. Never on a dirty tree, never an access-affecting change, "
            "and it always tells you what it skipped."
        )
    )
    parser.add_argument("path", help="IaC module directory (inside a git repo)")
    parser.add_argument(
        "--findings",
        required=True,
        help="Path to a findings JSON payload ({\"findings\": [...]})",
    )
    parser.add_argument(
        "--iac-format",
        dest="iac_format",
        choices=tuple(BACKENDS),
        help="terraform or cloudformation (default: detect from the directory)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be applied and skipped. Writes nothing.",
    )
    parser.add_argument("--branch", help="Override the generated branch name")
    parser.add_argument("--json", action="store_true", help="Emit JSON, not markdown")
    parser.add_argument("--no-fmt", action="store_true", help="Skip terraform fmt")
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip `terraform validate` on the patched module (it needs the network "
        "to fetch providers)",
    )
    # There is deliberately no --force. See rail 1.
    args = parser.parse_args(argv)

    if not os.path.isdir(args.path):
        print(f"error: not a directory: {args.path}", file=sys.stderr)
        return 2

    try:
        with open(args.findings, encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"error: could not read findings: {exc}", file=sys.stderr)
        return 2

    findings = payload.get("findings", payload if isinstance(payload, list) else [])

    result = run_fix(
        args.path,
        findings,
        dry_run=args.dry_run,
        branch_name=args.branch,
        use_fmt=not args.no_fmt,
        iac_format=args.iac_format,
        validate=not args.no_validate,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(format_fix_report(result))

    if result.refused:
        return 1
    if not result.success:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
