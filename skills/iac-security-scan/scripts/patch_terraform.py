#!/usr/bin/env python3
"""
Deterministic Terraform patcher (WS-5).

Ported from infrabot's ``src/tools/terraform-patch.ts`` (1262 lines) with ONE
structural substitution, which is the entire point of this workstream:

    infrabot parsed HCL with a regex (terraform-patch.ts:211-330).
    We do not. We consume the WS-1 parser (`parse_iac.py`, tfparse tier) instead.

infrabot's regex parser mis-handles heredocs, `dynamic` blocks, `for_each`, and
multi-line expressions. In a security tool a *missed resource is a missed
vulnerability*, so the regex parser is not ported at any fidelity. Every
resource boundary in this file comes from tfparse's `__tfmeta` line provenance.

What IS ported, near-verbatim:
  * the patch/change/result dataclasses (`terraform-patch.ts:27-120`)
  * `generateSecurityPatches()`      (:368)
  * `generateChangesForResource()`   (:566)  -- now data-driven, 8 rules -> 30
  * `generateUnifiedDiff()`          (:731)  -- now a real difflib unified diff
  * `isAutoApplicable()`             (:893)  -- now with a HARD-CODED never-list
  * `applyPatches()`                 (:918)
  * `createPatchBranch()`            (:1009)
  * `generateCommitMessage()`        (:1095)
  * `exportPatchFiles()`             (:1155)
  * `generatePatchReport()`          (:1196)

THE SAFETY LINE (SPEC §6.3) -- read before touching `is_auto_applicable`:

    `autoApplicable` means: additive, single-attribute, semantically
    unambiguous. Nothing else.

    Five categories are NEVER auto-applicable, no matter what the fix catalog
    says and no matter how confident any model is:

        1. Security-group CIDR narrowing
        2. IAM wildcard removal
        3. Bucket-policy changes
        4. KMS key-policy changes
        5. Network ACLs

    They are always diff-only. This is a hard-coded list, not a heuristic,
    because the failure mode is a production outage landing on somebody who
    never ran the scan. `tests/test_patch_terraform.py::TestNeverAutoApply`
    fails if any of them is ever marked auto-applicable. That test does not get
    relaxed.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import parse_iac  # noqa: E402  (WS-1 parser -- the whole reason this file exists)

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
FIX_RULES_PATH = os.path.join(_DATA_DIR, "fix-rules.json")

INDENT = "  "


# ===========================================================================
# THE NEVER-AUTO-APPLY LIST (SPEC §6.3 rail 4) -- hard-coded, not a heuristic
# ===========================================================================

#: Fix-catalog rules whose *category* is access-affecting. Membership here is
#: final: `is_auto_applicable()` returns False, regardless of the catalog's
#: `autoApplicable` flag, regardless of model confidence.
NEVER_AUTO_APPLY_CATEGORIES = frozenset(
    {
        "security-group-cidr",  # 1. narrowing an SG CIDR can lock out operators
        "iam-wildcard",         # 2. removing an IAM wildcard can break a workload
        "bucket-policy",        # 3. a bucket policy change can cut off consumers
        "kms-key-policy",       # 4. a KMS key policy change can brick decryption
        "network-acl",          # 5. NACLs are stateless; a bad rule is an outage
    }
)

#: Terraform resource types that live in the never-auto-apply blast radius.
#: If a change touches (or creates) one of these, the patch is diff-only.
NEVER_AUTO_APPLY_RESOURCE_TYPES = frozenset(
    {
        # 1. security-group CIDR narrowing
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
        "aws_vpc_security_group_egress_rule",
        "aws_default_security_group",
        # 2. IAM wildcard removal
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
        "aws_iam_policy_document",
        # 3. bucket-policy changes
        "aws_s3_bucket_policy",
        # 4. KMS key-policy changes
        "aws_kms_key",
        "aws_kms_key_policy",
        # 5. network ACLs
        "aws_network_acl",
        "aws_network_acl_rule",
        "aws_default_network_acl",
    }
)

#: Attribute names that carry an access-control payload wherever they appear.
NEVER_AUTO_APPLY_ATTRIBUTES = frozenset(
    {
        "policy",
        "cidr_blocks",
        "cidr_ipv4",
        "cidr_ipv6",
        "ipv6_cidr_blocks",
        "ingress",
        "egress",
        "assume_role_policy",
        "key_policy",
        "source_security_group_id",
    }
)


# ===========================================================================
# Schema (ported from terraform-patch.ts:27-120)
# ===========================================================================


@dataclass
class TerraformResource:
    """A parsed Terraform resource.

    Every field here is sourced from `parse_iac.py`'s tfparse tier. `startLine`
    / `endLine` are 1-based and inclusive of the closing brace.
    """

    file: str  # repo-relative
    resourceType: str
    resourceName: str
    address: str
    startLine: int
    endLine: int
    attributes: Dict[str, Any]
    rawContent: str
    absFile: str = ""

    @property
    def has_provenance(self) -> bool:
        return bool(self.startLine) and bool(self.endLine)


@dataclass
class PatchChange:
    """One change inside a patch. (terraform-patch.ts:49)"""

    type: str  # add | modify | remove
    kind: str  # attribute | block | companion
    path: str  # attribute name, block name, or companion resource address
    description: str
    findingIds: List[str] = field(default_factory=list)
    oldValue: Optional[str] = None
    newValue: Optional[str] = None
    body: List[str] = field(default_factory=list)   # block/companion HCL lines
    ruleId: str = ""
    category: str = ""
    createsResourceTypes: List[str] = field(default_factory=list)
    targetAddress: str = ""  # resource the change lands in (may differ from finding)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "kind": self.kind,
            "path": self.path,
            "description": self.description,
            "findingIds": list(self.findingIds),
            "oldValue": self.oldValue,
            "newValue": self.newValue,
            "ruleId": self.ruleId,
            "category": self.category,
        }


@dataclass
class TerraformPatch:
    """A patch for one resource. (terraform-patch.ts:67)"""

    file: str
    resourceType: str
    resourceName: str
    address: str
    changes: List[PatchChange]
    diff: str
    findingIds: List[str]
    ruleIds: List[str]
    severity: str
    autoApplicable: bool
    autoApplyBlockedBy: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "resourceType": self.resourceType,
            "resourceName": self.resourceName,
            "address": self.address,
            "changes": [c.to_dict() for c in self.changes],
            "diff": self.diff,
            "findingIds": list(self.findingIds),
            "ruleIds": list(self.ruleIds),
            "severity": self.severity,
            "autoApplicable": self.autoApplicable,
            "autoApplyBlockedBy": self.autoApplyBlockedBy,
        }


@dataclass
class PatchApplicationResult:
    """(terraform-patch.ts:91)"""

    success: bool = True
    appliedCount: int = 0
    skippedCount: int = 0
    failedCount: int = 0
    modifiedFiles: List[str] = field(default_factory=list)
    backupFiles: List[str] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class BranchCreationResult:
    """(terraform-patch.ts:109)"""

    success: bool = False
    branchName: str = ""
    commitHash: Optional[str] = None
    committedFiles: List[str] = field(default_factory=list)
    error: Optional[str] = None


# ===========================================================================
# The fix catalog
# ===========================================================================


class FixCatalog:
    """`data/fix-rules.json` -- the 30-rule deterministic fix catalog.

    Static, checked-in data, exactly like `rule-severity.json`. The model does
    not write to it at runtime.
    """

    def __init__(self, payload: Dict[str, Any]):
        self.shared: Dict[str, Any] = payload.get("sharedResources", {})
        self.dataSources: Dict[str, Any] = payload.get("dataSources", {})
        self.rules: Dict[str, Any] = payload.get("rules", {})
        for rule_id, rule in self.rules.items():
            if "changes" not in rule or not rule["changes"]:
                raise ValueError(f"{rule_id}: fix rule has no changes")
            if "resourceTypes" not in rule:
                raise ValueError(f"{rule_id}: fix rule has no resourceTypes")

    @classmethod
    def load(cls, path: Optional[str] = None) -> "FixCatalog":
        with open(path or FIX_RULES_PATH, encoding="utf-8") as fh:
            return cls(json.load(fh))

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self.rules

    def __len__(self) -> int:
        return len(self.rules)

    @property
    def rule_ids(self) -> List[str]:
        return list(self.rules)

    def get(self, rule_id: str) -> Optional[Dict[str, Any]]:
        return self.rules.get(rule_id)


#: Template variables the catalog may use. Anything else inside `${...}` is
#: Terraform's OWN interpolation syntax (a KMS key policy is full of it) and
#: must survive untouched -- rewriting it would corrupt the generated HCL.
_TEMPLATE_KEYS = ("name", "address", "type")
_TEMPLATE_PREFIXES = ("shared.", "raw.")


def _substitute(text: str, ctx: Dict[str, str]) -> str:
    """`${name}` / `${address}` / `${shared.x.ref}` / `${raw.attr}` substitution.

    `${data.aws_region.current.name}` is left alone: that is HCL, not us.
    """
    def repl(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key in ctx:
            return ctx[key]
        if key in _TEMPLATE_KEYS or key.startswith(_TEMPLATE_PREFIXES):
            raise KeyError(f"unknown template variable ${{{key}}}")
        return match.group(0)  # Terraform interpolation -- pass through verbatim

    return re.sub(r"\$\{([A-Za-z0-9_.\[\]\"]+)\}", repl, text)


# ===========================================================================
# Loading resources -- via the WS-1 parser, NOT a regex
# ===========================================================================


def load_terraform_resources(root: str) -> Tuple[List[TerraformResource], Dict[str, Any]]:
    """Load resources from `parse_iac.py`. Raises if the parser is degraded.

    A degraded tier (hcl2/regex) has no line numbers, and without line numbers
    there is no patching. We refuse rather than emit a diff we cannot anchor.
    """
    parsed = parse_iac.parse_terraform(root)
    if parsed.get("degraded"):
        raise RuntimeError(
            "DEGRADED PARSE (tier=%s): no line provenance, so no patches can be "
            "anchored. Install tfparse (pip install tfparse) and re-run."
            % parsed.get("parseTier")
        )

    resources: List[TerraformResource] = []
    file_cache: Dict[str, List[str]] = {}

    for res in parsed.get("resources", []):
        loc = res.get("location") or {}
        rel = loc.get("file") or ""
        start, end = loc.get("startLine"), loc.get("endLine")
        if not rel or not start or not end:
            continue
        abs_path = os.path.join(root, rel)
        if rel not in file_cache:
            if not os.path.isfile(abs_path):
                continue
            with open(abs_path, encoding="utf-8") as fh:
                file_cache[rel] = fh.read().split("\n")
        lines = file_cache[rel]
        raw = "\n".join(lines[start - 1 : end])
        resources.append(
            TerraformResource(
                file=rel,
                resourceType=loc.get("resourceType") or res.get("type", ""),
                resourceName=res.get("name", ""),
                address=loc.get("resourceAddress") or res.get("full_name", ""),
                startLine=int(start),
                endLine=int(end),
                attributes=res.get("attributes", {}) or {},
                rawContent=raw,
                absFile=abs_path,
            )
        )

    return resources, parsed


# ===========================================================================
# Change generation (terraform-patch.ts:566 -- generateChangesForResource)
# ===========================================================================


def _block_top_level_attr_line(resource: TerraformResource, attr: str) -> Optional[int]:
    """Find the file line (1-based) of a *top-level* `attr = ...` in the block.

    Brace-depth aware, so `retention_in_days` inside a nested `dynamic` block is
    not mistaken for the resource's own attribute. This is the kind of thing
    infrabot's regex parser got wrong.
    """
    lines = resource.rawContent.split("\n")
    depth = 0
    pattern = re.compile(r"^\s*" + re.escape(attr) + r"\s*=")
    for offset, line in enumerate(lines):
        stripped = line.strip()
        if depth == 1 and pattern.match(line):
            return resource.startLine + offset
        depth += line.count("{") - line.count("}")
        if depth == 0 and offset > 0 and stripped == "}":
            break
    return None


def _has_top_level_block(resource: TerraformResource, name: str) -> bool:
    return _top_level_block_span(resource, name) is not None


def _top_level_block_span(
    resource: TerraformResource, name: str
) -> Optional[Tuple[int, int]]:
    """(startLine, endLine) of a top-level `name { ... }` block, 1-based inclusive.

    Brace-depth aware, so a `redirect` inside a nested `dynamic` block is not
    mistaken for the resource's own `redirect` block.
    """
    lines = resource.rawContent.split("\n")
    depth = 0
    pattern = re.compile(r"^\s*" + re.escape(name) + r"\s*\{")
    block_start: Optional[int] = None
    block_depth = 0
    for offset, line in enumerate(lines):
        if block_start is None and depth == 1 and pattern.match(line):
            block_start = offset
            block_depth = 0
        opened = line.count("{")
        closed = line.count("}")
        if block_start is not None:
            block_depth += opened - closed
            if block_depth == 0:
                return (
                    resource.startLine + block_start,
                    resource.startLine + offset,
                )
        depth += opened - closed
    return None


def _raw_attr_value(resource: TerraformResource, name: str) -> Optional[str]:
    """The RHS *source text* of a top-level attribute.

    tfparse hands back the *evaluated* value; for a companion resource we need
    the original expression (`aws_api_gateway_rest_api.main.id`), not the string
    it evaluates to. So we read it back out of the raw HCL.
    """
    line_no = _block_top_level_attr_line(resource, name)
    if line_no is None:
        return None
    line = resource.rawContent.split("\n")[line_no - resource.startLine]
    return line.split("=", 1)[1].strip()


def _nested_attr_line(
    resource: TerraformResource, block: str, attr: str
) -> Optional[int]:
    """File line (1-based) of `attr = ...` one level inside a top-level `block`."""
    span = _top_level_block_span(resource, block)
    if span is None:
        return None
    lines = resource.rawContent.split("\n")
    pattern = re.compile(r"^\s*" + re.escape(attr) + r"\s*=")
    depth = 0
    for line_no in range(span[0], span[1] + 1):
        line = lines[line_no - resource.startLine]
        if depth == 1 and pattern.match(line):
            return line_no
        depth += line.count("{") - line.count("}")
    return None


def _nested_attr_value(
    resource: TerraformResource, block: str, attr: str
) -> Optional[str]:
    line_no = _nested_attr_line(resource, block, attr)
    if line_no is None:
        return None
    return resource.rawContent.split("\n")[line_no - resource.startLine].strip()


def _resolve_linked_resource(
    resources: Sequence[TerraformResource],
    target_types: Sequence[str],
    link_attr: str,
    address: str,
    match: Optional[Dict[str, str]] = None,
) -> Optional[TerraformResource]:
    """Find the resource of `target_types` whose `link_attr` points at `address`.

    Terraform's modern S3 shape splits one bucket across half a dozen sibling
    resources (`aws_s3_bucket_versioning`, `..._logging`, `..._server_side_
    encryption_configuration`). Checkov reports the finding on the *bucket*, but
    the fix often lands on the sibling. This is the resolver for that hop.
    """
    pattern = re.compile(
        r"^\s*" + re.escape(link_attr) + r"\s*=\s*" + re.escape(address) + r"\b"
    )
    for res in resources:
        if res.resourceType not in target_types:
            continue
        if not any(pattern.match(line) for line in res.rawContent.split("\n")):
            continue
        # An optional disambiguator. An ALB has two listeners bound to it; only
        # the HTTP one gets the redirect. Without this we would patch whichever
        # tfparse happened to emit first, which is not a fix, it is a coin flip.
        if match:
            ok = True
            for attr, expected in match.items():
                if _raw_attr_value(res, attr) != expected:
                    ok = False
                    break
            if not ok:
                continue
        return res
    return None


def generate_changes_for_resource(
    resource: TerraformResource,
    findings: Sequence[Dict[str, Any]],
    catalog: FixCatalog,
    all_resources: Sequence[TerraformResource],
    existing_addresses: Optional[set] = None,
) -> List[PatchChange]:
    """Turn (resource, findings) into concrete changes. Data-driven off the catalog.

    infrabot hard-coded eight `if` branches here (`terraform-patch.ts:566-706`).
    The branches are now rows in `data/fix-rules.json`, which is what makes 30
    rules maintainable and what lets WS-8 grade the catalog as data.
    """
    changes: List[PatchChange] = []
    # NOT a copy. The caller's set is mutated as shared companions are claimed, so
    # a KMS key emitted for a log group in cloudwatch.tf is not emitted AGAIN for a
    # log group in codebuild.tf -- that is a duplicate resource and `terraform
    # validate` rejects the whole tree.
    if existing_addresses is None:
        existing_addresses = {r.address for r in all_resources}
    existing = existing_addresses

    for finding in findings:
        rule_id = finding.get("ruleId", "")
        rule = catalog.get(rule_id)
        if rule is None:
            continue
        if resource.resourceType not in rule["resourceTypes"]:
            continue

        finding_id = finding.get("id", "")
        name = resource.resourceName
        ctx: Dict[str, str] = {
            "name": name,
            "address": resource.address,
            "type": resource.resourceType,
        }
        for shared_id, shared in catalog.shared.items():
            ctx[f"shared.{shared_id}.ref"] = _substitute(shared["ref"], {"name": name})

        for spec in rule["changes"]:
            changes.extend(
                _build_changes(
                    spec, rule_id, rule, resource, finding_id, ctx, catalog,
                    all_resources, existing,
                )
            )

    return changes


def _data_source_changes(
    ids: Sequence[str],
    catalog: FixCatalog,
    existing: set,
    rule_id: str,
    category: str,
    finding_id: str,
    target_address: str,
) -> List[PatchChange]:
    """Emit `data "aws_caller_identity" "current" {}` and friends -- but only if the
    tree does not already declare them. Declaring one twice is a hard
    `terraform validate` failure, so this check is not optional.
    """
    out: List[PatchChange] = []
    for ds_id in ids:
        entry = catalog.dataSources[ds_id]
        address = entry["address"]
        if address in existing:
            continue
        existing.add(address)
        out.append(
            PatchChange(
                type="add", kind="companion", path=address,
                description=entry.get("description", f"add {address}"),
                findingIds=[finding_id], body=list(entry["template"]),
                ruleId=rule_id, category=category, targetAddress=target_address,
            )
        )
    return out


def _build_changes(
    spec: Dict[str, Any],
    rule_id: str,
    rule: Dict[str, Any],
    resource: TerraformResource,
    finding_id: str,
    ctx: Dict[str, str],
    catalog: FixCatalog,
    all_resources: Sequence[TerraformResource],
    existing: set,
) -> List[PatchChange]:
    """One catalog change-spec -> zero or more concrete PatchChanges.

    Zero is a legitimate answer: if the fix is already present in the tree, or a
    referenced sibling resource does not exist, we emit nothing rather than a
    diff that would not apply.
    """
    kind = spec["kind"]
    category = rule.get("category", "")
    description = _substitute(spec.get("description", rule.get("title", rule_id)), ctx)

    # The change may land on a *sibling* resource (the modern split-S3 shape:
    # Checkov reports on aws_s3_bucket, the fix belongs on aws_s3_bucket_*).
    target = resource
    if spec.get("linkTo"):
        link = spec["linkTo"]
        linked = _resolve_linked_resource(
            all_resources, link["resourceTypes"], link.get("attribute", "bucket"),
            resource.address, link.get("match"),
        )
        if linked is None:
            return []
        target = linked
        ctx = dict(ctx, name=target.resourceName, address=target.address)

    # `skipIfLinked`: the sibling that would carry this fix already exists, so
    # creating a second one would be a duplicate-management conflict at apply
    # time. The `linkTo` variant of the same rule handles that case instead.
    if spec.get("skipIfLinked"):
        skip = spec["skipIfLinked"]
        if _resolve_linked_resource(
            all_resources, skip["resourceTypes"], skip.get("attribute", "bucket"),
            resource.address, skip.get("match"),
        ) is not None:
            return []

    # `${raw.<attr>}` -- the *source text* of one of the target's attributes.
    ctx = dict(ctx)
    for needed in spec.get("rawAttributes", []):
        value = _raw_attr_value(target, needed)
        if value is None:
            return []  # cannot build a correct companion without it
        ctx[f"raw.{needed}"] = value

    def _make(**kwargs: Any) -> PatchChange:
        return PatchChange(
            findingIds=[finding_id], ruleId=rule_id, category=category,
            targetAddress=target.address, **kwargs
        )

    if kind == "attribute":
        attr = spec["name"]
        value = _substitute(str(spec["value"]), ctx)
        line_no = _block_top_level_attr_line(target, attr)
        if line_no is not None:
            if spec.get("skipIfPresent"):
                return []
            old = target.rawContent.split("\n")[line_no - target.startLine].strip()
            old_rhs = old.split("=", 1)[-1].strip()
            if old_rhs == value:
                return []
            return [
                _make(type="modify", kind="attribute", path=attr,
                      description=description, oldValue=old, newValue=value)
            ]
        return [
            _make(type="add", kind="attribute", path=attr, description=description,
                  newValue=value)
        ]

    if kind == "block":
        name = spec["name"]
        if _has_top_level_block(target, name) and spec.get("skipIfPresent", True):
            return []
        body = [_substitute(line, ctx) for line in spec["body"]]
        return [_make(type="add", kind="block", path=name, description=description,
                      body=body)]

    if kind == "replace_block":
        name = spec["name"]
        span = _top_level_block_span(target, name)
        if span is None:
            return []
        body = [_substitute(line, ctx) for line in spec["body"]]
        old = "\n".join(
            target.rawContent.split("\n")[
                span[0] - target.startLine : span[1] - target.startLine + 1
            ]
        )
        return [_make(type="modify", kind="replace_block", path=name,
                      description=description, body=body, oldValue=old)]

    if kind == "nested_attribute":
        block = spec["block"]
        attr = spec["name"]
        value = _substitute(str(spec["value"]), ctx)
        span = _top_level_block_span(target, block)
        if span is None:
            return []
        return [
            _make(type="modify", kind="nested_attribute", path=f"{block}.{attr}",
                  description=description, newValue=value,
                  oldValue=_nested_attr_value(target, block, attr))
        ]

    if kind in ("companion", "shared"):
        # A shared resource may depend on another (the log bucket needs the CMK to
        # encrypt itself with). Emit the dependency first, or we generate a diff
        # with a dangling reference and `terraform validate` rejects it.
        out_pre: List[PatchChange] = []
        if kind == "shared":
            for dep in catalog.shared[spec["id"]].get("requires", []):
                out_pre.extend(
                    _build_changes(
                        {"kind": "shared", "id": dep}, rule_id, rule, resource,
                        finding_id, ctx, catalog, all_resources, existing,
                    )
                )

        if kind == "shared":
            entry = catalog.shared[spec["id"]]
            address = _substitute(entry["ref"], ctx)
            template = entry["template"]
            desc = _substitute(entry.get("description", description), ctx)
            creates = entry.get("createsResourceTypes", [])
            data_ids = entry.get("dataSources", [])
        else:
            entry = spec
            address = _substitute(spec["address"], ctx)
            template = spec["template"]
            desc = description
            creates = spec.get("createsResourceTypes", [])
            data_ids = spec.get("dataSources", [])

        out = out_pre + _data_source_changes(
            data_ids, catalog, existing, rule_id, category, finding_id, target.address
        )
        if address in existing:
            return out
        existing.add(address)
        out.append(
            _make(type="add", kind="companion", path=address, description=desc,
                  body=[_substitute(line, ctx) for line in template],
                  createsResourceTypes=list(creates))
        )
        return out

    raise ValueError(f"{rule_id}: unknown change kind {kind!r}")


# ===========================================================================
# isAutoApplicable (terraform-patch.ts:893) -- with the hard-coded never-list
# ===========================================================================


_EXPRESSION_RE = re.compile(r"(\$\{|\b(?:var|local|each|data|module)\.|\baws_[a-z0-9_]+\.)")


def _references_expression(old: Optional[str]) -> bool:
    """Does this attribute's current value reference something, rather than being a
    literal? `var.log_retention_days` -> True. `30` / `false` / `"AES256"` -> False.
    """
    if not old:
        return False
    rhs = old.split("=", 1)[-1]
    return bool(_EXPRESSION_RE.search(rhs))


def auto_apply_blocker(changes: Sequence[PatchChange]) -> Optional[str]:
    """Return the reason these changes may NOT be auto-applied, or None.

    Checked in order; the first four are the SPEC §6.3 hard-coded never-list and
    are not overridable by the catalog, by a flag, or by model confidence.
    """
    for change in changes:
        if change.category in NEVER_AUTO_APPLY_CATEGORIES:
            return (
                "never-auto-apply category %r (SPEC §6.3: access-affecting "
                "changes are always diff-only)" % change.category
            )

        touched = set(change.createsResourceTypes)
        if change.targetAddress:
            touched.add(change.targetAddress.split(".")[0])
        for resource_type in touched:
            if resource_type in NEVER_AUTO_APPLY_RESOURCE_TYPES:
                return (
                    "touches or creates %s, which is in the never-auto-apply "
                    "blast radius (SPEC §6.3)" % resource_type
                )

        if change.kind == "attribute" and change.path in NEVER_AUTO_APPLY_ATTRIBUTES:
            return (
                "attribute %r carries an access-control payload (SPEC §6.3)"
                % change.path
            )
        if change.kind == "block" and change.path in NEVER_AUTO_APPLY_ATTRIBUTES:
            return "block %r carries an access-control payload (SPEC §6.3)" % change.path

        # A structural rewrite is never "single-attribute".
        if change.kind == "replace_block":
            return (
                "rewrites the %r block wholesale, which is not a single-attribute "
                "change (SPEC §6.3)" % change.path
            )

        if change.type == "remove":
            return "removes configuration; only additive changes auto-apply (SPEC §6.3)"

        if change.type == "modify":
            # SPEC §6.3 lists `encrypted = true` as auto-applicable, and that IS a
            # false->true modify. So a modify is allowed -- but only when it
            # overwrites a LITERAL. Overwriting an expression (`var.retention_days`)
            # throws away a parameterisation somebody chose on purpose, and the
            # right fix is probably to change the variable's default instead.
            if _references_expression(change.oldValue):
                return (
                    "would overwrite the expression %r with a literal; changing a "
                    "deliberate parameterisation is not semantically unambiguous "
                    "(SPEC §6.3)" % (change.oldValue or "").split("=", 1)[-1].strip()
                )

    return None


def is_auto_applicable(changes: Sequence[PatchChange], rule_auto: bool = True) -> bool:
    """Additive, single-attribute, semantically unambiguous. Nothing else.

    `rule_auto` is the catalog's human-reviewed opinion; the never-list can only
    ever *veto* it. There is no path by which a never-list category becomes
    auto-applicable.
    """
    if auto_apply_blocker(changes) is not None:
        return False
    return bool(rule_auto)


# ===========================================================================
# Applying changes to text + unified diff
# ===========================================================================


def _format_block(name: str, body: Sequence[str], indent: str = INDENT) -> List[str]:
    out = [f"{indent}{name} {{"]
    out.extend(f"{indent}{line}" if line else "" for line in body)
    out.append(f"{indent}}}")
    return out


def apply_changes_to_lines(
    lines: List[str],
    changes: Sequence[PatchChange],
    resources_by_address: Dict[str, TerraformResource],
) -> List[str]:
    """Apply changes to one file's lines. Bottom-up, so line numbers stay valid.

    In-block insertions go immediately before the resource's closing brace,
    preceded by a blank line. The blank line is not cosmetic: `terraform fmt`
    aligns the `=` of *contiguous* attribute lines, so an attribute appended
    directly under an existing one would force fmt to re-align its neighbours
    and the patch would fail `fmt -check`. A blank line starts a new alignment
    group, which makes the insertion fmt-stable by construction.
    """
    out = list(lines)

    # Two rules can prescribe the identical edit (CKV_AWS_2, CKV2_AWS_20 and
    # CKV_AWS_103 are all fixed by the same HTTP->HTTPS redirect). Splicing the
    # same span twice corrupts the file, so identical edits collapse to one.
    deduped: List[PatchChange] = []
    seen_edits: set = set()
    for change in changes:
        key = (change.targetAddress, change.kind, change.path, change.newValue,
               tuple(change.body))
        if key in seen_edits:
            continue
        seen_edits.add(key)
        deduped.append(change)
    changes = deduped

    in_block = [
        c for c in changes
        if c.kind in ("attribute", "block", "replace_block", "nested_attribute")
    ]
    companions = [c for c in changes if c.kind == "companion"]

    # Every in-block edit becomes a (start, end, replacement) splice against the
    # ORIGINAL line numbers, then they are applied bottom-up so earlier line
    # numbers stay valid. Applying top-down is how a patcher corrupts a file.
    edits: List[Tuple[int, int, List[str]]] = []
    by_point: Dict[int, List[str]] = {}

    for change in in_block:
        resource = resources_by_address[change.targetAddress]

        if change.kind == "replace_block":
            span = _top_level_block_span(resource, change.path)
            if span is None:
                continue
            edits.append(
                (span[0] - 1, span[1], _format_block(change.path, change.body))
            )
            continue

        if change.kind == "nested_attribute":
            block, attr = change.path.split(".", 1)
            line_no = _nested_attr_line(resource, block, attr)
            if line_no is not None:
                idx = line_no - 1
                indent = re.match(r"^\s*", out[idx]).group(0)
                edits.append((idx, idx + 1, [f"{indent}{attr} = {change.newValue}"]))
            else:
                span = _top_level_block_span(resource, block)
                if span is None:
                    continue
                point = span[1] - 1  # the nested block's closing brace
                edits.append(
                    (point, point, [f"{INDENT * 2}{attr} = {change.newValue}"])
                )
            continue

        if change.type == "modify":
            line_no = _block_top_level_attr_line(resource, change.path)
            if line_no is None:
                continue
            idx = line_no - 1
            indent = re.match(r"^\s*", out[idx]).group(0)
            edits.append((idx, idx + 1, [f"{indent}{change.path} = {change.newValue}"]))
            continue

        # additive: insert immediately before the resource's closing brace
        point = resource.endLine - 1
        rendered = (
            [f"{INDENT}{change.path} = {change.newValue}"]
            if change.kind == "attribute"
            else _format_block(change.path, change.body)
        )
        # A blank line before the insertion starts a fresh `terraform fmt`
        # alignment group -- see the docstring.
        by_point.setdefault(point, [""])
        if len(by_point[point]) > 1:
            by_point[point].append("")
        by_point[point].extend(rendered)

    edits.extend((point, point, rendered) for point, rendered in by_point.items())

    for start, end, replacement in sorted(edits, key=lambda e: -e[0]):
        out[start:end] = replacement

    # --- companions appended at EOF, deduped ---
    if companions:
        seen: set = set()
        tail: List[str] = []
        for change in companions:
            if change.path in seen:
                continue
            seen.add(change.path)
            tail.append("")
            tail.extend(change.body)
        while out and out[-1].strip() == "":
            out.pop()
        out.extend(tail)
        out.append("")

    return out


def _terraform_available() -> bool:
    return shutil.which("terraform") is not None


def terraform_fmt_stdin(content: str) -> Optional[str]:
    """`terraform fmt -` : format HCL from stdin. None if terraform is absent/errors."""
    if not _terraform_available():
        return None
    try:
        proc = subprocess.run(
            ["terraform", "fmt", "-"], input=content, capture_output=True,
            text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def normalize_with_fmt(original: str, patched: str) -> str:
    """Run the patched content through `terraform fmt`, but ONLY when the original
    was already fmt-clean.

    Otherwise fmt would "fix" pre-existing formatting drift elsewhere in the file
    and the diff would carry hunks that have nothing to do with the security fix.
    A remediation diff that also reformats 40 unrelated lines does not get merged.
    """
    formatted_original = terraform_fmt_stdin(original)
    if formatted_original is None or formatted_original != original:
        return patched
    formatted_patched = terraform_fmt_stdin(patched)
    return formatted_patched if formatted_patched is not None else patched


def create_unified_diff(file: str, original: str, patched: str, context: int = 3) -> str:
    """A real unified diff. infrabot hand-rolled a line-by-line pseudo-diff
    (`terraform-patch.ts:842`) that `git apply` cannot consume; this one it can.
    """
    diff = difflib.unified_diff(
        original.split("\n"),
        patched.split("\n"),
        fromfile=f"a/{file}",
        tofile=f"b/{file}",
        lineterm="",
        n=context,
    )
    return "\n".join(diff)


# ===========================================================================
# generateSecurityPatches (terraform-patch.ts:368)
# ===========================================================================


def _highest_severity(severities: Sequence[str]) -> str:
    for level in ("critical", "high", "medium", "low", "informational"):
        if level in severities:
            return level
    return "unmapped"


def generate_security_patches(
    root: str,
    findings: Sequence[Dict[str, Any]],
    catalog: Optional[FixCatalog] = None,
    resources: Optional[Sequence[TerraformResource]] = None,
    use_fmt: bool = True,
) -> List[TerraformPatch]:
    """Findings -> patches, one per (file, resource).

    The join is `(location.file, location.resourceAddress)` -- §1.3's confirmed
    key. No ARN matching, no fuzzy name matching, no check-ID heuristics: all
    three of infrabot's `matchFindingsToResource()` strategies
    (`terraform-patch.ts:443`) were guesswork forced on it by having no line
    provenance. We have provenance, so we join exactly.
    """
    catalog = catalog or FixCatalog.load()
    parsed: Dict[str, Any] = {}
    if resources is None:
        resources, parsed = load_terraform_resources(root)

    by_address: Dict[str, TerraformResource] = {r.address: r for r in resources}

    # ONE `existing` set for the whole tree. A shared companion (the KMS key, the
    # log bucket) must be emitted exactly once across every file, or Terraform
    # sees a duplicate resource and `validate` hard-fails.
    existing: set = {r.address for r in resources}
    if not parsed:
        try:
            parsed = parse_iac.parse_terraform(root)
        except Exception:  # noqa: BLE001 - existence check is best-effort
            parsed = {}
    existing |= {d.get("address", "") for d in parsed.get("data_sources", [])}

    # group findings by the resource they land on
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        loc = finding.get("location") or {}
        address = loc.get("resourceAddress")
        if not address or address not in by_address:
            continue
        grouped.setdefault(address, []).append(finding)

    # ---- build changes per resource, then bucket them by FILE, because a
    # single file's patch must be applied as one coherent text edit.
    changes_by_file: Dict[str, List[PatchChange]] = {}
    meta_by_file: Dict[str, List[Tuple[TerraformResource, List[Dict[str, Any]], List[PatchChange]]]] = {}

    for address, res_findings in grouped.items():
        resource = by_address[address]
        changes = generate_changes_for_resource(
            resource, res_findings, catalog, resources, existing
        )
        if not changes:
            continue
        changes_by_file.setdefault(resource.file, []).extend(changes)
        meta_by_file.setdefault(resource.file, []).append((resource, res_findings, changes))

    patches: List[TerraformPatch] = []

    for file, entries in meta_by_file.items():
        abs_path = os.path.join(root, file)
        with open(abs_path, encoding="utf-8") as fh:
            original = fh.read()

        for resource, res_findings, changes in entries:
            patched_lines = apply_changes_to_lines(
                original.split("\n"), changes, by_address
            )
            patched = "\n".join(patched_lines)
            if use_fmt:
                patched = normalize_with_fmt(original, patched)
            if patched == original:
                continue

            diff = create_unified_diff(file, original, patched)
            rule_ids = sorted({c.ruleId for c in changes})
            severities = [f.get("severity") or "unmapped" for f in res_findings]
            rule_auto = bool(rule_ids) and all(
                (catalog.get(rid) or {}).get("autoApplicable", False) for rid in rule_ids
            )
            blocker = auto_apply_blocker(changes)

            patches.append(
                TerraformPatch(
                    file=file,
                    resourceType=resource.resourceType,
                    resourceName=resource.resourceName,
                    address=resource.address,
                    changes=changes,
                    diff=diff,
                    findingIds=sorted({f.get("id", "") for f in res_findings}),
                    ruleIds=rule_ids,
                    severity=_highest_severity(severities),
                    autoApplicable=is_auto_applicable(changes, rule_auto),
                    autoApplyBlockedBy=blocker,
                )
            )

    return patches


def apply_patches_to_tree(
    root: str,
    patches: Sequence[TerraformPatch],
    resources: Sequence[TerraformResource],
    only_auto_applicable: bool = False,
    use_fmt: bool = True,
) -> PatchApplicationResult:
    """Write patches to disk, coalescing every patch for a file into one edit.

    (terraform-patch.ts:918 `applyPatches`, but file-coherent -- infrabot applied
    patches by string-replacing `rawContent`, which corrupts a file the moment
    two resources in it share identical text.)
    """
    result = PatchApplicationResult()
    by_address = {r.address: r for r in resources}

    selected: List[TerraformPatch] = []
    for patch in patches:
        if only_auto_applicable and not patch.autoApplicable:
            result.skippedCount += 1
            result.skipped.append(
                {
                    "resource": patch.address,
                    "rules": ",".join(patch.ruleIds),
                    "reason": patch.autoApplyBlockedBy or "not marked auto-applicable in the fix catalog",
                }
            )
            continue
        selected.append(patch)

    by_file: Dict[str, List[TerraformPatch]] = {}
    for patch in selected:
        by_file.setdefault(patch.file, []).append(patch)

    for file, file_patches in by_file.items():
        abs_path = os.path.join(root, file)
        try:
            with open(abs_path, encoding="utf-8") as fh:
                original = fh.read()
            changes: List[PatchChange] = []
            for patch in file_patches:
                changes.extend(patch.changes)
            patched = "\n".join(
                apply_changes_to_lines(original.split("\n"), changes, by_address)
            )
            if use_fmt:
                patched = normalize_with_fmt(original, patched)
            if patched == original:
                continue
            with open(abs_path, "w", encoding="utf-8") as fh:
                fh.write(patched)
            result.modifiedFiles.append(file)
            result.appliedCount += len(file_patches)
        except OSError as exc:
            result.errors.append(f"Error applying patches to {file}: {exc}")
            result.failedCount += len(file_patches)
            result.success = False

    return result


# ===========================================================================
# Git (terraform-patch.ts:1009 createPatchBranch / :1095 generateCommitMessage)
# ===========================================================================


def _git(root: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", root, *args], capture_output=True, text=True, timeout=60
    )


def generate_commit_message(patches: Sequence[TerraformPatch], applied: int, files: int) -> str:
    """(terraform-patch.ts:1095) One commit per finding group -- a bad fix is one
    `git revert` away."""
    critical = sum(1 for p in patches if p.severity == "critical")
    high = sum(1 for p in patches if p.severity == "high")

    if critical:
        title = f"fix: apply {critical} critical security patches to Terraform"
    elif high:
        title = f"fix: apply {high} high severity security patches to Terraform"
    else:
        title = f"fix: apply {len(patches)} security patches to Terraform"

    lines = [title, "", f"Applied {applied} patches across {files} files.", ""]

    by_severity: Dict[str, List[TerraformPatch]] = {}
    for patch in patches:
        by_severity.setdefault(patch.severity, []).append(patch)

    for severity in ("critical", "high", "medium", "low", "informational", "unmapped"):
        group = by_severity.get(severity)
        if not group:
            continue
        lines.append(f"{severity.upper()}:")
        for patch in group[:5]:
            desc = ", ".join(c.description for c in patch.changes)
            lines.append(f"- {patch.address}: {desc}")
        if len(group) > 5:
            lines.append(f"- ...and {len(group) - 5} more")
        lines.append("")

    lines.append("Generated by iac-security-scan")
    return "\n".join(lines)


def create_patch_branch(
    root: str,
    patches: Sequence[TerraformPatch],
    resources: Sequence[TerraformResource],
    branch_name: Optional[str] = None,
) -> BranchCreationResult:
    """Apply auto-applicable patches on a NEW branch, never on a dirty tree.

    SPEC §6.3 rails, in order and all of them:
      1. refuse on a dirty tree -- no --force, no exceptions
      2. always a new branch `iac-security-scan/fix-<timestamp>`, never `main`
      3. only `autoApplicable` changes
      4. never an access-affecting change (enforced upstream by the never-list)
      5. one commit
      6. report what was skipped and why
    """
    branch = branch_name or f"iac-security-scan/fix-{int(time.time())}"
    result = BranchCreationResult(branchName=branch)

    if _git(root, "rev-parse", "--is-inside-work-tree").returncode != 0:
        result.error = "Not a git repository"
        return result

    status = _git(root, "status", "--porcelain")
    if status.stdout.strip():
        result.error = (
            "Working tree has uncommitted changes. Commit or stash first "
            "(SPEC §6.3 rail 1 -- there is no --force)."
        )
        return result

    checkout = _git(root, "checkout", "-b", branch)
    if checkout.returncode != 0:
        result.error = f"Could not create branch {branch}: {checkout.stderr.strip()}"
        return result

    applied = apply_patches_to_tree(root, patches, resources, only_auto_applicable=True)
    if not applied.success or not applied.modifiedFiles:
        result.error = (
            "No auto-applicable patches to commit. "
            + "; ".join(applied.errors)
        ).strip()
        return result

    for file in applied.modifiedFiles:
        _git(root, "add", file)
        result.committedFiles.append(file)

    message = generate_commit_message(
        [p for p in patches if p.autoApplicable],
        applied.appliedCount,
        len(applied.modifiedFiles),
    )
    commit = _git(root, "commit", "-m", message)
    if commit.returncode != 0:
        result.error = f"Commit failed: {commit.stderr.strip()}"
        return result

    result.commitHash = _git(root, "rev-parse", "HEAD").stdout.strip()
    result.success = True
    return result


# ===========================================================================
# Reporting (terraform-patch.ts:1155 / :1196)
# ===========================================================================


def export_patch_files(patches: Sequence[TerraformPatch], out_dir: str) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    written: List[str] = []
    for i, patch in enumerate(patches, start=1):
        fname = f"{i}-{patch.severity}-{patch.resourceType}-{patch.resourceName}.patch"
        path = os.path.join(out_dir, fname)
        header = [
            "# Terraform Security Patch",
            f"# Resource: {patch.address}",
            f"# File: {patch.file}",
            f"# Severity: {patch.severity}",
            f"# Rules: {', '.join(patch.ruleIds)}",
            f"# Finding IDs: {', '.join(patch.findingIds)}",
            f"# Auto-applicable: {patch.autoApplicable}",
        ]
        if not patch.autoApplicable:
            header.append(f"# Diff-only because: {patch.autoApplyBlockedBy}")
        header += ["", "# Changes:"]
        header += [f"# - {c.description}" for c in patch.changes]
        header += ["", patch.diff, ""]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(header))
        written.append(path)
    return written


def generate_patch_report(patches: Sequence[TerraformPatch]) -> str:
    lines = ["# Terraform Security Patch Report", "", f"Total patches: {len(patches)}", ""]
    auto = sum(1 for p in patches if p.autoApplicable)
    lines += [
        "## Auto-applicable",
        "",
        f"{auto} of {len(patches)} patches are auto-applicable "
        f"(additive, single-attribute, semantically unambiguous).",
        f"{len(patches) - auto} are diff-only and require review.",
        "",
    ]
    for patch in patches:
        lines += [
            f"### {patch.address}  ({patch.severity})",
            "",
            f"- File: `{patch.file}`",
            f"- Rules: {', '.join(patch.ruleIds)}",
            f"- Auto-applicable: {'yes' if patch.autoApplicable else 'no'}",
        ]
        if not patch.autoApplicable:
            lines.append(f"- Diff-only because: {patch.autoApplyBlockedBy}")
        lines += ["", "```diff", patch.diff, "```", ""]
    return "\n".join(lines)


# ===========================================================================
# CLI
# ===========================================================================


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic Terraform security patches from Checkov findings."
    )
    parser.add_argument("path", help="Terraform directory to patch")
    parser.add_argument("--findings", help="Path to a run_checkov.py JSON payload (default: run it)")
    parser.add_argument("--json-only", action="store_true", help="Emit only JSON on stdout")
    parser.add_argument("--markdown", action="store_true", help="Emit the markdown patch report")
    parser.add_argument("--no-fmt", action="store_true", help="Skip terraform fmt normalization")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.path):
        print(f"error: not a directory: {args.path}", file=sys.stderr)
        return 2

    if args.findings:
        with open(args.findings, encoding="utf-8") as fh:
            payload = json.load(fh)
    else:
        import run_checkov

        payload = run_checkov.run_checkov(args.path)

    findings = payload.get("findings", [])

    try:
        catalog = FixCatalog.load()
        resources, _ = load_terraform_resources(args.path)
        patches = generate_security_patches(
            args.path, findings, catalog, resources, use_fmt=not args.no_fmt
        )
    except Exception as exc:  # noqa: BLE001 -- scan error is exit 2 (SPEC §9.2)
        print(f"error: patch generation failed: {exc}", file=sys.stderr)
        return 2

    if args.markdown:
        print(generate_patch_report(patches))
        return 0

    fixed_rules = sorted({r for p in patches for r in p.ruleIds})
    out = {
        "path": os.path.abspath(args.path),
        "catalogSize": len(catalog),
        "totalFindings": len(findings),
        "patches": [p.to_dict() for p in patches],
        "patchCount": len(patches),
        "autoApplicableCount": sum(1 for p in patches if p.autoApplicable),
        "rulesFixed": fixed_rules,
    }
    json.dump(out, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
