#!/usr/bin/env python3
"""
Deterministic CloudFormation patcher (WS-13).

The CloudFormation analogue of ``patch_terraform.py`` (WS-5). Same philosophy,
same safety line (SPEC 6.3), a different fixer -- CFN templates are YAML/JSON, so
where the Terraform patcher inserts an HCL block, this one inserts a property
under a resource's ``Properties`` map.

    We do NOT regex the YAML. Resource boundaries come from the WS-12 provenance:

        parse_iac.py cloudformation <template> --json-only

    emits, per resource, a `location` with startLine/endLine/resourceAddress
    (the CFN *logical ID*)/resourceType (`AWS::S3::Bucket`)/service. We place
    every edit inside those boundaries, structurally, by YAML indentation.

THE JOIN (the one CFN-specific wrinkle):

    parse_iac's `location.resourceAddress` is the bare logical ID: `WebBucket`.
    Checkov's is the fully-qualified `AWS::S3::Bucket.WebBucket`. CFN logical IDs
    are alphanumeric (no dots) and CFN type names use `::` (no dots), so the
    logical ID is always the last dotted component of Checkov's address. That is
    the whole translation, and it lives in `_logical_id()`.

THE SAFETY LINE (SPEC 6.3) -- identical to WS-5, non-negotiable:

    `autoApplicable` means additive, single-property, semantically unambiguous.
    Nothing else.

    Never-auto-apply, always diff-only, at ANY confidence:
        1. SecurityGroup ingress CIDR
        2. IAM policy / wildcard
        3. S3 BucketPolicy
        4. KMS key policy
        5. Network ACLs

    Enforced by `cfn_auto_apply_blocker()`, a hard-coded veto that the catalog's
    `autoApplicable` flag can never override. The category set is reused verbatim
    from `patch_terraform` (categories are format-agnostic); the resource-type and
    attribute lists are the CFN-specific mirror.
    `tests/test_patch_cloudformation.py::TestNeverAutoApply` fails if any of the
    five is ever marked auto-applicable. That test does not get relaxed.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import parse_iac  # noqa: E402  (WS-12 parser -- the reason we do not regex YAML)

# Reused, generic, format-agnostic pieces of the WS-5 patcher. Nothing
# Terraform-specific crosses this import: PatchChange/FilePatch are plain
# containers, create_unified_diff is difflib, the category set is the SPEC 6.3
# never-list, and the git/report helpers only read the structural fields a
# CFNPatch shares with a TerraformPatch.
from patch_terraform import (  # noqa: E402
    PatchChange,
    FilePatch,
    PatchApplicationResult,
    BranchCreationResult,
    NEVER_AUTO_APPLY_CATEGORIES,
    create_unified_diff,
    _highest_severity,
    _git,
    generate_commit_message,
)

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
FIX_RULES_CFN_PATH = os.path.join(_DATA_DIR, "fix-rules-cfn.json")


# ===========================================================================
# THE NEVER-AUTO-APPLY LIST (SPEC 6.3 rail 4) -- CFN mirror, hard-coded
# ===========================================================================

#: CloudFormation resource types in the never-auto-apply blast radius. A change
#: landing on one of these is diff-only, full stop, mirroring
#: patch_terraform.NEVER_AUTO_APPLY_RESOURCE_TYPES.
NEVER_AUTO_APPLY_RESOURCE_TYPES_CFN = frozenset(
    {
        # 1. security-group CIDR narrowing
        "AWS::EC2::SecurityGroup",
        "AWS::EC2::SecurityGroupIngress",
        "AWS::EC2::SecurityGroupEgress",
        # 2. IAM policy / wildcard
        "AWS::IAM::Role",
        "AWS::IAM::Policy",
        "AWS::IAM::ManagedPolicy",
        "AWS::IAM::User",
        "AWS::IAM::Group",
        "AWS::IAM::UserPolicy",
        "AWS::IAM::RolePolicy",
        "AWS::IAM::GroupPolicy",
        # 3. bucket-policy changes
        "AWS::S3::BucketPolicy",
        # 4. KMS key-policy changes
        "AWS::KMS::Key",
        # 5. network ACLs
        "AWS::EC2::NetworkAcl",
        "AWS::EC2::NetworkAclEntry",
    }
)

#: CFN property names that carry an access-control payload wherever they appear.
NEVER_AUTO_APPLY_ATTRIBUTES_CFN = frozenset(
    {
        "KeyPolicy",
        "PolicyDocument",
        "AssumeRolePolicyDocument",
        "Policies",
        "SecurityGroupIngress",
        "SecurityGroupEgress",
        "Ingress",
        "Egress",
        "CidrIp",
        "CidrIpv6",
        "SourceSecurityGroupId",
        "PubliclyAccessible",  # flipping it removes a network path (access-affecting)
    }
)

#: cfn-lint / CFN intrinsic markers. If a property's current value references one
#: of these, it is a deliberate parameterisation and overwriting it with a literal
#: is not "semantically unambiguous" -- the right fix is to change the parameter.
_INTRINSIC_RE = re.compile(
    r"(!Ref\b|!GetAtt\b|!Sub\b|!If\b|!Select\b|!FindInMap\b|!ImportValue\b|!Join\b|\$\{)"
)


# ===========================================================================
# Schema
# ===========================================================================


@dataclass
class CFNResource:
    """A parsed CloudFormation resource, boundaries from WS-12 provenance.

    `startLine`/`endLine` are 1-based, inclusive. `address` is the logical ID,
    which is the join key against Checkov's fully-qualified resource address.
    """

    file: str  # relative to the template's directory (e.g. "template.yaml")
    resourceType: str  # "AWS::S3::Bucket"
    logicalId: str  # "WebBucket"
    startLine: int
    endLine: int
    rawContent: str
    absFile: str = ""

    @property
    def address(self) -> str:
        return self.logicalId

    @property
    def has_provenance(self) -> bool:
        return bool(self.startLine) and bool(self.endLine)


@dataclass
class CFNPatch:
    """A patch for one resource. Structural twin of TerraformPatch, so the reused
    generate_commit_message / _highest_severity helpers work unchanged."""

    file: str
    resourceType: str
    logicalId: str
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
            "logicalId": self.logicalId,
            "address": self.address,
            "changes": [c.to_dict() for c in self.changes],
            "diff": self.diff,
            "findingIds": list(self.findingIds),
            "ruleIds": list(self.ruleIds),
            "severity": self.severity,
            "autoApplicable": self.autoApplicable,
            "autoApplyBlockedBy": self.autoApplyBlockedBy,
        }


# ===========================================================================
# The fix catalog
# ===========================================================================


class CFNFixCatalog:
    """`data/fix-rules-cfn.json` -- the deterministic CFN fix catalog.

    Static, checked-in data, exactly like fix-rules.json. The model does not
    write to it at runtime.
    """

    def __init__(self, payload: Dict[str, Any]):
        self.rules: Dict[str, Any] = payload.get("rules", {})
        for rule_id, rule in self.rules.items():
            if "changes" not in rule or not rule["changes"]:
                raise ValueError(f"{rule_id}: fix rule has no changes")
            if "resourceTypes" not in rule:
                raise ValueError(f"{rule_id}: fix rule has no resourceTypes")
            for spec in rule["changes"]:
                if spec.get("kind") not in ("attribute", "block"):
                    raise ValueError(
                        f"{rule_id}: unknown CFN change kind {spec.get('kind')!r}"
                    )

    @classmethod
    def load(cls, path: Optional[str] = None) -> "CFNFixCatalog":
        with open(path or FIX_RULES_CFN_PATH, encoding="utf-8") as fh:
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


def _logical_id(resource_address: str) -> str:
    """Checkov's `AWS::S3::Bucket.WebBucket` -> `WebBucket`; passthrough for a bare id.

    CFN logical IDs are alphanumeric and CFN types use `::`, so the logical ID is
    always the final dotted component.
    """
    if not resource_address:
        return ""
    return resource_address.split(".")[-1]


# ===========================================================================
# YAML layout -- structural, indentation-based, never a content regex
# ===========================================================================


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


@dataclass
class _Layout:
    base_indent: int  # the logical-id line's indent
    key_indent: int  # Type: / Properties: indent
    props_offset: Optional[int]  # offset of `Properties:` within rawContent, or None
    prop_indent: int  # indent of properties (children of Properties:)
    first_prop_offset: Optional[int]  # offset of the first property line, or None


def _layout(resource: CFNResource) -> _Layout:
    """Locate the `Properties:` block and its child indentation inside a resource.

    Purely indentation-driven, so a `VersioningConfiguration` nested three levels
    deep is never mistaken for a top-level property -- the kind of thing a regex
    parser gets wrong, and the reason WS-12's provenance exists.
    """
    lines = resource.rawContent.split("\n")
    base = _indent(lines[0]) if lines else 0
    key_indent: Optional[int] = None
    props_offset: Optional[int] = None
    props_re = re.compile(r"\s*Properties\s*:\s*$")

    for offset, line in enumerate(lines):
        if offset == 0 or not line.strip():
            continue
        ind = _indent(line)
        if ind <= base:
            break
        if key_indent is None:
            key_indent = ind
        if ind == key_indent and props_re.match(line):
            props_offset = offset
            break

    if key_indent is None:
        key_indent = base + 2

    prop_indent: Optional[int] = None
    first_prop_offset: Optional[int] = None
    if props_offset is not None:
        for offset in range(props_offset + 1, len(lines)):
            line = lines[offset]
            if not line.strip():
                continue
            ind = _indent(line)
            if ind <= key_indent:
                break
            prop_indent = ind
            first_prop_offset = offset
            break
    if prop_indent is None:
        prop_indent = key_indent + 2

    return _Layout(base, key_indent, props_offset, prop_indent, first_prop_offset)


def _top_level_prop_offset(resource: CFNResource, name: str) -> Optional[int]:
    """Offset (within rawContent) of a top-level `Name:` inside Properties, or None.

    Only matches at exactly the property indent, so `Status:` inside a nested
    `VersioningConfiguration` never masquerades as a top-level property.
    """
    layout = _layout(resource)
    if layout.props_offset is None:
        return None
    lines = resource.rawContent.split("\n")
    pat = re.compile(r"\s*" + re.escape(name) + r"\s*:")
    for offset in range(layout.props_offset + 1, len(lines)):
        line = lines[offset]
        if not line.strip():
            continue
        ind = _indent(line)
        if ind <= layout.key_indent:
            break
        if ind == layout.prop_indent and pat.match(line):
            return offset
    return None


def _top_level_prop_value(resource: CFNResource, name: str) -> Optional[str]:
    offset = _top_level_prop_offset(resource, name)
    if offset is None:
        return None
    line = resource.rawContent.split("\n")[offset]
    return line.split(":", 1)[1].strip()


# ===========================================================================
# Change generation
# ===========================================================================


def generate_changes_for_resource(
    resource: CFNResource,
    findings: Sequence[Dict[str, Any]],
    catalog: CFNFixCatalog,
) -> List[PatchChange]:
    """Turn (resource, findings) into concrete PatchChanges, data-driven off the catalog.

    Zero changes is a legitimate answer: if the property is already present (add),
    or the referenced property is absent (modify), we emit nothing rather than a
    diff that would not apply or would duplicate a key.
    """
    changes: List[PatchChange] = []

    for finding in findings:
        rule_id = finding.get("ruleId", "")
        rule = catalog.get(rule_id)
        if rule is None:
            continue
        if resource.resourceType not in rule["resourceTypes"]:
            continue
        finding_id = finding.get("id", "")
        category = rule.get("category", "")

        for spec in rule["changes"]:
            kind = spec["kind"]
            name = spec["name"]
            description = spec.get("description", rule.get("title", rule_id))

            def _make(**kwargs: Any) -> PatchChange:
                return PatchChange(
                    findingIds=[finding_id],
                    ruleId=rule_id,
                    category=category,
                    targetAddress=resource.address,
                    **kwargs,
                )

            if kind == "attribute":
                value = str(spec["value"])
                existing_off = _top_level_prop_offset(resource, name)
                if existing_off is not None:
                    old = resource.rawContent.split("\n")[existing_off].strip()
                    old_rhs = old.split(":", 1)[-1].strip()
                    if old_rhs == value:
                        continue  # already correct
                    changes.append(
                        _make(
                            type="modify",
                            kind="attribute",
                            path=name,
                            description=description,
                            oldValue=old,
                            newValue=value,
                        )
                    )
                else:
                    changes.append(
                        _make(
                            type="add",
                            kind="attribute",
                            path=name,
                            description=description,
                            newValue=value,
                        )
                    )

            elif kind == "block":
                if _top_level_prop_offset(resource, name) is not None:
                    continue  # block already present
                changes.append(
                    _make(
                        type="add",
                        kind="block",
                        path=name,
                        description=description,
                        body=list(spec["body"]),
                    )
                )

    return changes


# ===========================================================================
# isAutoApplicable -- with the hard-coded CFN never-list
# ===========================================================================


def _references_intrinsic(old: Optional[str]) -> bool:
    if not old:
        return False
    rhs = old.split(":", 1)[-1] if ":" in old else old
    return bool(_INTRINSIC_RE.search(rhs))


def cfn_auto_apply_blocker(
    changes: Sequence[PatchChange], resource_type: str
) -> Optional[str]:
    """Return the reason these changes may NOT be auto-applied, or None.

    The five SPEC 6.3 categories are hard-coded and not overridable by the
    catalog, by a flag, or by model confidence. Category set reused from
    patch_terraform; resource-type / attribute lists are the CFN mirror.
    """
    if resource_type in NEVER_AUTO_APPLY_RESOURCE_TYPES_CFN:
        return (
            "resource type %s is in the never-auto-apply blast radius "
            "(SPEC 6.3)" % resource_type
        )

    for change in changes:
        if change.category in NEVER_AUTO_APPLY_CATEGORIES:
            return (
                "never-auto-apply category %r (SPEC 6.3: access-affecting changes "
                "are always diff-only)" % change.category
            )

        for created in change.createsResourceTypes:
            if created in NEVER_AUTO_APPLY_RESOURCE_TYPES_CFN:
                return (
                    "creates %s, which is in the never-auto-apply blast radius "
                    "(SPEC 6.3)" % created
                )

        if change.kind in ("attribute", "block") and change.path in NEVER_AUTO_APPLY_ATTRIBUTES_CFN:
            return (
                "property %r carries an access-control payload (SPEC 6.3)"
                % change.path
            )

        if change.type == "remove":
            return "removes configuration; only additive changes auto-apply (SPEC 6.3)"

        if change.type == "modify" and _references_intrinsic(change.oldValue):
            return (
                "would overwrite a CFN intrinsic (%s) with a literal; changing a "
                "deliberate parameterisation is not semantically unambiguous "
                "(SPEC 6.3)" % (change.oldValue or "").split(":", 1)[-1].strip()
            )

    return None


def is_auto_applicable(
    changes: Sequence[PatchChange], resource_type: str, rule_auto: bool = True
) -> bool:
    """Additive, single-property, semantically unambiguous. Nothing else.

    `rule_auto` is the catalog's human-reviewed opinion; the never-list can only
    ever *veto* it. There is no path by which a never-list case auto-applies.
    """
    if cfn_auto_apply_blocker(changes, resource_type) is not None:
        return False
    return bool(rule_auto)


# ===========================================================================
# Applying changes to text
# ===========================================================================


def apply_changes_to_lines(
    lines: List[str],
    changes: Sequence[PatchChange],
    resources_by_address: Dict[str, CFNResource],
) -> List[str]:
    """Apply changes to one template's lines. Bottom-up, so line numbers stay valid.

    Additions are inserted as the FIRST property under `Properties:` -- the one
    insertion point in a block-style YAML resource that is guaranteed to sit at
    the property indent and never inside a nested list/map. (Inserting at the end
    of the Properties body can land in the middle of a trailing
    GlobalSecondaryIndexes list and produce invalid YAML.)
    Modifications rewrite the property's own line in place.
    """
    out = list(lines)

    # Collapse identical edits (two rules prescribing the same property).
    deduped: List[PatchChange] = []
    seen: set = set()
    for change in changes:
        key = (change.targetAddress, change.kind, change.path, change.newValue, tuple(change.body))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(change)
    changes = deduped

    # Each edit is (start_idx, end_idx, replacement_lines) against ORIGINAL file
    # indices; applied bottom-up so earlier indices stay valid.
    edits: List[Tuple[int, int, List[str]]] = []
    additions_by_point: Dict[Tuple[int, int], List[str]] = {}

    for change in changes:
        resource = resources_by_address.get(change.targetAddress)
        if resource is None:
            continue
        layout = _layout(resource)

        if change.type == "modify":
            off = _top_level_prop_offset(resource, change.path)
            if off is None:
                continue
            idx = resource.startLine - 1 + off
            indent = re.match(r"^\s*", out[idx]).group(0)
            edits.append((idx, idx + 1, [f"{indent}{change.path}: {change.newValue}"]))
            continue

        # additive: render the property lines...
        indent = " " * layout.prop_indent
        if change.kind == "attribute":
            rendered = [f"{indent}{change.path}: {change.newValue}"]
        else:  # block
            rendered = [f"{indent}{change.path}:"]
            rendered += [f"{indent}  {b}" for b in change.body]

        # ...and place them at the first-property line (or synthesise Properties:).
        if layout.first_prop_offset is not None:
            point = resource.startLine - 1 + layout.first_prop_offset
            additions_by_point.setdefault((point, point), []).extend(rendered)
        elif layout.props_offset is not None:
            # Properties: exists but is empty -> insert right after it.
            point = resource.startLine - 1 + layout.props_offset + 1
            additions_by_point.setdefault((point, point), []).extend(rendered)
        else:
            # No Properties: block at all -> create one after the Type: line.
            # prop_indent defaulted to key_indent+2, so `rendered` already sits at
            # the right depth to nest directly under a fresh `Properties:`.
            type_off = _type_offset(resource)
            point = resource.startLine - 1 + type_off + 1
            block = [f"{' ' * layout.key_indent}Properties:"] + rendered
            additions_by_point.setdefault((point, point), []).extend(block)

    for (start, end), rendered in additions_by_point.items():
        edits.append((start, end, rendered + out[start:end]))

    for start, end, replacement in sorted(edits, key=lambda e: -e[0]):
        out[start:end] = replacement

    return out


def _type_offset(resource: CFNResource) -> int:
    lines = resource.rawContent.split("\n")
    for offset, line in enumerate(lines):
        if re.match(r"\s*Type\s*:", line):
            return offset
    return 0


# ===========================================================================
# Loading resources -- via the WS-12 parser
# ===========================================================================


def _parse(template_file: str) -> Dict[str, Any]:
    """Call the WS-12 CFN parser with its progress chatter forced onto stderr."""
    with contextlib.redirect_stdout(sys.stderr):
        return parse_iac.parse_cloudformation(template_file)


def load_cloudformation_resources(
    template_file: str,
) -> Tuple[List[CFNResource], Dict[str, Any]]:
    """Load resources from `parse_iac.py`. Raises if the parse is degraded.

    ``template_file`` may be one template or a DIRECTORY of templates; for a
    directory every resource's ``file`` is relative to it, so the patches that
    come out apply against that directory.

    A degraded parse has no line provenance, and without it nothing can be
    anchored. We refuse rather than emit a diff we cannot place.
    """
    parsed = _parse(template_file)
    if parsed.get("error"):
        raise RuntimeError(parsed["error"])
    if parsed.get("degraded"):
        raise RuntimeError(
            "DEGRADED PARSE (tier=%s): no line provenance, so no CFN patches can "
            "be anchored. Install cfn-lint and re-run." % parsed.get("parseTier")
        )

    if os.path.isdir(template_file):
        root = os.path.abspath(template_file)
    else:
        root = os.path.dirname(os.path.abspath(template_file))
    resources: List[CFNResource] = []
    file_cache: Dict[str, List[str]] = {}

    for res in parsed.get("resources", []):
        loc = res.get("location") or {}
        rel = loc.get("file") or os.path.basename(template_file)
        start, end = loc.get("startLine"), loc.get("endLine")
        logical = loc.get("resourceAddress") or ""
        if not start or not end or not logical:
            continue
        abs_path = os.path.join(root, rel)
        if rel not in file_cache:
            if not os.path.isfile(abs_path):
                # single-file scan: fall back to the template we were given
                abs_path = os.path.abspath(template_file)
                rel = os.path.basename(template_file)
                if rel not in file_cache:
                    with open(abs_path, encoding="utf-8") as fh:
                        file_cache[rel] = fh.read().split("\n")
            else:
                with open(abs_path, encoding="utf-8") as fh:
                    file_cache[rel] = fh.read().split("\n")
        lines = file_cache[rel]
        raw = "\n".join(lines[start - 1 : end])
        resources.append(
            CFNResource(
                file=rel,
                resourceType=loc.get("resourceType") or res.get("type", ""),
                logicalId=logical,
                startLine=int(start),
                endLine=int(end),
                rawContent=raw,
                absFile=abs_path,
            )
        )

    return resources, parsed


# ===========================================================================
# generate_security_patches
# ===========================================================================


def generate_security_patches(
    template_file: str,
    findings: Sequence[Dict[str, Any]],
    catalog: Optional[CFNFixCatalog] = None,
    resources: Optional[Sequence[CFNResource]] = None,
) -> List[CFNPatch]:
    """Findings -> patches, one per resource.

    The join is `location.resourceAddress` reduced to the logical ID (see
    `_logical_id`). No fuzzy matching: WS-12 gives exact provenance.
    """
    catalog = catalog or CFNFixCatalog.load()
    if resources is None:
        resources, _ = load_cloudformation_resources(template_file)

    by_address: Dict[str, CFNResource] = {r.address: r for r in resources}

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        loc = finding.get("location") or {}
        logical = _logical_id(loc.get("resourceAddress") or "")
        if not logical or logical not in by_address:
            continue
        grouped.setdefault(logical, []).append(finding)

    patches: List[CFNPatch] = []
    file_cache: Dict[str, str] = {}

    for logical, res_findings in grouped.items():
        resource = by_address[logical]
        changes = generate_changes_for_resource(resource, res_findings, catalog)
        if not changes:
            continue

        if resource.absFile not in file_cache:
            with open(resource.absFile, encoding="utf-8") as fh:
                file_cache[resource.absFile] = fh.read()
        original = file_cache[resource.absFile]

        patched = "\n".join(
            apply_changes_to_lines(original.split("\n"), changes, by_address)
        )
        if patched == original:
            continue

        diff = create_unified_diff(resource.file, original, patched)
        rule_ids = sorted({c.ruleId for c in changes})
        fixed = [f for f in res_findings if (f.get("ruleId") or "") in set(rule_ids)]
        severities = [f.get("severity") or "unmapped" for f in fixed]
        rule_auto = bool(rule_ids) and all(
            (catalog.get(rid) or {}).get("autoApplicable", False) for rid in rule_ids
        )
        blocker = cfn_auto_apply_blocker(changes, resource.resourceType)

        patches.append(
            CFNPatch(
                file=resource.file,
                resourceType=resource.resourceType,
                logicalId=resource.logicalId,
                address=resource.address,
                changes=changes,
                diff=diff,
                findingIds=sorted({f.get("id", "") for f in fixed}),
                ruleIds=rule_ids,
                severity=_highest_severity(severities),
                autoApplicable=is_auto_applicable(
                    changes, resource.resourceType, rule_auto
                ),
                autoApplyBlockedBy=blocker,
            )
        )

    return patches


# ===========================================================================
# The applicable (git apply-able) per-file patch set
# ===========================================================================


def _group_by_file(
    patches: Sequence[CFNPatch],
    only_auto_applicable: bool,
    result: Optional[PatchApplicationResult] = None,
) -> Dict[str, List[CFNPatch]]:
    """Select patches to act on and bucket them by file.

    SPEC 6.3 rail 6: anything skipped is recorded with a reason.
    """
    by_file: Dict[str, List[CFNPatch]] = {}
    for patch in patches:
        if only_auto_applicable and not patch.autoApplicable:
            if result is not None:
                result.skippedCount += 1
                result.skipped.append(
                    {
                        "resource": patch.address,
                        "rules": ",".join(patch.ruleIds),
                        "reason": patch.autoApplyBlockedBy
                        or "not marked auto-applicable in the fix catalog",
                    }
                )
            continue
        by_file.setdefault(patch.file, []).append(patch)
    return by_file


def _patched_content(
    root: str,
    file: str,
    patches: Sequence[CFNPatch],
    by_address: Dict[str, CFNResource],
) -> Tuple[str, str, List[PatchChange]]:
    """(original, patched, changes) for one file -- the SINGLE source of truth.

    Both the emitted patch set and the on-disk apply go through here, so the diff
    we hand a user and the edit we would make ourselves cannot drift apart.
    """
    with open(os.path.join(root, file), encoding="utf-8") as fh:
        original = fh.read()
    changes: List[PatchChange] = []
    for patch in patches:
        changes.extend(patch.changes)
    patched = "\n".join(apply_changes_to_lines(original.split("\n"), changes, by_address))
    return original, patched, changes


def generate_file_patches(
    root: str,
    patches: Sequence[CFNPatch],
    resources: Sequence[CFNResource],
    only_auto_applicable: bool = False,
) -> List[FilePatch]:
    """The APPLICABLE patch set: one coherent diff per file, against the pristine file.

    Per-resource diffs are each computed against the pristine file, so applying
    several that touch the same template fails on the second hunk. This coalesces
    every change for a file into ONE diff that `git apply` will take -- mirroring
    patch_terraform.generate_file_patches / the FilePatch design.
    """
    by_address = {r.address: r for r in resources}
    out: List[FilePatch] = []

    for file, file_patches in _group_by_file(patches, only_auto_applicable).items():
        original, patched, changes = _patched_content(root, file, file_patches, by_address)
        if patched == original:
            continue
        out.append(
            FilePatch(
                file=file,
                diff=create_unified_diff(file, original, patched),
                changes=changes,
                ruleIds=sorted({r for p in file_patches for r in p.ruleIds}),
                findingIds=sorted({f for p in file_patches for f in p.findingIds}),
                patchCount=len(file_patches),
                autoApplicable=all(p.autoApplicable for p in file_patches),
            )
        )

    return sorted(out, key=lambda fp: fp.file)


def apply_patches_to_tree(
    root: str,
    patches: Sequence[CFNPatch],
    resources: Sequence[CFNResource],
    only_auto_applicable: bool = False,
) -> PatchApplicationResult:
    """Write patches to disk, coalescing every patch for a file into one edit.

    Shares `_patched_content()` with `generate_file_patches()`, so what we write
    to disk is byte-for-byte what the emitted patch set would have produced.
    """
    result = PatchApplicationResult()
    by_address = {r.address: r for r in resources}
    by_file = _group_by_file(patches, only_auto_applicable, result)

    for file, file_patches in by_file.items():
        abs_path = os.path.join(root, file)
        try:
            original, patched, _ = _patched_content(root, file, file_patches, by_address)
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


def write_patch_set(file_patches: Sequence[FilePatch], path: str) -> str:
    """Write one `git apply`-able patch file covering the whole template set."""
    with open(path, "w", encoding="utf-8") as fh:
        for fp in file_patches:
            fh.write(fp.diff)
    return path


def create_patch_branch(
    root: str,
    patches: Sequence[CFNPatch],
    resources: Sequence[CFNResource],
    branch_name: Optional[str] = None,
) -> BranchCreationResult:
    """Apply auto-applicable patches on a NEW branch, never on a dirty tree.

    SPEC 6.3 rails, in order and all of them:
      1. refuse on a dirty tree -- no --force, no exceptions
      2. always a new branch iac-security-scan/fix-<timestamp>, never main
      3. only autoApplicable changes
      4. never an access-affecting change (enforced by the never-list)
      5. one commit
      6. report what was skipped and why (via apply_patches_to_tree's result)
    """
    import time

    branch = branch_name or f"iac-security-scan/fix-{int(time.time())}"
    result = BranchCreationResult(branchName=branch)

    if _git(root, "rev-parse", "--is-inside-work-tree").returncode != 0:
        result.error = "Not a git repository"
        return result

    if _git(root, "status", "--porcelain").stdout.strip():
        result.error = (
            "Working tree has uncommitted changes. Commit or stash first "
            "(SPEC 6.3 rail 1 -- there is no --force)."
        )
        return result

    checkout = _git(root, "checkout", "-b", branch)
    if checkout.returncode != 0:
        result.error = f"Could not create branch {branch}: {checkout.stderr.strip()}"
        return result

    applied = apply_patches_to_tree(root, patches, resources, only_auto_applicable=True)
    if not applied.success or not applied.modifiedFiles:
        result.error = (
            "No auto-applicable patches to commit. " + "; ".join(applied.errors)
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
# Reporting
# ===========================================================================


def generate_patch_report(
    patches: Sequence[CFNPatch],
    file_patches: Optional[Sequence[FilePatch]] = None,
) -> str:
    """Markdown report -- per-finding diffs for READING, per-file diffs for APPLYING."""
    lines = ["# CloudFormation Security Patch Report", "", f"Total patches: {len(patches)}", ""]
    auto = sum(1 for p in patches if p.autoApplicable)
    lines += [
        "## Auto-applicable",
        "",
        f"{auto} of {len(patches)} patches are auto-applicable "
        f"(additive, single-property, semantically unambiguous).",
        f"{len(patches) - auto} are diff-only and require review.",
        "",
        "## Findings",
        "",
    ]
    for patch in patches:
        lines += [
            f"### {patch.address}  ({patch.severity})",
            "",
            f"- File: `{patch.file}`",
            f"- Type: `{patch.resourceType}`",
            f"- Rules: {', '.join(patch.ruleIds)}",
            f"- Auto-applicable: {'yes' if patch.autoApplicable else 'no'}",
        ]
        if not patch.autoApplicable:
            lines.append(f"- Diff-only because: {patch.autoApplyBlockedBy}")
        lines += ["", "```diff", patch.diff.rstrip("\n"), "```", ""]

    if file_patches:
        lines += [
            "## Applying these fixes",
            "",
            "The per-finding diffs above are for READING. To apply, use the "
            "coherent per-file patch set below (`git apply`).",
            "",
        ]
        for fp in file_patches:
            lines += [
                f"### `{fp.file}`  ({fp.patchCount} resources, "
                f"{'auto-applicable' if fp.autoApplicable else 'review required'})",
                "",
                "```diff",
                fp.diff.rstrip("\n"),
                "```",
                "",
            ]

    return "\n".join(lines)


# ===========================================================================
# CLI
# ===========================================================================


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic CloudFormation security patches from Checkov findings."
    )
    parser.add_argument("template", help="CloudFormation template FILE to patch")
    parser.add_argument("--findings", help="Path to a run_checkov.py JSON payload (default: run it)")
    parser.add_argument("--json-only", action="store_true", help="Emit only JSON on stdout")
    parser.add_argument("--markdown", action="store_true", help="Emit the markdown patch report")
    parser.add_argument("--patch-set", metavar="FILE", help="Write the git apply-able patch set to FILE")
    parser.add_argument("--auto-only", action="store_true", help="Restrict the patch set to auto-applicable fixes")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.template):
        print(f"error: not a file: {args.template}", file=sys.stderr)
        return 2

    root = os.path.dirname(os.path.abspath(args.template))

    if args.findings:
        with open(args.findings, encoding="utf-8") as fh:
            payload = json.load(fh)
    else:
        import run_checkov

        payload = run_checkov.run_checkov(root, framework=("cloudformation", "secrets"))

    findings = payload.get("findings", [])

    try:
        catalog = CFNFixCatalog.load()
        resources, _ = load_cloudformation_resources(args.template)
        patches = generate_security_patches(args.template, findings, catalog, resources)
        file_patches = generate_file_patches(
            root, patches, resources, only_auto_applicable=args.auto_only
        )
    except Exception as exc:  # noqa: BLE001 -- scan error is exit 2 (SPEC 9.2)
        print(f"error: patch generation failed: {exc}", file=sys.stderr)
        return 2

    if args.patch_set:
        write_patch_set(file_patches, args.patch_set)
        print(f"wrote patch set: {args.patch_set}", file=sys.stderr)

    if args.markdown:
        print(generate_patch_report(patches, file_patches))
        return 0

    out = {
        "template": os.path.abspath(args.template),
        "catalogSize": len(catalog),
        "totalFindings": len(findings),
        "patches": [p.to_dict() for p in patches],
        "patchCount": len(patches),
        "autoApplicableCount": sum(1 for p in patches if p.autoApplicable),
        "filePatches": [fp.to_dict() for fp in file_patches],
        "rulesFixed": sorted({r for p in patches for r in p.ruleIds}),
    }
    json.dump(out, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
