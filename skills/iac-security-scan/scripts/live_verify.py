#!/usr/bin/env python3
"""
live_verify.py -- opt-in, READ-ONLY live verification of static findings.

WS-17 (SPEC Phase 4, ``--live``, SPEC §3.2). This is the single most scope-creep-
prone feature in the whole product, so the design is built around one sentence and
refuses to do anything else:

    Live mode is VERIFICATION-ONLY. It takes the static findings we already have,
    confirms-or-drops each against a live AWS account, and flags drift. It does
    NOT enumerate resources absent from IaC. That is CSPM/Prowler, a different
    product. We scan your IaC. (SPEC §14.7)

So this module has exactly one job: for each static finding we ALREADY produced,
make a read-only AWS call against the SPECIFIC resource that finding names and set
the finding's ``verification`` field. It never lists-and-scans, it never invents a
finding for a resource that is not already in the list, and it never issues a call
that could change anything.

The verification vocabulary (findings.py ``VERIFICATIONS``):

  * ``confirmed``   -- the resource exists live and the flagged misconfiguration is
                       real right now. Priority boost (+15, SPEC §5.4).
  * ``not-deployed``-- no matching live resource. Still reported (it is about to be
                       deployed) but demoted (-20, SPEC §5.4).
  * ``drifted``     -- the live resource exists but its security-relevant config
                       DIFFERS from the IaC finding (e.g. someone fixed it by hand
                       in the console; the next ``apply`` will re-break it). This is
                       the state SPEC §3.2 also calls "already-mitigated"; the code
                       vocabulary collapses both into ``drifted``.
  * ``static-only`` -- the default. ``--live`` was off, OR the finding could not be
                       mapped to a specific describable resource. NEVER a silent
                       "looks clean" -- an unmapped finding stays exactly as loud as
                       it was.

THE THREE NON-NEGOTIABLES, enforced by construction rather than by good intentions:

  1. READ-ONLY. Every AWS call goes through ``ReadOnlyCaller``, whose ``.call()``
     rejects any operation whose name does not match ``^(Describe|Get|List|Head)``
     BEFORE it ever reaches boto3. A verifier is handed only a ``ReadOnlyCaller``;
     there is no path from a verifier to a mutating verb. ``PutBucketAcl`` /
     ``DeleteBucket`` raise ``NonReadOnlyCallError`` at the boundary.

  2. NEVER ENUMERATE. Verifiers look up the SPECIFIC resource named in the finding
     (``GetBucketEncryption(Bucket=<name>)``, a targeted ``DescribeSecurityGroups``
     filter). No verifier does a bare list-all. A finding we cannot map to a named
     resource stays ``static-only`` -- we do not go fishing.

  3. NEVER ADD A FINDING. ``live_verify`` only annotates the findings it was given;
     the input finding id-set is asserted equal on the way out
     (``_assert_no_new_findings``). There is no code path that appends a finding for
     a resource discovered live. That assertion IS the anti-CSPM guarantee.

CREDENTIALS (SPEC §3.2 / §11): ambient only, via the boto3 default chain. Never
prompted, never written, never sent to a model. If there are no usable credentials
the run degrades LOUDLY -- ``liveVerifyDegraded: true`` with a reason and an enable
hint -- and every finding stays ``static-only``. A no-creds ``--live`` run must
NEVER look like a run where everything verified clean.

report.py rendering (NOT wired here -- WS-14 owns report.py): report.py already
reads ``finding["verification"]`` in ``derive_complexity``. When the verification
column is added, it should render the per-finding ``verification`` value with the
``liveVerification`` evidence blob as the tooltip/detail, and surface the top-level
``liveVerification`` summary + ``liveVerifyDegraded`` banner alongside the existing
degradation notice (SPEC §9.1).

TESTING NOTE (stated plainly, per the WS-17 brief): the verification LOGIC in this
module is tested end-to-end with an injected in-memory stub caller. The REAL boto3
path (``boto3_caller`` + the STS fail-closed probe) is exercised only for its
read-only enforcement and its no-creds degradation; it has NOT been run against a
real AWS account. No live verification is claimed that was not performed.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from findings import (  # noqa: E402
    UNMAPPED,
    VERIFICATIONS,
    is_quick_win,
    priority_score,
)

# ---------------------------------------------------------------------------
# Verification vocabulary (must stay a subset of findings.VERIFICATIONS)
# ---------------------------------------------------------------------------

STATIC_ONLY = "static-only"
CONFIRMED = "confirmed"
NOT_DEPLOYED = "not-deployed"
DRIFTED = "drifted"

# Fail fast if findings.py and this module ever disagree about the vocabulary.
assert {STATIC_ONLY, CONFIRMED, NOT_DEPLOYED, DRIFTED}.issubset(set(VERIFICATIONS)), (
    "live_verify verification states drifted from findings.VERIFICATIONS"
)


# ---------------------------------------------------------------------------
# Read-only enforcement -- the whole safety story, by construction
# ---------------------------------------------------------------------------

#: The ONLY verb prefixes an AWS call may start with. Anything else is a bug and is
#: refused before it can reach boto3. This is deliberately an allowlist (reject by
#: default), not a denylist -- a new mutating verb we never heard of is rejected
#: automatically, whereas a denylist would let it through.
READ_ONLY_VERB_RE = re.compile(r"^(Describe|Get|List|Head)[A-Z0-9]")


class NonReadOnlyCallError(RuntimeError):
    """A caller tried to issue a non-read-only AWS operation. This is a BUG, never a
    degradation -- it must surface loudly, never be swallowed and turned into a
    quiet ``static-only``. If this is ever raised in production, a mutating verb got
    within one function call of AWS and the allowlist stopped it."""


def assert_read_only(operation: str) -> None:
    """Reject any operation whose name is not an allowlisted read-only verb.

    ``operation`` is the AWS API operation name in PascalCase (``GetBucketEncryption``,
    ``DescribeSecurityGroups``). ``PutBucketAcl``, ``DeleteBucket``,
    ``UpdateFunctionConfiguration`` and friends do not match and are refused.
    """
    if not READ_ONLY_VERB_RE.match(operation or ""):
        raise NonReadOnlyCallError(
            "refused non-read-only AWS operation %r: live mode may ONLY issue "
            "Describe*/Get*/List*/Head* calls (SPEC §3.2/§11)." % operation
        )


# ---------------------------------------------------------------------------
# Errors surfaced to verifiers (shared by the real boto3 path and the stub)
# ---------------------------------------------------------------------------


class AwsCallError(RuntimeError):
    """A read-only AWS call failed for a reason other than 'resource not found'.

    Carries the AWS error ``code`` so a verifier can distinguish, e.g.,
    'the bucket exists but has no encryption config'
    (``ServerSideEncryptionConfigurationNotFoundError`` -> the misconfig is real)
    from a transient/permission failure (-> we could not verify -> ``static-only``).
    """

    def __init__(self, service: str, operation: str, code: str, message: str = ""):
        super().__init__("%s.%s failed [%s]: %s" % (service, operation, code, message))
        self.service = service
        self.operation = operation
        self.code = code


class ResourceNotFoundError(AwsCallError):
    """The specific resource the finding names does not exist in the account.

    This is the ``not-deployed`` signal. It is a distinct subclass so verifiers can
    let it propagate to the wrapper (which maps it to ``not-deployed`` uniformly)
    without having to enumerate every service's not-found error code themselves.
    """


#: AWS error codes that mean "the named resource does not exist" -> ``not-deployed``.
#: NOT included here (on purpose): the "resource exists but this sub-config is
#: absent" codes like ``ServerSideEncryptionConfigurationNotFoundError`` and
#: ``NoSuchPublicAccessBlockConfiguration`` -- those mean the FLAGGED misconfig is
#: real and are handled by the individual verifiers as ``confirmed``.
NOT_FOUND_CODES = frozenset(
    {
        "NoSuchBucket",
        "NoSuchEntity",
        "ResourceNotFoundException",
        "NotFoundException",
        "NoSuchResource",
        "404",
        "InvalidGroup.NotFound",
        "InvalidGroupId.NotFound",
        "InvalidVpcID.NotFound",
        "InvalidInstanceID.NotFound",
        "InvalidSubnetID.NotFound",
        "DBInstanceNotFound",
        "InvalidKeyId.NotFound",
        "AccessPointNotFound",
    }
)


# ---------------------------------------------------------------------------
# The injectable seam -- like WS-6's ModelFn / WS-16's CodexFn
# ---------------------------------------------------------------------------

#: A raw AWS caller: (service, operation-PascalCase, params) -> response dict. It
#: may raise ``ResourceNotFoundError`` / ``AwsCallError``. This is the seam: the
#: real one is ``boto3_caller``; tests inject an in-memory stub, so all the
#: verification LOGIC is tested without any AWS account or even boto3.
AwsCallFn = Callable[[str, str, Dict[str, Any]], Dict[str, Any]]


class ReadOnlyCaller:
    """The ONLY interface a verifier is ever given to reach AWS.

    Every call passes ``assert_read_only`` *before* the underlying ``AwsCallFn`` is
    touched. That is what makes a mutating call impossible by construction rather
    than by convention: a verifier holding a ``ReadOnlyCaller`` literally cannot
    express ``PutBucketAcl`` -- the boundary refuses it here, above the stub and
    above boto3 alike.
    """

    def __init__(self, fn: AwsCallFn):
        self._fn = fn

    def call(self, service: str, operation: str, **params: Any) -> Dict[str, Any]:
        assert_read_only(operation)
        return self._fn(service, operation, params)


def _pascal_to_snake(name: str) -> str:
    """``GetBucketEncryption`` -> ``get_bucket_encryption`` (the boto3 method name)."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def boto3_caller(
    session_factory: Optional[Callable[[], Any]] = None,
    *,
    region: Optional[str] = None,
) -> AwsCallFn:
    """The real read-only caller, backed by boto3's default credential chain.

    NOT unit-tested against a live account (no creds in CI). It is structured so the
    read-only guarantee holds even here: ``assert_read_only`` runs again inside this
    function (defense in depth), so even a direct call bypassing ``ReadOnlyCaller``
    still cannot issue a mutating verb. botocore ``ClientError``s are normalized to
    our ``ResourceNotFoundError`` / ``AwsCallError`` so verifiers are provider-
    agnostic.
    """
    import boto3  # imported lazily so the module loads without boto3 installed
    from botocore.exceptions import BotoCoreError, ClientError

    session = (session_factory or boto3.Session)()
    clients: Dict[str, Any] = {}

    def _fn(service: str, operation: str, params: Dict[str, Any]) -> Dict[str, Any]:
        assert_read_only(operation)  # defense in depth -- never trust the caller
        client = clients.get(service)
        if client is None:
            client = session.client(service, region_name=region)
            clients[service] = client
        method_name = _pascal_to_snake(operation)
        method = getattr(client, method_name, None)
        if method is None or not callable(method):
            raise AwsCallError(service, operation, "UnknownOperation", "no boto3 method %s" % method_name)
        try:
            return method(**(params or {}))
        except ClientError as exc:  # noqa: PERF203
            code = (exc.response or {}).get("Error", {}).get("Code", "") or ""
            if code in NOT_FOUND_CODES:
                raise ResourceNotFoundError(service, operation, code, str(exc)[:300])
            raise AwsCallError(service, operation, code or "ClientError", str(exc)[:300])
        except BotoCoreError as exc:
            raise AwsCallError(service, operation, "BotoCoreError", str(exc)[:300])

    return _fn


# ---------------------------------------------------------------------------
# Resolving the SPECIFIC resource a finding names (never enumerate)
# ---------------------------------------------------------------------------


class PhysicalId:
    """The concrete AWS identifier a verifier will look up, plus whether we had to
    derive it heuristically (which the evidence records honestly)."""

    __slots__ = ("value", "derived")

    def __init__(self, value: str, derived: bool):
        self.value = value
        self.derived = derived


def _physical_id(finding: Dict[str, Any]) -> Optional[PhysicalId]:
    """Extract the physical resource identifier this finding is about, or ``None``.

    Order of trust:
      1. ``finding["physicalId"]`` -- an explicit id resolved by the pipeline.
      2. ``finding["location"]["physicalId"]`` -- same, nested.
      3. ``finding["resource"]["attributes"][<name-attr>]`` -- a LITERAL name in the
         parsed IaC (e.g. ``bucket = "acme-data-lake"``). Only used when it is a
         plain string (an unresolved ``${var.x}`` interpolation is not a real name).
      4. Fallback: the Terraform resource label (``aws_s3_bucket.data`` -> ``data``),
         flagged ``derived=True`` because a TF label is not guaranteed to equal the
         deployed physical name.

    Returns ``None`` when there is nothing usable -> the finding stays
    ``static-only``. We do NOT go looking; an unmappable finding is left alone.
    """
    explicit = finding.get("physicalId")
    if isinstance(explicit, str) and explicit.strip():
        return PhysicalId(explicit.strip(), derived=False)

    location = finding.get("location") or {}
    nested = location.get("physicalId")
    if isinstance(nested, str) and nested.strip():
        return PhysicalId(nested.strip(), derived=False)

    resource = finding.get("resource") or {}
    attrs = resource.get("attributes") or {}
    name_attr = _NAME_ATTRIBUTE.get(location.get("resourceType") or "")
    if name_attr:
        literal = attrs.get(name_attr)
        if isinstance(literal, str) and literal.strip() and "${" not in literal:
            return PhysicalId(literal.strip(), derived=False)

    address = location.get("resourceAddress") or ""
    if "." in address:
        label = address.split(".", 1)[1].strip()
        if label:
            return PhysicalId(label, derived=True)
    return None


#: The attribute that carries a resource's physical name, per resource type. Used
#: only to pull a LITERAL name out of parsed IaC when the pipeline provides it.
_NAME_ATTRIBUTE = {
    "aws_s3_bucket": "bucket",
    "aws_security_group": "name",
}


# ---------------------------------------------------------------------------
# Verifiers -- one per rule concept we know how to check read-only
#
# Each verifier is (finding, caller, physical_id) -> (verification, evidence).
# It may:
#   * return CONFIRMED / DRIFTED with evidence,
#   * let ResourceNotFoundError propagate (wrapper -> NOT_DEPLOYED),
#   * let an unexpected AwsCallError propagate (wrapper -> STATIC_ONLY + note).
# A rule with no verifier here -> the finding stays STATIC_ONLY. We only ever claim
# a verdict for a condition we can actually read back from the API.
# ---------------------------------------------------------------------------

Verifier = Callable[[Dict[str, Any], ReadOnlyCaller, str], Tuple[str, Dict[str, Any]]]


def _verify_s3_encryption(finding: Dict[str, Any], caller: ReadOnlyCaller, bucket: str) -> Tuple[str, Dict[str, Any]]:
    """Finding: 'S3 bucket is not encrypted at rest.' Check live SSE config."""
    try:
        resp = caller.call("s3", "GetBucketEncryption", Bucket=bucket)
    except AwsCallError as exc:
        if isinstance(exc, ResourceNotFoundError):
            raise
        if exc.code in ("ServerSideEncryptionConfigurationNotFoundError",):
            # Bucket exists, but has no SSE config -> the flagged misconfig is real.
            return CONFIRMED, {"check": "s3:GetBucketEncryption", "detail": "no server-side encryption configured on the live bucket"}
        raise
    rules = (resp.get("ServerSideEncryptionConfiguration") or {}).get("Rules") or []
    if rules:
        # Live bucket IS encrypted though the IaC finding says it is not -> drift.
        return DRIFTED, {"check": "s3:GetBucketEncryption", "detail": "live bucket is encrypted; IaC finding says it is not (fixed out-of-band)", "liveRules": rules}
    return CONFIRMED, {"check": "s3:GetBucketEncryption", "detail": "no encryption rules on the live bucket"}


def _verify_s3_logging(finding: Dict[str, Any], caller: ReadOnlyCaller, bucket: str) -> Tuple[str, Dict[str, Any]]:
    """Finding: 'S3 bucket has no access logging.' Check live logging config."""
    resp = caller.call("s3", "GetBucketLogging", Bucket=bucket)
    if resp.get("LoggingEnabled"):
        return DRIFTED, {"check": "s3:GetBucketLogging", "detail": "live bucket has access logging enabled; IaC finding says it does not"}
    return CONFIRMED, {"check": "s3:GetBucketLogging", "detail": "no access logging on the live bucket"}


def _verify_s3_versioning(finding: Dict[str, Any], caller: ReadOnlyCaller, bucket: str) -> Tuple[str, Dict[str, Any]]:
    """Finding: 'S3 bucket versioning is not enabled.' Check live versioning."""
    resp = caller.call("s3", "GetBucketVersioning", Bucket=bucket)
    if (resp.get("Status") or "").lower() == "enabled":
        return DRIFTED, {"check": "s3:GetBucketVersioning", "detail": "live bucket has versioning enabled; IaC finding says it does not"}
    return CONFIRMED, {"check": "s3:GetBucketVersioning", "detail": "versioning is %s on the live bucket" % (resp.get("Status") or "not set")}


def _verify_s3_public_access_block(finding: Dict[str, Any], caller: ReadOnlyCaller, bucket: str) -> Tuple[str, Dict[str, Any]]:
    """Finding: 'S3 bucket public access is not fully blocked.' Check live PAB."""
    try:
        resp = caller.call("s3", "GetPublicAccessBlock", Bucket=bucket)
    except AwsCallError as exc:
        if isinstance(exc, ResourceNotFoundError):
            raise
        if exc.code in ("NoSuchPublicAccessBlockConfiguration",):
            return CONFIRMED, {"check": "s3:GetPublicAccessBlock", "detail": "no public-access-block configuration on the live bucket"}
        raise
    cfg = resp.get("PublicAccessBlockConfiguration") or {}
    flags = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    if all(cfg.get(flag) is True for flag in flags):
        return DRIFTED, {"check": "s3:GetPublicAccessBlock", "detail": "live bucket blocks all public access; IaC finding says it does not", "liveConfig": cfg}
    return CONFIRMED, {"check": "s3:GetPublicAccessBlock", "detail": "public access is not fully blocked on the live bucket", "liveConfig": cfg}


_OPEN_CIDRS = ("0.0.0.0/0", "::/0")


def _verify_sg_open_ingress(finding: Dict[str, Any], caller: ReadOnlyCaller, group_name: str) -> Tuple[str, Dict[str, Any]]:
    """Finding: 'Security group allows ingress from 0.0.0.0/0.'

    Targeted lookup by group-name filter -- NOT a bare DescribeSecurityGroups. If no
    group matches the name, the resource is not deployed. If it matches, check its
    live ingress rules for an open CIDR.
    """
    resp = caller.call(
        "ec2",
        "DescribeSecurityGroups",
        Filters=[{"Name": "group-name", "Values": [group_name]}],
    )
    groups = resp.get("SecurityGroups") or []
    if not groups:
        raise ResourceNotFoundError("ec2", "DescribeSecurityGroups", "InvalidGroup.NotFound", "no security group named %r" % group_name)
    open_rules = []
    for group in groups:
        for perm in group.get("IpPermissions") or []:
            for rng in perm.get("IpRanges") or []:
                if rng.get("CidrIp") in _OPEN_CIDRS:
                    open_rules.append({"from": perm.get("FromPort"), "to": perm.get("ToPort"), "cidr": rng.get("CidrIp")})
            for rng in perm.get("Ipv6Ranges") or []:
                if rng.get("CidrIpv6") in _OPEN_CIDRS:
                    open_rules.append({"from": perm.get("FromPort"), "to": perm.get("ToPort"), "cidr": rng.get("CidrIpv6")})
    if open_rules:
        return CONFIRMED, {"check": "ec2:DescribeSecurityGroups", "detail": "live security group has open ingress", "openIngress": open_rules}
    return DRIFTED, {"check": "ec2:DescribeSecurityGroups", "detail": "live security group has no open ingress; IaC finding says it does (fixed out-of-band)"}


#: rule id -> verifier. Only rules we can actually read back appear here. Everything
#: else stays ``static-only`` -- honest silence over a guess. Several Checkov rule
#: ids map to the same physical check (Checkov splits one concept across several
#: ids), which is why the map has repeats pointing at one verifier.
VERIFIERS: Dict[str, Verifier] = {
    # S3 server-side encryption
    "CKV_AWS_16": _verify_s3_encryption,
    "CKV_AWS_145": _verify_s3_encryption,
    "CKV2_AWS_67": _verify_s3_encryption,
    "CKV2_AWS_6": _verify_s3_public_access_block,
    # S3 access logging
    "CKV_AWS_18": _verify_s3_logging,
    # S3 versioning
    "CKV_AWS_21": _verify_s3_versioning,
    # S3 public access block
    "CKV_AWS_53": _verify_s3_public_access_block,
    "CKV_AWS_54": _verify_s3_public_access_block,
    "CKV_AWS_55": _verify_s3_public_access_block,
    "CKV_AWS_56": _verify_s3_public_access_block,
    # Security group open ingress
    "CKV_AWS_24": _verify_sg_open_ingress,
    "CKV_AWS_25": _verify_sg_open_ingress,
    "CKV_AWS_260": _verify_sg_open_ingress,
}


# ---------------------------------------------------------------------------
# Per-finding verification -- annotate only, never invent
# ---------------------------------------------------------------------------


def _static_only(reason: str, **extra: Any) -> Dict[str, Any]:
    """Build the annotation for a finding we did NOT verify. Never reads as clean."""
    ev = {"status": STATIC_ONLY, "reason": reason}
    ev.update(extra)
    return {"verification": STATIC_ONLY, "liveVerification": ev}


def verify_finding(finding: Dict[str, Any], caller: ReadOnlyCaller) -> Dict[str, Any]:
    """Return the verification annotation for ONE finding (keys to merge onto it).

    This function NEVER creates or drops a finding; it only returns annotation keys.
    ``NonReadOnlyCallError`` is deliberately NOT caught -- it is a bug, and turning
    it into a quiet ``static-only`` would hide exactly the failure the allowlist
    exists to make loud.
    """
    rule_id = finding.get("ruleId") or ""
    verifier = VERIFIERS.get(rule_id)
    if verifier is None:
        rtype = (finding.get("location") or {}).get("resourceType") or "unknown"
        return _static_only(
            "no read-only live verifier for rule %s (%s); not verified against the "
            "account. Reported as static-only, not clean." % (rule_id, rtype)
        )

    physical = _physical_id(finding)
    if physical is None:
        return _static_only(
            "could not resolve a specific live resource identifier for %s; left "
            "static-only rather than enumerate the account." % rule_id
        )

    try:
        verification, evidence = verifier(finding, caller, physical.value)
    except ResourceNotFoundError as exc:
        verification, evidence = NOT_DEPLOYED, {"check": "%s:%s" % (exc.service, exc.operation), "detail": "no matching live resource (%s)" % exc.code}
    except NonReadOnlyCallError:
        raise  # a mutating verb got this far -- surface it, never swallow it
    except AwsCallError as exc:
        # A failed lookup is NOT a verification. We do not know the live state, so
        # the finding stays static-only with the error recorded -- never confirmed,
        # never silently dropped.
        return _static_only(
            "live lookup failed (%s); could not verify. Finding stands." % exc.code,
            error=str(exc)[:300],
            lookupIdentifier=physical.value,
        )

    evidence.setdefault("status", verification)
    evidence["lookupIdentifier"] = physical.value
    evidence["identifierDerived"] = physical.derived
    if physical.derived:
        evidence["identifierNote"] = (
            "identifier derived from the Terraform resource label, which may differ "
            "from the deployed physical name; verdict is best-effort."
        )
    return {"verification": verification, "liveVerification": evidence}


# ---------------------------------------------------------------------------
# Rescoring -- verification feeds priorityScore (SPEC §5.4), exactly as report.py
# ---------------------------------------------------------------------------


def _rescore(finding: Dict[str, Any]) -> None:
    """Recompute priorityScore/isQuickWin now that verification changed.

    SPEC §5.4 ties verification to score (+15 confirmed, -20 not-deployed). This
    mirrors report.py ``derive_complexity`` verbatim so a confirmed finding actually
    ranks up and a not-deployed one ranks down. An unmapped severity scores 0 in
    ``priority_score`` regardless, so this is safe for every finding.
    """
    severity = finding.get("severity") or UNMAPPED
    complexity = finding.get("remediationComplexity") or "moderate"
    finding["priorityScore"] = priority_score(
        severity,
        finding.get("exploitability") or "moderate",
        complexity,
        affects_critical_resource=bool(finding.get("affectsCriticalResource")),
        is_public_facing=bool(finding.get("isPublicFacing")),
        verification=finding.get("verification") or STATIC_ONLY,
        threat_score=finding.get("threatScore"),
    )
    finding["isQuickWin"] = is_quick_win(severity, complexity)


# ---------------------------------------------------------------------------
# The live-verify pass itself
# ---------------------------------------------------------------------------


def live_verify(
    payload: Dict[str, Any],
    caller: ReadOnlyCaller,
    *,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    on_log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Annotate ``payload['findings']`` with live verification. Returns a NEW payload.

    The input finding id-set is preserved EXACTLY -- asserted on the way out by
    ``_assert_no_new_findings``. That assertion is the anti-CSPM guarantee: this
    function physically cannot return a finding for a resource that was not already
    in the list, no matter what the account contains.
    """
    log = on_log or (lambda _m: None)
    result = copy.deepcopy(payload)
    findings: List[Dict[str, Any]] = result.get("findings") or []
    original_ids = [f.get("id") for f in findings]

    counts = {CONFIRMED: 0, NOT_DEPLOYED: 0, DRIFTED: 0, STATIC_ONLY: 0}
    for finding in findings:
        annotation = verify_finding(finding, caller)
        finding.update(annotation)
        verification = finding.get("verification") or STATIC_ONLY
        counts[verification] = counts.get(verification, 0) + 1
        # Stamp the account context onto findings we actually confirmed/drifted on
        # (the resource exists there). Not-deployed and static-only carry no ARN.
        if verification in (CONFIRMED, DRIFTED) and account_id:
            finding["accountId"] = account_id
            if region:
                finding["region"] = region
        _rescore(finding)
        if verification != STATIC_ONLY:
            log(
                "%s: %s on %s"
                % (
                    verification,
                    finding.get("ruleId"),
                    (finding.get("location") or {}).get("resourceAddress"),
                )
            )

    result["findings"] = findings
    _assert_no_new_findings(original_ids, findings)

    result["liveVerification"] = {
        "checked": len(findings),
        "confirmed": counts[CONFIRMED],
        "notDeployed": counts[NOT_DEPLOYED],
        "drifted": counts[DRIFTED],
        "staticOnly": counts[STATIC_ONLY],
        "accountId": account_id,
        "region": region,
        "note": (
            "Verification-only overlay: confirms/drops/flags-drift on the static "
            "findings. It does NOT enumerate resources absent from your IaC (SPEC §14.7)."
        ),
    }
    result["liveVerifyDegraded"] = False
    return result


def _assert_no_new_findings(original_ids: Sequence[Optional[str]], findings: Sequence[Dict[str, Any]]) -> None:
    """THE anti-CSPM guarantee, asserted rather than trusted.

    Live mode annotates; it never enumerates. The set of finding ids on the way out
    must be exactly the set on the way in -- nothing added (no CSPM discovery),
    nothing dropped (a live check can never delete a static finding). If a future
    refactor ever violates this, it raises here instead of silently shipping either
    a discovered-resource finding or a lost one.
    """
    before = list(original_ids)
    after = [f.get("id") for f in findings]
    added = set(after) - set(before)
    removed = set(before) - set(after)
    if added:
        raise AssertionError(
            "live verify ADDED finding(s) %s -- live mode may only annotate existing "
            "findings, never enumerate new resources (anti-CSPM, SPEC §14.7)." % sorted(added)
        )
    if removed:
        raise AssertionError(
            "live verify DROPPED finding(s) %s -- a live check may confirm/demote a "
            "finding, never delete it." % sorted(removed)
        )
    if len(after) != len(before):
        raise AssertionError("live verify changed the finding count (%d -> %d)" % (len(before), len(after)))


# ---------------------------------------------------------------------------
# Loud degradation -- no usable creds, fail closed (SPEC §3.2)
# ---------------------------------------------------------------------------

INSTALL_HINT = (
    "AWS SDK (boto3) not installed. Install it (`pip install boto3`) to enable "
    "--live verification."
)
NO_CREDS_HINT = (
    "No usable AWS credentials in the default chain. Authenticate first "
    "(`aws sso login`, set AWS_PROFILE, or an instance role) and re-run with --live. "
    "Live mode uses AMBIENT credentials only -- it never prompts for or stores keys."
)


def degraded_payload(
    payload: Dict[str, Any], reason: str, hint: str, on_log: Optional[Callable[[str], None]] = None
) -> Dict[str, Any]:
    """The loud-degradation result: every finding stays exactly static-only, plus a
    flag that CANNOT be mistaken for 'everything verified clean' and an enable hint.
    Same discipline as the Checkov-absent path.
    """
    log = on_log or (lambda _m: None)
    log("LIVE VERIFY DEGRADED: %s" % reason)
    log(hint)
    result = copy.deepcopy(payload)
    findings: List[Dict[str, Any]] = result.get("findings") or []
    for finding in findings:
        # Make the non-verification explicit on every finding, so nothing downstream
        # can read a missing field as "checked and clean".
        finding.setdefault("verification", STATIC_ONLY)
        finding["verification"] = STATIC_ONLY
    result["findings"] = findings
    result["liveVerifyDegraded"] = True
    result["liveVerifyDegradationReason"] = reason
    result["liveVerifyEnableHint"] = hint
    # Deliberately NO ``liveVerification`` summary block -- a degraded run produced
    # no verdicts and must never render as one where everything was confirmed clean.
    return result


def credentials_available(session_factory: Optional[Callable[[], Any]] = None) -> Dict[str, Any]:
    """Are ambient AWS credentials present? Returns ``{available, reason, hint}``.

    This only checks that the default chain RESOLVES a credential -- a live STS
    probe (does it actually work?) happens fail-closed in ``run_live_verify`` so an
    expired credential also degrades loudly rather than erroring per-finding.
    """
    try:
        import boto3  # noqa: F401
    except ImportError:
        return {"available": False, "reason": "boto3 not installed", "hint": INSTALL_HINT}
    try:
        import boto3

        session = (session_factory or boto3.Session)()
        creds = session.get_credentials()
    except Exception as exc:  # noqa: BLE001 -- any failure resolving creds -> degrade
        return {"available": False, "reason": "could not resolve AWS credentials: %s" % exc, "hint": NO_CREDS_HINT}
    if creds is None:
        return {"available": False, "reason": "no AWS credentials in the default chain", "hint": NO_CREDS_HINT}
    return {"available": True, "reason": None, "hint": None}


# ---------------------------------------------------------------------------
# Top-level entry
# ---------------------------------------------------------------------------


def run_live_verify(
    payload: Dict[str, Any],
    *,
    caller: Optional[Any] = None,
    session_factory: Optional[Callable[[], Any]] = None,
    region: Optional[str] = None,
    on_log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Top-level: check creds, degrade loudly if absent, else verify.

    If ``caller`` is injected (tests) we skip the availability probe and the STS
    fail-closed probe and use it directly -- that is the seam that makes the whole
    verification mechanism testable without boto3 or an AWS account. ``caller`` may
    be a ``ReadOnlyCaller`` or a bare ``AwsCallFn`` (it is wrapped so the read-only
    boundary always applies).
    """
    log = on_log or (lambda _m: None)

    if caller is not None:
        ro = caller if isinstance(caller, ReadOnlyCaller) else ReadOnlyCaller(caller)
        return live_verify(payload, ro, account_id=None, region=region, on_log=log)

    avail = credentials_available(session_factory)
    if not avail["available"]:
        return degraded_payload(payload, avail["reason"], avail["hint"], on_log=log)

    ro = ReadOnlyCaller(boto3_caller(session_factory, region=region))

    # Fail-closed identity probe: prove the credential actually works before we
    # trust any verdict. GetCallerIdentity is read-only (matches the allowlist). If
    # it fails -- expired token, no permission, no network -- degrade the WHOLE run
    # loudly rather than mark every finding static-only one failed call at a time.
    try:
        identity = ro.call("sts", "GetCallerIdentity")
    except Exception as exc:  # noqa: BLE001
        return degraded_payload(
            payload,
            "AWS credentials resolved but are not usable (%s)" % exc,
            NO_CREDS_HINT,
            on_log=log,
        )
    account_id = identity.get("Account")
    log("live verifying against account %s" % account_id)

    return live_verify(payload, ro, account_id=account_id, region=region, on_log=log)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="READ-ONLY live verification of static findings against a live "
        "AWS account (SPEC Phase 4 --live). Verification-only: confirms/drops/flags-"
        "drift; it does NOT enumerate resources absent from your IaC."
    )
    parser.add_argument("--findings", required=True, help="findings JSON (or {'findings':[...]})")
    parser.add_argument("--region", default=None, help="AWS region (default: the ambient/default region)")
    parser.add_argument("--out", default="-", help="Output path (default: stdout)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    with open(args.findings, encoding="utf-8") as fh:
        payload = json.load(fh)
    if isinstance(payload, list):
        payload = {"findings": payload}

    log = (lambda _m: None) if args.quiet else (lambda m: print("[live_verify] %s" % m, file=sys.stderr))

    result = run_live_verify(payload, region=args.region, on_log=log)

    text = json.dumps(result, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    # Exit non-zero on degradation so a --live run that could not verify is visible
    # to a CI caller, never mistaken for a clean pass.
    return 3 if result.get("liveVerifyDegraded") else 0


__all__ = [
    "STATIC_ONLY",
    "CONFIRMED",
    "NOT_DEPLOYED",
    "DRIFTED",
    "READ_ONLY_VERB_RE",
    "NonReadOnlyCallError",
    "assert_read_only",
    "AwsCallError",
    "ResourceNotFoundError",
    "NOT_FOUND_CODES",
    "AwsCallFn",
    "ReadOnlyCaller",
    "boto3_caller",
    "VERIFIERS",
    "verify_finding",
    "live_verify",
    "run_live_verify",
    "credentials_available",
    "degraded_payload",
]


if __name__ == "__main__":
    sys.exit(main())
