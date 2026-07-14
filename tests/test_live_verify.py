#!/usr/bin/env python3
"""
Tests for live_verify.py (WS-17, --live read-only verification).

The whole point of the injectable ``AwsCallFn`` seam is that these tests exercise
the real verification LOGIC end-to-end with an in-memory stub -- no boto3, no AWS
account. The stub records every (service, operation, params) tuple it is asked for,
which lets us assert BOTH the verdict logic AND that only read-only, targeted calls
are ever issued.

The real boto3 path is NOT exercised against a live account here (there are no
credentials in CI). It is covered only for (a) read-only enforcement and (b) the
no-creds loud-degradation path.
"""

import os
import sys

import pytest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "skills", "iac-security-scan", "scripts")
)

import live_verify as lv  # noqa: E402
from findings import VERIFICATIONS  # noqa: E402


# ---------------------------------------------------------------------------
# In-memory stub caller -- the seam under test
# ---------------------------------------------------------------------------


class StubAws:
    """A hand-built read-only AWS stub.

    Keyed by (service, operation) -> either a response dict, or a callable
    ``(params) -> response`` (so a verifier's targeting params can be inspected), or
    an exception instance to raise (to simulate not-found / not-configured).

    It RECORDS every call, so a test can prove the verifier issued a targeted,
    read-only lookup and nothing else.
    """

    def __init__(self, responses):
        self._responses = responses
        self.calls = []  # list of (service, operation, params)

    def __call__(self, service, operation, params):
        self.calls.append((service, operation, params))
        key = (service, operation)
        if key not in self._responses:
            raise lv.AwsCallError(service, operation, "StubMiss", "no stubbed response for %s" % (key,))
        result = self._responses[key]
        if isinstance(result, BaseException):
            raise result
        if callable(result):
            return result(params)
        return result

    def operations(self):
        return [op for (_svc, op, _p) in self.calls]


def _finding(rule_id="CKV_AWS_18", resource_type="aws_s3_bucket", address=None, **extra):
    address = address or "%s.data" % resource_type
    f = {
        "id": "finding-%s-%s" % (rule_id, address),
        "ruleId": rule_id,
        "title": "test finding",
        "severity": "high",
        "exploitability": "moderate",
        "remediationComplexity": "moderate",
        "verification": "static-only",
        "priorityScore": 0,
        "location": {
            "file": "s3.tf",
            "startLine": 1,
            "endLine": 5,
            "resourceAddress": address,
            "resourceType": resource_type,
            "service": resource_type.split("_")[1],
        },
    }
    f.update(extra)
    return f


def _run(findings, responses):
    stub = StubAws(responses)
    result = lv.run_live_verify({"findings": findings}, caller=stub)
    return result, stub


# ===========================================================================
# Acceptance #1 -- confirmed / not-deployed / drift via read-only stub calls
# ===========================================================================


def test_confirmed_when_misconfig_present_live():
    """S3 logging finding + a live bucket with no logging -> confirmed."""
    findings = [_finding("CKV_AWS_18", physicalId="my-bucket")]
    responses = {("s3", "GetBucketLogging"): {}}  # no LoggingEnabled -> misconfig real
    result, stub = _run(findings, responses)

    f = result["findings"][0]
    assert f["verification"] == lv.CONFIRMED
    assert f["liveVerification"]["check"] == "s3:GetBucketLogging"
    assert stub.operations() == ["GetBucketLogging"]


def test_not_deployed_when_resource_absent():
    """S3 encryption finding + no such bucket -> not-deployed."""
    findings = [_finding("CKV_AWS_16", physicalId="ghost-bucket")]
    responses = {
        ("s3", "GetBucketEncryption"): lv.ResourceNotFoundError(
            "s3", "GetBucketEncryption", "NoSuchBucket", "the bucket does not exist"
        )
    }
    result, _ = _run(findings, responses)

    f = result["findings"][0]
    assert f["verification"] == lv.NOT_DEPLOYED
    assert "no matching live resource" in f["liveVerification"]["detail"]


def test_drift_when_live_differs_from_iac():
    """S3 encryption finding, but the live bucket IS encrypted -> drift."""
    findings = [_finding("CKV_AWS_16", physicalId="fixed-bucket")]
    responses = {
        ("s3", "GetBucketEncryption"): {
            "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}
        }
    }
    result, _ = _run(findings, responses)

    f = result["findings"][0]
    assert f["verification"] == lv.DRIFTED
    assert "fixed out-of-band" in f["liveVerification"]["detail"]


def test_confirmed_s3_encryption_exists_but_unconfigured():
    """Bucket exists but has NO encryption config (its own error code) -> confirmed."""
    findings = [_finding("CKV_AWS_16", physicalId="plain-bucket")]
    responses = {
        ("s3", "GetBucketEncryption"): lv.AwsCallError(
            "s3", "GetBucketEncryption", "ServerSideEncryptionConfigurationNotFoundError", "not configured"
        )
    }
    result, _ = _run(findings, responses)
    assert result["findings"][0]["verification"] == lv.CONFIRMED


def test_s3_public_access_block_confirmed_and_drift():
    """No PAB config -> confirmed; all-flags-true PAB -> drift."""
    absent = [_finding("CKV_AWS_53", address="aws_s3_bucket.open", physicalId="open-bucket")]
    r_absent, _ = _run(
        absent,
        {("s3", "GetPublicAccessBlock"): lv.AwsCallError("s3", "GetPublicAccessBlock", "NoSuchPublicAccessBlockConfiguration", "")},
    )
    assert r_absent["findings"][0]["verification"] == lv.CONFIRMED

    blocked = [_finding("CKV_AWS_53", address="aws_s3_bucket.locked", physicalId="locked-bucket")]
    r_blocked, _ = _run(
        blocked,
        {
            ("s3", "GetPublicAccessBlock"): {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        },
    )
    assert r_blocked["findings"][0]["verification"] == lv.DRIFTED


def test_s3_versioning_confirmed_and_drift():
    conf = [_finding("CKV_AWS_21", physicalId="unversioned")]
    r1, _ = _run(conf, {("s3", "GetBucketVersioning"): {}})
    assert r1["findings"][0]["verification"] == lv.CONFIRMED

    drift = [_finding("CKV_AWS_21", physicalId="versioned")]
    r2, _ = _run(drift, {("s3", "GetBucketVersioning"): {"Status": "Enabled"}})
    assert r2["findings"][0]["verification"] == lv.DRIFTED


def test_security_group_open_ingress_confirmed():
    """SG finding + live SG with 0.0.0.0/0 ingress -> confirmed, via a TARGETED filter."""
    findings = [_finding("CKV_AWS_24", resource_type="aws_security_group", address="aws_security_group.web", physicalId="web-sg")]

    def _describe(params):
        # Prove the lookup is targeted: it MUST pass a group-name filter, never a
        # bare list-all.
        assert params.get("Filters") == [{"Name": "group-name", "Values": ["web-sg"]}]
        return {"SecurityGroups": [{"IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}

    result, stub = _run(findings, {("ec2", "DescribeSecurityGroups"): _describe})
    f = result["findings"][0]
    assert f["verification"] == lv.CONFIRMED
    assert f["liveVerification"]["openIngress"][0]["cidr"] == "0.0.0.0/0"
    assert stub.operations() == ["DescribeSecurityGroups"]


def test_security_group_no_match_is_not_deployed():
    findings = [_finding("CKV_AWS_24", resource_type="aws_security_group", address="aws_security_group.web", physicalId="web-sg")]
    result, _ = _run(findings, {("ec2", "DescribeSecurityGroups"): {"SecurityGroups": []}})
    assert result["findings"][0]["verification"] == lv.NOT_DEPLOYED


def test_security_group_closed_ingress_is_drift():
    findings = [_finding("CKV_AWS_24", resource_type="aws_security_group", address="aws_security_group.web", physicalId="web-sg")]
    result, _ = _run(
        findings,
        {("ec2", "DescribeSecurityGroups"): {"SecurityGroups": [{"IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]}},
    )
    assert result["findings"][0]["verification"] == lv.DRIFTED


# ===========================================================================
# Acceptance #2 -- a mutating verb is impossible BY CONSTRUCTION
# ===========================================================================


@pytest.mark.parametrize(
    "operation",
    [
        "PutBucketAcl",
        "DeleteBucket",
        "PutBucketEncryption",
        "DeleteSecurityGroup",
        "AuthorizeSecurityGroupIngress",
        "UpdateFunctionConfiguration",
        "CreateBucket",
        "ModifyInstanceAttribute",
        "TerminateInstances",
        "PutObject",
        "RevokeSecurityGroupIngress",
        "SetBucketPolicy",
    ],
)
def test_readonly_caller_rejects_mutating_verbs(operation):
    """The read-only boundary refuses anything not Describe*/Get*/List*/Head*.

    This is the test that FAILS if any code path could ever issue a mutating call:
    the ReadOnlyCaller is the ONLY interface a verifier gets, and it rejects here
    before the underlying fn (stub or boto3) is ever touched.
    """
    reached = []
    caller = lv.ReadOnlyCaller(lambda s, o, p: reached.append((s, o)) or {})
    with pytest.raises(lv.NonReadOnlyCallError):
        caller.call("s3", operation, Bucket="x")
    assert reached == [], "the mutating call reached the underlying fn -- boundary failed"


def test_assert_read_only_helper_rejects_and_accepts():
    for good in ("DescribeSecurityGroups", "GetBucketEncryption", "ListBuckets", "HeadObject"):
        lv.assert_read_only(good)  # must not raise
    for bad in ("PutBucketAcl", "DeleteBucket", "Describe", "Getty", "", "getBucketEncryption"):
        with pytest.raises(lv.NonReadOnlyCallError):
            lv.assert_read_only(bad)


def test_readonly_regex_is_an_allowlist_not_denylist():
    """A never-before-seen mutating verb must be rejected by default."""
    with pytest.raises(lv.NonReadOnlyCallError):
        lv.assert_read_only("FrobnicateEverything")


def test_boto3_caller_enforces_readonly_before_touching_boto3():
    """Even bypassing ReadOnlyCaller, the real caller refuses a mutating verb.

    We build the real caller with a session factory that would EXPLODE if it were
    ever asked to make a client -- proving the refusal happens before any boto3
    contact.
    """

    class Boom:
        def client(self, *a, **k):  # pragma: no cover - must never be reached
            raise AssertionError("boto3 client should never be constructed for a mutating verb")

    fn = lv.boto3_caller(session_factory=lambda: Boom())
    with pytest.raises(lv.NonReadOnlyCallError):
        fn("s3", "DeleteBucket", {"Bucket": "x"})


def test_no_verifier_ever_maps_to_a_mutating_operation():
    """Belt-and-braces: run every verifier against a stub that fails LOUDLY if it is
    asked for a non-read-only op, and confirm none of them try one."""

    def guard(service, operation, params):
        lv.assert_read_only(operation)  # raises if a verifier asked for a mutating verb
        # Return something benign so the verifier completes; we only care that the
        # operation it asked for was read-only.
        raise lv.ResourceNotFoundError(service, operation, "NoSuchBucket", "stub")

    caller = lv.ReadOnlyCaller(guard)
    for rule_id, verifier in lv.VERIFIERS.items():
        finding = _finding(rule_id, physicalId="probe")
        # security-group verifier needs the sg resource type for identifier derivation,
        # but physicalId is explicit here so any type works.
        try:
            verifier(finding, caller, "probe")
        except lv.NonReadOnlyCallError:  # pragma: no cover
            pytest.fail("verifier for %s issued a non-read-only operation" % rule_id)
        except lv.AwsCallError:
            pass  # expected -- the guard raises not-found; that is fine


# ===========================================================================
# Acceptance #3 -- no creds degrades LOUDLY; every finding stays static-only
# ===========================================================================


def test_no_credentials_degrades_loudly():
    """A None from the default chain -> degraded, loud, every finding static-only."""
    findings = [_finding("CKV_AWS_18"), _finding("CKV_AWS_16", address="aws_s3_bucket.other")]

    class NoCredsSession:
        def get_credentials(self):
            return None

    logs = []
    result = lv.run_live_verify(
        {"findings": findings},
        session_factory=lambda: NoCredsSession(),
        on_log=logs.append,
    )

    assert result["liveVerifyDegraded"] is True
    assert result.get("liveVerifyDegradationReason")
    assert result.get("liveVerifyEnableHint")
    # No summary block that could read as "verified clean".
    assert "liveVerification" not in result
    # EVERY finding stays static-only.
    for f in result["findings"]:
        assert f["verification"] == "static-only"
    # It was loud.
    assert any("DEGRADED" in m for m in logs)


def test_degraded_run_does_not_look_like_clean_verification():
    """The load-bearing distinction: a no-creds run must not look like a run where
    everything verified confirmed/clean."""
    findings = [_finding("CKV_AWS_18")]

    class NoCredsSession:
        def get_credentials(self):
            return None

    result = lv.run_live_verify({"findings": findings}, session_factory=lambda: NoCredsSession())
    # There is no confirmed/drifted verdict anywhere, and the degraded flag is set.
    assert result["liveVerifyDegraded"] is True
    assert all(f["verification"] == "static-only" for f in result["findings"])


def test_credentials_available_reports_missing():
    class NoCredsSession:
        def get_credentials(self):
            return None

    out = lv.credentials_available(session_factory=lambda: NoCredsSession())
    assert out["available"] is False
    assert out["hint"]


def test_credentials_available_reports_present():
    class OkSession:
        def get_credentials(self):
            return object()  # any non-None credential

    out = lv.credentials_available(session_factory=lambda: OkSession())
    assert out["available"] is True


def test_expired_credentials_fail_closed_via_sts_probe():
    """Creds resolve but STS GetCallerIdentity fails -> whole run degrades loudly,
    not one static-only finding at a time."""
    findings = [_finding("CKV_AWS_18", physicalId="b")]

    class OkSession:
        def get_credentials(self):
            return object()

        def client(self, service, region_name=None):
            raise RuntimeError("should not build clients; boto3 path is stubbed via monkeypatch")

    # Patch boto3_caller so the STS probe raises (simulating an expired token) while
    # the availability check passes.
    def exploding_caller(session_factory=None, region=None):
        def _fn(service, operation, params):
            lv.assert_read_only(operation)
            raise lv.AwsCallError(service, operation, "ExpiredToken", "token expired")

        return _fn

    orig = lv.boto3_caller
    lv.boto3_caller = exploding_caller
    try:
        result = lv.run_live_verify({"findings": findings}, session_factory=lambda: OkSession())
    finally:
        lv.boto3_caller = orig

    assert result["liveVerifyDegraded"] is True
    assert all(f["verification"] == "static-only" for f in result["findings"])


# ===========================================================================
# Acceptance #4 -- the anti-CSPM guarantee: NEVER add a finding
# ===========================================================================


def test_live_mode_never_adds_a_finding():
    """The core anti-CSPM property: verification annotates the existing list; it
    never returns a finding for a resource not already present."""
    findings = [
        _finding("CKV_AWS_18", address="aws_s3_bucket.a", physicalId="a"),
        _finding("CKV_AWS_16", address="aws_s3_bucket.b", physicalId="b"),
    ]
    responses = {
        ("s3", "GetBucketLogging"): {},
        ("s3", "GetBucketEncryption"): lv.ResourceNotFoundError("s3", "GetBucketEncryption", "NoSuchBucket", ""),
    }
    result, _ = _run(findings, responses)
    before = {f["id"] for f in findings}
    after = {f["id"] for f in result["findings"]}
    assert after == before
    assert len(result["findings"]) == len(findings)


def test_assert_no_new_findings_raises_on_addition():
    with pytest.raises(AssertionError):
        lv._assert_no_new_findings(["a", "b"], [{"id": "a"}, {"id": "b"}, {"id": "c"}])


def test_assert_no_new_findings_raises_on_removal():
    with pytest.raises(AssertionError):
        lv._assert_no_new_findings(["a", "b"], [{"id": "a"}])


def test_assert_no_new_findings_passes_when_identical():
    lv._assert_no_new_findings(["a", "b"], [{"id": "a"}, {"id": "b"}])  # must not raise


def test_verifiers_never_enumerate_the_account():
    """No verifier issues a bare list-all. Every AWS call recorded carries a
    targeting parameter (a specific Bucket, or a group-name Filter)."""
    findings = [
        _finding("CKV_AWS_18", address="aws_s3_bucket.a", physicalId="a"),
        _finding("CKV_AWS_24", resource_type="aws_security_group", address="aws_security_group.g", physicalId="g"),
    ]
    responses = {
        ("s3", "GetBucketLogging"): {},
        ("ec2", "DescribeSecurityGroups"): {"SecurityGroups": []},
    }
    _, stub = _run(findings, responses)
    for service, operation, params in stub.calls:
        # Every call is targeted: it names a specific resource, never a blanket scan.
        assert params, "%s.%s issued with no targeting params (enumerate risk)" % (service, operation)
        assert ("Bucket" in params) or ("Filters" in params) or ("GroupIds" in params)


# ===========================================================================
# Unmappable / static-only behaviour
# ===========================================================================


def test_unknown_rule_stays_static_only():
    """A finding whose rule we cannot verify stays static-only -- not 'clean'."""
    findings = [_finding("CKV_AWS_99999", physicalId="whatever")]
    result, stub = _run(findings, {})
    f = result["findings"][0]
    assert f["verification"] == "static-only"
    assert "no read-only live verifier" in f["liveVerification"]["reason"]
    assert stub.calls == [], "an unverifiable finding must issue no AWS calls"


def test_unresolvable_identifier_stays_static_only():
    """No physical id resolvable -> static-only, and NO account call made."""
    finding = _finding("CKV_AWS_18")
    finding["location"]["resourceAddress"] = "aws_s3_bucket"  # no label after a dot
    result, stub = _run([finding], {})
    f = result["findings"][0]
    assert f["verification"] == "static-only"
    assert stub.calls == []


def test_derived_identifier_is_flagged_honestly():
    """When we fall back to the TF label as the physical name, say so."""
    findings = [_finding("CKV_AWS_18", address="aws_s3_bucket.data")]  # no physicalId -> derived
    responses = {("s3", "GetBucketLogging"): {}}
    result, _ = _run(findings, responses)
    ev = result["findings"][0]["liveVerification"]
    assert ev["identifierDerived"] is True
    assert ev["lookupIdentifier"] == "data"
    assert "identifierNote" in ev


def test_literal_bucket_attribute_is_used_over_label():
    """A literal ``bucket = "real-name"`` in parsed IaC beats the TF label."""
    findings = [
        _finding(
            "CKV_AWS_18",
            address="aws_s3_bucket.data",
            resource={"attributes": {"bucket": "real-name"}},
        )
    ]
    result, stub = _run(findings, {("s3", "GetBucketLogging"): {}})
    assert result["findings"][0]["liveVerification"]["lookupIdentifier"] == "real-name"
    assert result["findings"][0]["liveVerification"]["identifierDerived"] is False


def test_interpolated_attribute_is_not_treated_as_literal():
    """An unresolved ``${var.x}`` is not a real name; fall back to the label."""
    findings = [
        _finding(
            "CKV_AWS_18",
            address="aws_s3_bucket.data",
            resource={"attributes": {"bucket": "${var.bucket_name}"}},
        )
    ]
    result, _ = _run(findings, {("s3", "GetBucketLogging"): {}})
    ev = result["findings"][0]["liveVerification"]
    assert ev["lookupIdentifier"] == "data"
    assert ev["identifierDerived"] is True


def test_transient_lookup_failure_stays_static_only_not_confirmed():
    """A permission/transient error is NOT a verification. The finding stands as
    static-only with the error recorded -- never silently confirmed or dropped."""
    findings = [_finding("CKV_AWS_18", physicalId="b")]
    responses = {("s3", "GetBucketLogging"): lv.AwsCallError("s3", "GetBucketLogging", "AccessDenied", "no perms")}
    result, _ = _run(findings, responses)
    f = result["findings"][0]
    assert f["verification"] == "static-only"
    assert "AccessDenied" in f["liveVerification"]["error"]


# ===========================================================================
# Scoring: verification feeds priorityScore (SPEC §5.4)
# ===========================================================================


def test_confirmed_boosts_priority_score():
    findings = [_finding("CKV_AWS_18", severity="high", exploitability="moderate", remediationComplexity="simple", physicalId="b")]
    result, _ = _run(findings, {("s3", "GetBucketLogging"): {}})
    f = result["findings"][0]
    assert f["verification"] == lv.CONFIRMED
    # high(80) x moderate(1.2) x simple(1.5) = 144 -> clamp 100, +15 confirmed -> stays 100.
    assert f["priorityScore"] == 100
    assert f["isQuickWin"] is True


def test_not_deployed_penalizes_priority_score():
    findings = [_finding("CKV_AWS_16", severity="medium", exploitability="complex", remediationComplexity="moderate", physicalId="ghost")]
    responses = {("s3", "GetBucketEncryption"): lv.ResourceNotFoundError("s3", "GetBucketEncryption", "NoSuchBucket", "")}
    result, _ = _run(findings, responses)
    f = result["findings"][0]
    assert f["verification"] == lv.NOT_DEPLOYED
    # medium(60) x complex(1.0) x moderate(1.0) = 60, -20 not-deployed -> 40.
    assert f["priorityScore"] == 40


def test_account_id_stamped_on_confirmed_finding():
    """When we know the account and the resource exists, stamp accountId."""
    findings = [_finding("CKV_AWS_18", physicalId="b")]
    stub = StubAws({("s3", "GetBucketLogging"): {}})
    ro = lv.ReadOnlyCaller(stub)
    result = lv.live_verify({"findings": findings}, ro, account_id="123456789012", region="us-east-1")
    f = result["findings"][0]
    assert f["accountId"] == "123456789012"
    assert f["region"] == "us-east-1"


# ===========================================================================
# Summary block + injected-caller seam
# ===========================================================================


def test_summary_block_counts_verdicts():
    findings = [
        _finding("CKV_AWS_18", address="aws_s3_bucket.a", physicalId="a"),  # confirmed
        _finding("CKV_AWS_16", address="aws_s3_bucket.b", physicalId="b"),  # not-deployed
        _finding("CKV_AWS_21", address="aws_s3_bucket.c", physicalId="c"),  # drift
        _finding("CKV_AWS_99999", address="aws_s3_bucket.d", physicalId="d"),  # static-only
    ]
    responses = {
        ("s3", "GetBucketLogging"): {},
        ("s3", "GetBucketEncryption"): lv.ResourceNotFoundError("s3", "GetBucketEncryption", "NoSuchBucket", ""),
        ("s3", "GetBucketVersioning"): {"Status": "Enabled"},
    }
    result, _ = _run(findings, responses)
    summary = result["liveVerification"]
    assert summary["checked"] == 4
    assert summary["confirmed"] == 1
    assert summary["notDeployed"] == 1
    assert summary["drifted"] == 1
    assert summary["staticOnly"] == 1
    assert result["liveVerifyDegraded"] is False


def test_injected_caller_skips_availability_probe():
    """A bare AwsCallFn injected as caller is wrapped and used; no boto3 needed."""
    findings = [_finding("CKV_AWS_18", physicalId="b")]
    result = lv.run_live_verify({"findings": findings}, caller=lambda s, o, p: {})
    assert result["findings"][0]["verification"] == lv.CONFIRMED


def test_empty_findings_is_a_clean_noop():
    result = lv.run_live_verify({"findings": []}, caller=lambda s, o, p: {})
    assert result["findings"] == []
    assert result["liveVerification"]["checked"] == 0
    assert result["liveVerifyDegraded"] is False


def test_verification_states_are_valid_schema_values():
    """Every verdict this module can emit is a legal findings.py verification value."""
    assert {lv.STATIC_ONLY, lv.CONFIRMED, lv.NOT_DEPLOYED, lv.DRIFTED}.issubset(set(VERIFICATIONS))


def test_original_payload_not_mutated():
    """run_live_verify returns a NEW payload; the caller's input is untouched."""
    findings = [_finding("CKV_AWS_18", physicalId="b")]
    payload = {"findings": findings}
    lv.run_live_verify(payload, caller=lambda s, o, p: {})
    assert payload["findings"][0]["verification"] == "static-only"
