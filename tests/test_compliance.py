"""WS-10 · compliance.py + control-map.json (SPEC §5.3 / §7.2), GATE 3.

The governance rule this file exists to enforce:

    data/control-map.json is checked-in, human-reviewed DATA. The model NEVER
    generates a control ID at runtime. Every nist_800_53 entry must trace to an
    authority; anything else is coverage="unmapped". A hallucinated AC-17 in a
    FedRAMP package is the single worst thing this plugin could do (risk #3).

And the one mitigation that is NOT optional:

    "IaC-assessable controls only. N controls in this baseline cannot be
    evaluated from Terraform." -- present in EVERY compliance report.
"""

import json
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "skills", "iac-security-scan", "scripts")
DATA = os.path.join(ROOT, "skills", "iac-security-scan", "data")
sys.path.insert(0, SCRIPTS)

from compliance import (  # noqa: E402
    CONTROL_ID_RE,
    COVERAGE_VALUES,
    ControlMap,
    attach_compliance,
    base_control,
    build_control_coverage,
)
from report import build_report, render_markdown  # noqa: E402

CONTROL_MAP_PATH = os.path.join(DATA, "control-map.json")
BASELINE_PATH = os.path.join(DATA, "control-baseline-800-53.json")
CMMC_PATH = "/Users/sasser/dev/infrabot/src/compliance/cmmc_level2_aws.json"

# NIST 800-53 Rev 5 control-ID format, independent of the module under test.
NIST_RE = re.compile(r"^[A-Z]{2}-\d+(\(\d+\)|\([a-z]\))*$")


@pytest.fixture(scope="module")
def raw_map():
    with open(CONTROL_MAP_PATH, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def entries(raw_map):
    return {k: v for k, v in raw_map.items() if not k.startswith(("$", "_"))}


@pytest.fixture(scope="module")
def cmmc_base_controls():
    """Every base control the cmmc authority names -- the traceability oracle."""
    if not os.path.exists(CMMC_PATH):
        pytest.skip("infrabot cmmc source not present; baseline extract test covers it")
    with open(CMMC_PATH, encoding="utf-8") as fh:
        cmmc = json.load(fh)
    base = set()
    for req in cmmc["Requirements"]:
        for a in req.get("Attributes", []):
            for c in re.split(r"[,\s]+", a.get("NIST_800_53_Control", "")):
                c = c.strip()
                if c:
                    base.add(base_control(c))
    return base


# ---------------------------------------------------------------------------
# Acceptance #2 -- ZERO INVENTED CONTROL IDs
# ---------------------------------------------------------------------------


class TestNoInventedControls:
    def test_every_control_id_is_valid_nist_format(self, entries):
        for rule, e in entries.items():
            for c in e.get("nist_800_53") or []:
                assert NIST_RE.match(c), "%s: %r is not a NIST 800-53 Rev5 control ID" % (rule, c)

    def test_every_control_traces_to_an_authority(self, entries, cmmc_base_controls):
        """Every mapped control appears in the cmmc source file, OR the entry is
        source='curated' with a non-empty rationale. No third option exists --
        that is the whole point of GATE 3."""
        for rule, e in entries.items():
            controls = e.get("nist_800_53") or []
            if not controls:
                continue
            source = e.get("source")
            if source == "curated":
                assert (e.get("rationale") or "").strip(), "%s: curated but no rationale" % rule
                continue
            assert source == "cmmc-derived", "%s: unexpected source %r" % (rule, source)
            for c in controls:
                assert base_control(c) in cmmc_base_controls, (
                    "%s: control %s is NOT in the cmmc authority and is not curated -- "
                    "this is exactly the hallucination GATE 3 guards against" % (rule, c)
                )

    def test_baseline_extract_matches_the_cmmc_authority(self, cmmc_base_controls):
        with open(BASELINE_PATH, encoding="utf-8") as fh:
            baseline = json.load(fh)
        assert set(baseline["baseControls"]) == cmmc_base_controls

    def test_no_control_id_is_synthesized_by_the_loader(self):
        """A rule absent from the map resolves to unmapped with NO control -- the
        loader can never mint an ID."""
        cm = ControlMap.load()
        got = cm.compliance_for_rule("CKV_AWS_DOES_NOT_EXIST_9999")
        assert got["coverage"] == "unmapped"
        assert got["nist_800_53"] == []


# ---------------------------------------------------------------------------
# Acceptance #3 -- unmapped is stated plainly, never guessed or defaulted
# ---------------------------------------------------------------------------


class TestUnmappedIsHonest:
    def test_unmapped_entries_carry_no_controls(self, entries):
        for rule, e in entries.items():
            if e.get("coverage") == "unmapped":
                assert not (e.get("nist_800_53") or []), "%s: unmapped but has controls" % rule

    def test_coverage_values_are_from_the_closed_set(self, entries):
        for rule, e in entries.items():
            assert e.get("coverage") in COVERAGE_VALUES, "%s: bad coverage" % rule

    def test_loader_rejects_an_unmapped_entry_that_carries_a_control(self):
        with pytest.raises(ValueError):
            ControlMap({"CKV_X": {"coverage": "unmapped", "nist_800_53": ["AC-3"]}})

    def test_loader_rejects_a_malformed_control_id(self):
        with pytest.raises(ValueError):
            ControlMap({"CKV_X": {"coverage": "automated", "nist_800_53": ["not-a-control"]}})


# ---------------------------------------------------------------------------
# Acceptance #1 -- every mapped control is auditable (source + rationale)
# ---------------------------------------------------------------------------


class TestAuditability:
    def test_every_mapped_rule_has_source_and_rationale(self, entries):
        for rule, e in entries.items():
            if e.get("coverage") == "unmapped":
                continue
            assert e.get("source"), "%s: no source" % rule
            assert (e.get("rationale") or "").strip(), "%s: no rationale" % rule

    def test_map_covers_the_criticals_we_emit(self, entries):
        """The rules that must never resolve to unmapped in a real repo: the
        public-exposure criticals. They are mapped, and NOT to AC-17."""
        for rule in ("CKV_AWS_70", "CKV_AWS_20", "CKV_AWS_57", "CKV_AWS_17"):
            e = entries[rule]
            assert e["coverage"] == "automated"
            assert e["nist_800_53"], "%s must map to a control" % rule
            assert not any(base_control(c) == "AC-17" for c in e["nist_800_53"]), (
                "%s must NOT map to AC-17 (remote access) -- the over-map hazard" % rule
            )


# ---------------------------------------------------------------------------
# Acceptance #4 -- the "N controls not assessable" line ships in EVERY report
# ---------------------------------------------------------------------------


class TestMandatoryCaveat:
    def _cov(self, findings=None, passed=None):
        cm = ControlMap.load()
        return build_control_coverage(findings or [], passed or [], cm)

    def test_caveat_present_with_zero_findings(self):
        cov = self._cov()
        assert re.search(
            r"IaC-assessable controls only\. \d+ controls in this baseline cannot be "
            r"evaluated from Terraform\.",
            cov["mandatoryCaveat"],
        )

    def test_caveat_count_is_baseline_minus_assessable(self):
        cm = ControlMap.load()
        cov = build_control_coverage([], [], cm)
        expected = len(cm.baseline_base_controls) - len(cm.assessable_base_controls)
        assert cov["notAssessable"]["count"] == expected
        assert str(expected) in cov["mandatoryCaveat"]

    def test_not_assessable_names_the_process_controls(self):
        cov = self._cov()
        controls = cov["notAssessable"]["controls"]
        # AC-17 (remote access) and PS-3 (personnel screening) are in the baseline
        # but cannot be evaluated from Terraform -- they MUST be named, not omitted.
        assert "AC-17" in controls
        assert "PS-3" in controls

    def test_caveat_renders_in_every_compliance_report(self):
        report = build_report(
            _merged([_finding("CKV_AWS_70")]),
            checkov_result={"degraded": False, "findings": []},
            parse_result={"parseTier": "tfparse", "degraded": False, "resources": []},
            compliance="800-53",
            compliance_coverage=self._cov([_finding("CKV_AWS_70")]),
        )
        md = render_markdown(report)
        block = md.split("## Compliance coverage")[1]
        assert "IaC-assessable controls only." in block
        assert "cannot be evaluated from Terraform" in block

    def test_caveat_present_even_on_a_clean_scan_report(self):
        """A clean scan is the most dangerous case: it must still say what it
        could NOT assess, or it reads as a clean FedRAMP posture."""
        cov = self._cov([])  # no findings at all
        report = build_report(
            _merged([]),
            checkov_result={"degraded": False, "findings": []},
            parse_result={"parseTier": "tfparse", "degraded": False, "resources": []},
            compliance="800-53",
            compliance_coverage=cov,
        )
        block = render_markdown(report).split("## Compliance coverage")[1]
        assert "IaC-assessable controls only." in block
        assert "NOT ASSESSABLE FROM IaC" in block


# ---------------------------------------------------------------------------
# Buckets: satisfied / violated / unmapped-findings
# ---------------------------------------------------------------------------


class TestBuckets:
    def test_violation_maps_a_finding_to_its_controls(self):
        cm = ControlMap.load()
        cov = build_control_coverage([_finding("CKV_AWS_70", fid="f1")], [], cm)
        violated = {v["control"] for v in cov["violated"]}
        assert "AC-3" in violated and "SC-7" in violated

    def test_passing_check_satisfies_a_control(self):
        cm = ControlMap.load()
        cov = build_control_coverage([], [{"ruleId": "CKV_AWS_19"}], cm)
        satisfied = {s["control"] for s in cov["satisfied"]}
        assert "SC-28" in satisfied

    def test_a_control_with_any_violation_is_not_satisfied(self):
        cm = ControlMap.load()
        # SC-28 both passes (bucket A) and fails (bucket B) -> must land violated only.
        cov = build_control_coverage(
            [_finding("CKV_AWS_145", fid="fail")],  # S3 KMS -> SC-28
            [{"ruleId": "CKV_AWS_19"}],  # S3 default encryption -> SC-28
            cm,
        )
        assert "SC-28" in {v["control"] for v in cov["violated"]}
        assert "SC-28" not in {s["control"] for s in cov["satisfied"]}

    def test_unmapped_finding_is_reported_not_dropped(self):
        cm = ControlMap.load()
        cov = build_control_coverage([_finding("CKV_AWS_116", fid="dlq")], [], cm)
        assert "CKV_AWS_116" in cov["unmappedRules"]
        assert cov["violated"] == []


# ---------------------------------------------------------------------------
# Per-finding attachment (SPEC 7.2: "attaches to every finding")
# ---------------------------------------------------------------------------


class TestAttach:
    def test_attach_sets_data_backed_compliance(self):
        cm = ControlMap.load()
        findings = [_finding("CKV_AWS_70"), _finding("CKV_AWS_116")]
        attach_compliance(findings, cm)
        assert findings[0]["compliance"]["coverage"] == "automated"
        assert findings[0]["compliance"]["nist_800_53"]
        assert findings[1]["compliance"]["coverage"] == "unmapped"
        assert findings[1]["compliance"]["nist_800_53"] == []


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _finding(rule_id, fid=None):
    return {
        "id": fid or (rule_id + "-1"),
        "ruleId": rule_id,
        "title": rule_id,
        "location": {"file": "main.tf", "startLine": 1, "resourceAddress": "r.x"},
    }


def _merged(findings):
    return {
        "findings": findings,
        "exposureChains": [],
        "suppressionLog": [],
        "injectionAttempts": [],
        "summary": {"total": len(findings)},
    }
