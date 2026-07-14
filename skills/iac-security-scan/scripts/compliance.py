#!/usr/bin/env python3
"""
Control-coverage mapping for ``--compliance 800-53`` (WS-10, SPEC 5.3 / 7.2).

THE GOVERNANCE RULE (non-negotiable):

    data/control-map.json is STATIC, CHECKED-IN, HUMAN-REVIEWED DATA. The model
    NEVER generates a control ID at runtime. This module only *reads* that file
    and *joins* it against the findings and passed checks. It cannot mint,
    default, or infer a control ID. A rule with no mapping resolves to the
    explicit sentinel coverage="unmapped" -- never a guess.

    A hallucinated AC-17 in a FedRAMP package is the single worst thing this
    plugin could do (risk #3). Silence is safer than a guess.

The most dangerous misreading in all of compliance tooling is "clean scan =
compliant" (SPEC 14.6). The mitigation ships in EVERY compliance report, not
behind a flag:

    "IaC-assessable controls only. N controls in this baseline cannot be
    evaluated from Terraform."

A control like AC-17 (remote access) or PS-3 (personnel screening) cannot be
evaluated from Terraform at all. This module names them in the not-assessable
bucket so nobody reads a clean IaC scan as a clean FedRAMP posture.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional

# The universe of controls this baseline speaks to. It is checked-in authority
# data (infrabot's CMMC-L2 / NIST 800-171 Rev2 -> 800-53 Rev5 mapping), NOT a
# runtime-derived number. "Assessable from IaC" == at least one Checkov rule in
# control-map.json maps to the control. Everything else in the baseline is
# reported, honestly, as not assessable from Terraform.
_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_CONTROL_MAP_PATH = os.path.join(_HERE, "..", "data", "control-map.json")
_DEFAULT_CMMC_BASELINE_PATH = os.path.join(_HERE, "..", "data", "control-baseline-800-53.json")

# NIST 800-53 Rev 5 control-ID format: family (two letters) - number, optional
# enhancement (n) and/or a lowercased sub-item letter, e.g. AC-2, AC-17(1),
# SC-7(24)(b). The base control is everything before the first parenthesis.
CONTROL_ID_RE = re.compile(r"^[A-Z]{2}-\d+(\(\d+\)|\([a-z]\))*$")

COVERAGE_VALUES = ("automated", "partial", "manual", "unmapped")

MANDATORY_CAVEAT_TEMPLATE = (
    "IaC-assessable controls only. %d controls in this baseline cannot be "
    "evaluated from Terraform."
)


def base_control(control_id: str) -> str:
    """AC-17(1) -> AC-17. The family+number a report groups by."""
    return re.sub(r"\(.*", "", control_id)


class ControlMap:
    """The checked-in Checkov-rule -> NIST 800-53 control map.

    This is data. Nothing at runtime may write to it, and it is the ONLY source
    of a control ID in the whole pipeline.
    """

    def __init__(self, rules: Dict[str, Dict[str, Any]], baseline_controls: Optional[Iterable[str]] = None):
        self._rules: Dict[str, Dict[str, Any]] = {}
        for rule_id, entry in rules.items():
            coverage = entry.get("coverage", "unmapped")
            if coverage not in COVERAGE_VALUES:
                raise ValueError("%s: invalid coverage %r in control-map.json" % (rule_id, coverage))
            controls = entry.get("nist_800_53") or []
            for c in controls:
                if not CONTROL_ID_RE.match(c):
                    raise ValueError("%s: %r is not a NIST 800-53 Rev5 control ID" % (rule_id, c))
            if coverage == "unmapped" and controls:
                raise ValueError("%s: coverage 'unmapped' must carry NO controls" % rule_id)
            self._rules[rule_id] = entry
        # The baseline universe of BASE controls we claim to speak to.
        self._baseline: List[str] = sorted({base_control(c) for c in (baseline_controls or [])})

    @classmethod
    def load(cls, path: Optional[str] = None, baseline_path: Optional[str] = None) -> "ControlMap":
        with open(path or _DEFAULT_CONTROL_MAP_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        rules = {k: v for k, v in data.items() if not k.startswith(("$", "_"))}
        baseline = _load_baseline(baseline_path)
        return cls(rules, baseline_controls=baseline)

    # -- lookups ------------------------------------------------------------

    def for_rule(self, rule_id: str) -> Dict[str, Any]:
        """The mapping entry for a rule, or the explicit unmapped sentinel.

        Never invents a control. A rule absent from the map is unmapped, exactly
        like a rule the reviewers deliberately marked unmapped.
        """
        entry = self._rules.get(rule_id)
        if entry is None:
            return {
                "nist_800_53": [],
                "cis_aws": [],
                "fedrampBaseline": None,
                "coverage": "unmapped",
                "source": "none",
                "rationale": "No entry in control-map.json. Reported unmapped, never guessed.",
            }
        return entry

    def compliance_for_rule(self, rule_id: str) -> Dict[str, Any]:
        """The four wire fields (SPEC 5.3 Compliance dataclass), joined from data."""
        e = self.for_rule(rule_id)
        return {
            "nist_800_53": list(e.get("nist_800_53") or []),
            "cis_aws": list(e.get("cis_aws") or []),
            "fedrampBaseline": e.get("fedrampBaseline"),
            "coverage": e.get("coverage", "unmapped"),
        }

    @property
    def assessable_base_controls(self) -> List[str]:
        """Base controls at least one rule maps to -- what IaC can actually assess."""
        out = set()
        for entry in self._rules.values():
            for c in entry.get("nist_800_53") or []:
                out.add(base_control(c))
        return sorted(out)

    @property
    def baseline_base_controls(self) -> List[str]:
        return list(self._baseline)

    def not_assessable_base_controls(self) -> List[str]:
        """Baseline controls no IaC rule maps to. The honest bucket (AC-17, PS-3, ...)."""
        assessable = set(self.assessable_base_controls)
        return [c for c in self._baseline if c not in assessable]


def _load_baseline(baseline_path: Optional[str]) -> List[str]:
    """The baseline control universe. Prefers a checked-in extract; else derives
    it live from infrabot's cmmc file if present; else falls back to the set of
    controls the map covers (degenerate: then N-not-assessable reads 0 and the
    report says so). All three paths are authority-backed, never invented."""
    path = baseline_path or _DEFAULT_CMMC_BASELINE_PATH
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return list(data.get("baseControls") or [])
    return []


# ---------------------------------------------------------------------------
# Attaching compliance to findings (SPEC 7.2: "attaches to every finding")
# ---------------------------------------------------------------------------


def attach_compliance(findings: List[Dict[str, Any]], control_map: ControlMap) -> None:
    """Set finding['compliance'] in place from the checked-in map. Never invents."""
    for f in findings:
        f["compliance"] = control_map.compliance_for_rule(f.get("ruleId") or "")


# ---------------------------------------------------------------------------
# The control-coverage section (SPEC 7.2)
# ---------------------------------------------------------------------------


def build_control_coverage(
    findings: List[Dict[str, Any]],
    passed_checks: Optional[List[Dict[str, Any]]],
    control_map: ControlMap,
    *,
    baseline: str = "800-53",
) -> Dict[str, Any]:
    """Three buckets: satisfied / violated / NOT ASSESSABLE FROM IaC.

    - violated:  a control with >=1 finding (failed check) mapped to it.
    - satisfied: a control with >=1 passed check mapped to it AND no violation.
    - notAssessable: baseline controls no rule maps to -- named honestly.

    The mandatory caveat is always present, driven by the static baseline vs the
    map, so it ships even when there are zero findings.
    """
    passed_checks = passed_checks or []

    # rule -> base controls, from data only.
    def controls_of(rule_id: str) -> List[str]:
        return sorted({base_control(c) for c in control_map.for_rule(rule_id).get("nist_800_53") or []})

    violated: Dict[str, Dict[str, Any]] = {}
    unmapped_rule_ids: set = set()

    for f in findings:
        rid = f.get("ruleId") or ""
        controls = controls_of(rid)
        if not controls:
            unmapped_rule_ids.add(rid)
            continue
        for c in controls:
            b = violated.setdefault(c, {"control": c, "family": _family(c), "findingIds": [], "ruleIds": set()})
            b["findingIds"].append(f.get("id"))
            b["ruleIds"].add(rid)

    satisfied: Dict[str, Dict[str, Any]] = {}
    for chk in passed_checks:
        rid = chk.get("ruleId") or chk.get("check_id") or ""
        for c in controls_of(rid):
            if c in violated:
                continue  # a control with any violation is not satisfied
            b = satisfied.setdefault(c, {"control": c, "family": _family(c), "ruleIds": set()})
            b["ruleIds"].add(rid)

    not_assessable = control_map.not_assessable_base_controls()
    caveat = MANDATORY_CAVEAT_TEMPLATE % len(not_assessable)

    return {
        "baseline": baseline,
        "baselineSource": "CMMC L2 / NIST 800-171 Rev2 -> 800-53 Rev5 (infrabot cmmc_level2_aws.json)",
        "assessableControlCount": len(control_map.assessable_base_controls),
        "baselineControlCount": len(control_map.baseline_base_controls),
        "satisfied": [
            {"control": v["control"], "family": v["family"], "ruleIds": sorted(v["ruleIds"])}
            for v in _by_control(satisfied)
        ],
        "violated": [
            {
                "control": v["control"],
                "family": v["family"],
                "findingIds": v["findingIds"],
                "ruleIds": sorted(v["ruleIds"]),
            }
            for v in _by_control(violated)
        ],
        "notAssessable": {
            "count": len(not_assessable),
            "controls": not_assessable,
            "note": (
                "These controls are in the baseline but cannot be evaluated from "
                "Terraform -- they are process/operational (e.g. AC-17 remote access, "
                "PS-3 personnel screening, AT-2 awareness training) or simply have no "
                "IaC-detectable rule. Their absence from the findings is NOT evidence "
                "of compliance."
            ),
        },
        "unmappedRules": sorted(r for r in unmapped_rule_ids if r),
        "mandatoryCaveat": caveat,
    }


def _family(control_id: str) -> str:
    return control_id.split("-", 1)[0]


def _by_control(d: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    def sort_key(item):
        c = item["control"]
        m = re.match(r"^([A-Z]{2})-(\d+)", c)
        return (m.group(1), int(m.group(2))) if m else (c, 0)
    return sorted(d.values(), key=sort_key)


__all__ = [
    "ControlMap",
    "CONTROL_ID_RE",
    "COVERAGE_VALUES",
    "MANDATORY_CAVEAT_TEMPLATE",
    "attach_compliance",
    "base_control",
    "build_control_coverage",
]
