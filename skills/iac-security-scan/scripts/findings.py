#!/usr/bin/env python3
"""
Finding schema, severity resolution, and priority scoring.

Ported from infrabot's ``src/types/findings.ts`` (585 lines) with the §5 schema
inversion that everything in this product hinges on:

    infrabot was ARN-centric  ->  we are location-centric

infrabot's ``EnrichedFinding`` carried ``resourceArn`` / ``region`` / ``accountId``
and had **no file or line provenance at all**. For a static IaC scanner that is
backwards: the file and line are the only things that always exist, and the ARN
is the thing that usually does not (nothing is deployed yet).

So:
  * ``location`` (file, startLine, endLine, resourceAddress, resourceType, service)
    is **REQUIRED**. No location, no finding.
  * ``resourceArn`` / ``accountId`` / ``region`` are **optional and live-only** --
    they are ``None`` in every static scan and only populated under ``--live``.

Severity governance (the non-negotiable):

    data/rule-severity.json is static, checked-in, human-reviewed data.
    The model NEVER generates a baseline severity at runtime.

    The LLM may *adjust* a real seed by at most +/-1 level and must record
    ``severityAdjustedFrom`` plus a written justification. It may not invent a
    severity for a rule that has no seed. An unmapped rule resolves to the
    explicit sentinel ``unmapped`` -- it is NEVER defaulted to a middle value.
    Silence is safer than a guess.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Vocabularies (ported verbatim from findings.ts / remediation.ts)
# ---------------------------------------------------------------------------

# findings.ts:14 -- Severity
SEVERITIES = ("critical", "high", "medium", "low", "informational")

# findings.ts:59 -- Exploitability
EXPLOITABILITIES = ("trivial", "moderate", "complex", "theoretical")

# findings.ts:64 -- RemediationComplexity
REMEDIATION_COMPLEXITIES = ("simple", "moderate", "complex")

# SPEC §6.4 -- RemediationType
REMEDIATION_TYPES = ("iac", "cli", "manual", "console", "hybrid")

# SPEC §3.2 -- live verification state
VERIFICATIONS = ("static-only", "confirmed", "not-deployed", "drifted")

# The explicit sentinel for a rule with no checked-in seed.
# This is a first-class value, not an error and not a default.
UNMAPPED = "unmapped"

# Severity ordering, most severe first. Used for the +/-1 adjustment cap.
_SEVERITY_ORDER: List[str] = list(SEVERITIES)


# ---------------------------------------------------------------------------
# Priority scoring -- ported VERBATIM from assessment.ts:1970-2011
# ---------------------------------------------------------------------------

# assessment.ts:1975 -- severityScore
SEVERITY_WEIGHT: Dict[str, int] = {
    "critical": 100,
    "high": 80,
    "medium": 60,
    "low": 40,
    "informational": 20,
}

# assessment.ts:1983 -- exploitabilityScore
EXPLOITABILITY_MULTIPLIER: Dict[str, float] = {
    "trivial": 1.5,
    "moderate": 1.2,
    "complex": 1.0,
    "theoretical": 0.8,
}

# assessment.ts:1990 -- complexityScore. Cheap fixes rank UP: a simple fix for a
# high-severity issue should outrank a complex fix for the same severity.
COMPLEXITY_MULTIPLIER: Dict[str, float] = {
    "simple": 1.5,
    "moderate": 1.0,
    "complex": 0.7,
}

# Boosts. The first two are assessment.ts:1375; the verification pair is new in
# SPEC §5.4 (a statically-found flaw that is confirmed live *right now* is more
# urgent; one that is not deployed anywhere is less).
CRITICAL_RESOURCE_BOOST = 15
PUBLIC_FACING_BOOST = 10
VERIFICATION_CONFIRMED_BOOST = 15
VERIFICATION_NOT_DEPLOYED_PENALTY = -20


def _round_half_up(value: float) -> int:
    """JS Math.round semantics: .5 always rounds up (Python's round() is banker's)."""
    import math

    return int(math.floor(value + 0.5))


def priority_score(
    severity: str,
    exploitability: str,
    remediation_complexity: str,
    *,
    affects_critical_resource: bool = False,
    is_public_facing: bool = False,
    verification: str = "static-only",
    threat_score: Optional[float] = None,
) -> int:
    """Compute a 0-100 priority score.

    Ported verbatim from ``assessment.ts:1970-2011`` (``calculatePriorityScore``)
    plus the boosts applied at its call site (``assessment.ts:1375``) and the two
    verification adjustments added by SPEC §5.4.

        score = severityWeight x exploitabilityMul x complexityMul
              (+ ThreatScore blended 70/30 when present -- live mode only)
              + 15 critical resource
              + 10 public facing
              + 15 verification == "confirmed"
              - 20 verification == "not-deployed"
              -> clamp(0, 100)

    An ``unmapped`` severity has no weight and therefore no score: callers get 0
    and must present the finding as unranked rather than pretend it is low risk.
    """
    if severity not in SEVERITY_WEIGHT:
        # unmapped (or garbage). We do not invent a weight. 0 == unranked.
        return 0
    if exploitability not in EXPLOITABILITY_MULTIPLIER:
        raise ValueError(f"unknown exploitability: {exploitability!r}")
    if remediation_complexity not in COMPLEXITY_MULTIPLIER:
        raise ValueError(f"unknown remediationComplexity: {remediation_complexity!r}")

    base = _round_half_up(
        SEVERITY_WEIGHT[severity]
        * EXPLOITABILITY_MULTIPLIER[exploitability]
        * COMPLEXITY_MULTIPLIER[remediation_complexity]
    )

    # assessment.ts:2001 -- Prowler v5 ThreatScore, weighted 30%. Live-only; a
    # static scan never has one.
    if threat_score is not None and 0 <= threat_score <= 100:
        base = _round_half_up(base * 0.7 + threat_score * 0.3)

    if affects_critical_resource:
        base = min(100, base + CRITICAL_RESOURCE_BOOST)
    if is_public_facing:
        base = min(100, base + PUBLIC_FACING_BOOST)

    if verification == "confirmed":
        base = min(100, base + VERIFICATION_CONFIRMED_BOOST)
    elif verification == "not-deployed":
        base = base + VERIFICATION_NOT_DEPLOYED_PENALTY

    return min(max(base, 0), 100)


def is_quick_win(severity: str, remediation_complexity: str) -> bool:
    """(critical|high) && complexity == simple -- assessment.ts:2016-2024.

    This drives the report's most-used section: the "fix these five things before
    lunch" list. An ``unmapped`` severity is never a quick win -- we do not know
    that it matters, so we do not tell anyone to drop everything for it.
    """
    return severity in ("critical", "high") and remediation_complexity == "simple"


# ---------------------------------------------------------------------------
# Severity resolution chain
#
#   data/rule-severity.json  (checked-in seed, human-reviewed)
#     -> LLM adjustment      (+/-1 level max, requires severityAdjustedFrom + reason)
#     -> priorityScore       (§5.4 formula, above)
# ---------------------------------------------------------------------------

_DEFAULT_SEVERITY_MAP_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "rule-severity.json"
)


@dataclass(frozen=True)
class SeveritySeed:
    """One row of the checked-in severity map."""

    rule_id: str
    severity: str  # one of SEVERITIES, or UNMAPPED
    rationale: str
    source: str  # checkov-metadata | prowler | curated | none

    @property
    def is_mapped(self) -> bool:
        return self.severity != UNMAPPED


UNMAPPED_SEED_RATIONALE = (
    "No checked-in baseline severity for this rule. Reported as unmapped rather "
    "than guessed; add a reviewed entry to data/rule-severity.json to rank it."
)


class SeverityMap:
    """The checked-in rule-ID -> baseline-severity map.

    This is the ranking spine of the entire product. It is *data*, it is reviewed
    by a human, and nothing at runtime may write to it.
    """

    def __init__(self, rules: Dict[str, Dict[str, str]]):
        self._rules: Dict[str, SeveritySeed] = {}
        for rule_id, entry in rules.items():
            severity = entry["severity"]
            if severity not in SEVERITIES and severity != UNMAPPED:
                raise ValueError(
                    f"{rule_id}: invalid severity {severity!r} in rule-severity.json"
                )
            # Provenance of the baseline severity, weakest to strongest authority.
            # "gate1-reviewed" means a human looked at this specific rule and ruled on
            # it, overriding whatever the upstream source said. It outranks the rest.
            source = entry.get("source", "curated")
            if source not in (
                "checkov-metadata",
                "prowler",
                "curated",
                "gate1-reviewed",
                "none",
            ):
                raise ValueError(f"{rule_id}: invalid source {source!r}")
            self._rules[rule_id] = SeveritySeed(
                rule_id=rule_id,
                severity=severity,
                rationale=entry.get("rationale", ""),
                source=source,
            )

    @classmethod
    def load(cls, path: Optional[str] = None) -> "SeverityMap":
        with open(path or _DEFAULT_SEVERITY_MAP_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        # Allow an optional "$schema"/"_meta" preamble without polluting the map.
        rules = {k: v for k, v in data.items() if not k.startswith(("$", "_"))}
        return cls(rules)

    def resolve(self, rule_id: str) -> SeveritySeed:
        """Resolve a rule ID to its seeded baseline severity.

        An unknown rule resolves to the explicit ``unmapped`` sentinel. It is NOT
        defaulted to "medium" or any other middle value -- a fabricated middle
        severity is indistinguishable from a real one in the report, and would
        silently mis-rank every scan.
        """
        seed = self._rules.get(rule_id)
        if seed is not None:
            return seed
        return SeveritySeed(
            rule_id=rule_id,
            severity=UNMAPPED,
            rationale=UNMAPPED_SEED_RATIONALE,
            source="none",
        )

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rule_ids(self) -> List[str]:
        return list(self._rules)


class SeverityAdjustmentError(ValueError):
    """The LLM tried to make an adjustment the governance rule forbids."""


def adjust_severity(seed: SeveritySeed, proposed: str, justification: str) -> Dict[str, Any]:
    """Apply an LLM severity adjustment to a *real seed* (SPEC §5.1).

    Rules, all enforced here rather than trusted to the prompt:
      * The seed must exist. The model may not invent a severity for an unmapped
        rule -- that is exactly the "generate a baseline at runtime" behavior the
        governance rule forbids.
      * The move is capped at +/-1 level. A critical does not become a low.
      * A written justification is mandatory, and ``severityAdjustedFrom`` is
        recorded so a human can audit every adjustment in one pass.

    Returns the fields to merge into the finding.
    """
    if not seed.is_mapped:
        raise SeverityAdjustmentError(
            f"{seed.rule_id}: cannot adjust an unmapped rule. The model may adjust a "
            "reviewed seed, never invent one. Add a seed to data/rule-severity.json."
        )
    if proposed not in SEVERITIES:
        raise SeverityAdjustmentError(f"{seed.rule_id}: invalid severity {proposed!r}")
    if not justification or not justification.strip():
        raise SeverityAdjustmentError(
            f"{seed.rule_id}: a severity adjustment requires a written justification."
        )

    distance = abs(_SEVERITY_ORDER.index(proposed) - _SEVERITY_ORDER.index(seed.severity))
    if distance > 1:
        raise SeverityAdjustmentError(
            f"{seed.rule_id}: adjustment {seed.severity} -> {proposed} moves "
            f"{distance} levels; the cap is 1 (SPEC §5.1)."
        )

    return {
        "severity": proposed,
        "severityAdjustedFrom": seed.severity,
        "severityAdjustmentReason": justification.strip(),
    }


# ---------------------------------------------------------------------------
# Finding ID
# ---------------------------------------------------------------------------


def generate_finding_id(rule_id: str, file: str, resource_address: str) -> str:
    """``finding-<sha256(ruleId + ':' + file + ':' + resourceAddress)[0:16]>`` (SPEC §5).

    Stable across runs, which is what makes baselines and suppressions possible
    later. Note the inputs are all static-scan facts -- no ARN, no timestamp.
    """
    key = f"{rule_id}:{file}:{resource_address}"
    return "finding-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# The schema
# ---------------------------------------------------------------------------


@dataclass
class Location:
    """REQUIRED on every finding. The schema inversion (SPEC §5).

    Populated from tfparse's ``__tfmeta`` block (see WS-1). A finding without a
    location cannot populate SARIF and cannot drive the patcher, so it is not a
    finding we are willing to emit.
    """

    file: str  # repo-relative, always
    startLine: int
    endLine: int
    resourceAddress: str  # "aws_s3_bucket.data_lake"
    resourceType: str  # "aws_s3_bucket"
    service: str  # "s3"

    def __post_init__(self) -> None:
        if not self.file:
            raise ValueError("location.file is required")
        if not self.resourceAddress:
            raise ValueError("location.resourceAddress is required")

    @staticmethod
    def service_from_resource_type(resource_type: str) -> str:
        """``aws_s3_bucket`` -> ``s3``; ``aws_cloudwatch_log_group`` -> ``cloudwatch``."""
        parts = resource_type.split("_")
        if len(parts) >= 2 and parts[0] in ("aws", "google", "azurerm"):
            return parts[1]
        return parts[0] if parts else resource_type


@dataclass
class Fix:
    diff: str
    validated: bool = False  # survived the Checkov re-check loop
    confidence: str = "medium"  # high | medium | low


@dataclass
class Compliance:
    """Only populated when --compliance is set. Never model-generated (SPEC §5.3)."""

    nist_800_53: List[str] = field(default_factory=list)
    cis_aws: List[str] = field(default_factory=list)
    fedrampBaseline: Optional[str] = None  # low | moderate | high
    coverage: str = "unmapped"  # automated | partial | manual | unmapped


@dataclass
class Finding:
    """The core finding record. Field names match SPEC §5 exactly -- three other
    workstreams (merge/enrich, remediation, SARIF) join against this shape.
    """

    # --- Identity ---
    ruleId: str
    title: str
    location: Location
    description: str = ""
    source: List[str] = field(default_factory=list)  # ["checkov"] | ["llm"] | both

    # --- Severity & scoring ---
    severity: str = UNMAPPED
    severityAdjustedFrom: Optional[str] = None
    severityAdjustmentReason: Optional[str] = None
    severitySource: str = "none"  # checkov-metadata | prowler | curated | none
    exploitability: str = "moderate"
    remediationComplexity: str = "moderate"
    priorityScore: int = 0
    isQuickWin: bool = False

    # --- Enrichment (LLM) ---
    businessImpact: str = ""
    attackScenario: str = ""
    remediationApproach: str = ""
    dependenciesToCheck: List[str] = field(default_factory=list)
    testingSteps: List[str] = field(default_factory=list)
    relatedFindings: List[str] = field(default_factory=list)

    # --- Remediation ---
    remediationType: str = "iac"
    nonIaCCategory: Optional[str] = None
    autoApplicable: bool = False
    fix: Optional[Fix] = None

    # --- Compliance (only when --compliance is set) ---
    compliance: Optional[Compliance] = None

    # --- Live verification (only when --live) ---
    verification: str = "static-only"
    resourceArn: Optional[str] = None  # live-only, optional
    accountId: Optional[str] = None  # live-only, optional
    region: Optional[str] = None  # live-only, optional

    # --- Scoring context (inputs to the boosts; not part of the wire schema) ---
    affectsCriticalResource: bool = False
    isPublicFacing: bool = False
    threatScore: Optional[float] = None

    # --- Identity, derived ---
    id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.location, Location):
            raise TypeError("Finding.location is required and must be a Location")
        if not self.id:
            self.id = generate_finding_id(
                self.ruleId, self.location.file, self.location.resourceAddress
            )

    # -- scoring ------------------------------------------------------------

    def rescore(self) -> "Finding":
        """Recompute priorityScore and isQuickWin from current fields."""
        self.priorityScore = priority_score(
            self.severity,
            self.exploitability,
            self.remediationComplexity,
            affects_critical_resource=self.affectsCriticalResource,
            is_public_facing=self.isPublicFacing,
            verification=self.verification,
            threat_score=self.threatScore,
        )
        self.isQuickWin = is_quick_win(self.severity, self.remediationComplexity)
        return self

    def apply_severity_seed(self, seed: SeveritySeed) -> "Finding":
        """Seed the baseline severity from the checked-in map, then rescore."""
        self.severity = seed.severity
        self.severitySource = seed.source
        return self.rescore()

    def apply_severity_adjustment(
        self, seed: SeveritySeed, proposed: str, justification: str
    ) -> "Finding":
        """Apply an audited +/-1 LLM adjustment on top of a real seed, then rescore."""
        for key, value in adjust_severity(seed, proposed, justification).items():
            setattr(self, key, value)
        return self.rescore()

    @property
    def is_unmapped(self) -> bool:
        return self.severity == UNMAPPED

    # -- serialization ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Present id first; it is what everything downstream keys on.
        return {"id": d.pop("id"), **d}


def build_finding(
    *,
    rule_id: str,
    title: str,
    location: Location,
    severity_map: SeverityMap,
    description: str = "",
    source: Optional[List[str]] = None,
    exploitability: str = "moderate",
    remediation_complexity: str = "moderate",
    **kwargs: Any,
) -> Finding:
    """Construct a Finding with its baseline severity resolved from the checked-in map.

    This is the only sanctioned way to give a finding a severity. There is no code
    path that assigns one from anywhere else.
    """
    finding = Finding(
        ruleId=rule_id,
        title=title,
        location=location,
        description=description,
        source=source or [],
        exploitability=exploitability,
        remediationComplexity=remediation_complexity,
        **kwargs,
    )
    return finding.apply_severity_seed(severity_map.resolve(rule_id))


__all__ = [
    "SEVERITIES",
    "EXPLOITABILITIES",
    "REMEDIATION_COMPLEXITIES",
    "REMEDIATION_TYPES",
    "VERIFICATIONS",
    "UNMAPPED",
    "SEVERITY_WEIGHT",
    "EXPLOITABILITY_MULTIPLIER",
    "COMPLEXITY_MULTIPLIER",
    "Location",
    "Fix",
    "Compliance",
    "Finding",
    "SeveritySeed",
    "SeverityMap",
    "SeverityAdjustmentError",
    "adjust_severity",
    "build_finding",
    "generate_finding_id",
    "priority_score",
    "is_quick_win",
]
