#!/usr/bin/env python3
"""
merge_findings.py — join the two rule layers, dedupe, enrich (WS-4).

SPEC §4.3: both layers produce findings and they WILL overlap. The dedupe key is
``(normalized-rule-concept, file, resourceAddress)``. On collision we keep the
Checkov finding — its stable rule ID and its line precision — and absorb the LLM's
enrichment fields into it. The user sees ONE finding carrying the best of both,
with ``source: ["checkov", "llm"]``, because that concurrence is itself a
confidence signal.

Pre-flight (IMPLEMENTATION_PLAN §1.3) confirmed the key joins natively:

    checkov.resource       == "aws_athena_workgroup.main"
    tfparse.__tfmeta.path  == "aws_athena_workgroup.main"     <- byte-identical

so there is no address translation layer here, deliberately. The only
normalization is the one the adapter already does (Checkov's ``/athena.tf`` ->
repo-relative ``athena.tf``), and it happens in ``run_checkov.py``, not here.

SPEC §4.2 — the exposure-chain pass. tfparse hands us ``references`` per resource
for free. We build the dependency graph from them and use it for two things:
  * ``relatedFindings`` — findings on resources that are wired to this one.
  * ``exposureChains``  — an internet-reachable resource -> ... -> a data resource,
    where the individual hops may each be unremarkable and the *path* is the bug.
    This is the thing a rule engine structurally cannot see, and the clearest
    place we beat the commodity tools.

===========================================================================
PROMPT-INJECTION HARDENING (SPEC §11) — the load-bearing property of this file
===========================================================================

The deterministic layer is STRUCTURALLY INCAPABLE of being talked out of a
finding. That is not a policy in a prompt; it is the shape of this code:

  * Every Checkov finding enters ``merge()`` and every Checkov finding leaves it.
    ``merge()`` asserts this on the way out (``_assert_checkov_survives``) and
    raises if it is ever violated. The LLM's payload can only ever *add* keys to a
    finding dict; there is no code path in which an LLM response removes an
    element from the finding list.
  * An LLM "suppression" is a REQUEST. It is recorded on the finding
    (``llmSuppressionRequested`` / ``llmSuppressionReason``), written to the
    top-level ``suppressionLog``, and printed to stderr. The finding is still
    reported. A model that has been talked into dropping a finding leaves a trace.
  * A severity adjustment goes through ``findings.adjust_severity()``, which caps
    the move at +/-1, requires a written reason, and refuses to invent a severity
    for an unmapped rule.

Usage:
    python3 merge_findings.py --parse <parse.json> --checkov <checkov.json> \\
                              [--llm <llm.json>] [--emit-prompts] [--out -]

Exit codes: 0 ok, 2 error.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enrich_prompts import (  # noqa: E402
    batch_enrichment_prompt,
    deep_enrichment_prompt,
    minimal_enrichment,
    tier_findings,
)
from findings import (  # noqa: E402
    SEVERITIES,
    UNMAPPED,
    SeverityAdjustmentError,
    SeverityMap,
    adjust_severity,
    is_quick_win,
    priority_score,
)

# ---------------------------------------------------------------------------
# Rule-concept normalization (the first third of the §4.3 join key)
# ---------------------------------------------------------------------------
#
# Two layers can find the same bug under two different names: Checkov calls it
# CKV_AWS_18, the model calls it "the logs bucket has no access logging". The
# concept is what makes them collide.
#
# This map is CURATED DATA, in code, deliberately small. It only needs entries for
# concepts BOTH layers can plausibly find. An unmapped Checkov rule falls back to a
# namespaced slug of its own ID, which can never collide by accident — the failure
# mode of a missing entry is a duplicate-looking pair, never a wrongly-merged pair,
# and that is the right way round for a security tool.

CONCEPT_MAP: Dict[str, str] = {
    # --- S3 ---
    "CKV_AWS_18": "s3-access-logging",
    "CKV2_AWS_62": "s3-event-notifications",
    "CKV_AWS_21": "s3-versioning",
    "CKV_AWS_144": "s3-cross-region-replication",
    "CKV_AWS_145": "s3-encryption-at-rest",
    "CKV_AWS_19": "s3-encryption-at-rest",
    "CKV2_AWS_6": "s3-public-access-block",
    "CKV_AWS_20": "s3-public-read",
    "CKV_AWS_53": "s3-public-access-block",
    "CKV_AWS_54": "s3-public-access-block",
    "CKV_AWS_55": "s3-public-access-block",
    "CKV_AWS_56": "s3-public-access-block",
    "CKV_AWS_300": "s3-lifecycle-abort-multipart",
    # --- Logging / CloudWatch ---
    "CKV_AWS_66": "cloudwatch-log-retention",
    "CKV_AWS_338": "cloudwatch-log-retention",
    "CKV_AWS_158": "cloudwatch-log-kms-encryption",
    # --- Compute / EBS ---
    "CKV_AWS_3": "ebs-encryption",
    "CKV_AWS_8": "ec2-root-volume-encryption",
    "CKV_AWS_79": "ec2-imdsv2",
    "CKV_AWS_135": "ebs-optimized",
    # --- Network ---
    "CKV_AWS_23": "sg-rule-description",
    "CKV_AWS_24": "sg-ssh-open-to-world",
    "CKV_AWS_25": "sg-rdp-open-to-world",
    "CKV_AWS_260": "sg-http-open-to-world",
    "CKV_AWS_277": "sg-unrestricted-ingress",
    "CKV2_AWS_5": "sg-unattached",
    # --- IAM ---
    "CKV_AWS_1": "iam-wildcard-action",
    "CKV_AWS_40": "iam-policy-attached-to-user",
    "CKV_AWS_49": "iam-wildcard-action",
    "CKV_AWS_60": "iam-role-wildcard-trust",
    "CKV_AWS_61": "iam-role-wildcard-trust",
    "CKV_AWS_62": "iam-role-wildcard-trust",
    "CKV_AWS_63": "iam-wildcard-action",
    "CKV2_AWS_56": "iam-wildcard-action",
    "CKV_AWS_355": "iam-wildcard-resource",
    "CKV_AWS_290": "iam-wildcard-write-resource",
    "CKV_AWS_286": "iam-privilege-escalation",
    "CKV_AWS_287": "iam-credentials-exposure",
    "CKV_AWS_288": "iam-data-exfiltration",
    "CKV_AWS_289": "iam-permissions-management",
    # --- Lambda ---
    "CKV_AWS_50": "lambda-xray-tracing",
    "CKV_AWS_115": "lambda-concurrency-limit",
    "CKV_AWS_116": "lambda-dlq",
    "CKV_AWS_117": "lambda-vpc",
    "CKV_AWS_173": "lambda-env-var-encryption",
    "CKV_AWS_272": "lambda-code-signing",
    # --- RDS / data ---
    "CKV_AWS_16": "rds-encryption-at-rest",
    "CKV_AWS_17": "rds-publicly-accessible",
    "CKV_AWS_118": "rds-enhanced-monitoring",
    "CKV_AWS_129": "rds-log-exports",
    "CKV_AWS_133": "rds-backup-retention",
    "CKV_AWS_157": "rds-multi-az",
    "CKV_AWS_161": "rds-iam-auth",
    "CKV_AWS_226": "rds-auto-minor-version-upgrade",
    "CKV_AWS_293": "rds-deletion-protection",
    "CKV_AWS_353": "rds-performance-insights",
    "CKV_AWS_354": "rds-performance-insights-kms",
    # --- KMS / secrets ---
    "CKV_AWS_7": "kms-key-rotation",
    "CKV_AWS_33": "ecr-image-scanning",
    "CKV_AWS_136": "ecr-kms-encryption",
    "CKV_AWS_149": "secrets-cmk-encryption",
    "CKV_AWS_304": "secrets-rotation",
    # --- DynamoDB / SQS / SNS ---
    "CKV_AWS_119": "dynamodb-kms-encryption",
    "CKV_AWS_28": "dynamodb-pitr",
    "CKV_AWS_27": "sns-encryption",
    "CKV_AWS_26": "sns-encryption",
    "CKV_AWS_101": "sqs-encryption",
    # --- API Gateway / CloudFront / ELB ---
    "CKV_AWS_59": "apigw-open-authorization",
    "CKV_AWS_76": "apigw-access-logging",
    "CKV_AWS_73": "apigw-xray-tracing",
    "CKV_AWS_120": "apigw-caching",
    "CKV2_AWS_29": "apigw-waf",
    "CKV2_AWS_51": "apigw-client-certificate",
    "CKV_AWS_86": "cloudfront-access-logging",
    "CKV_AWS_68": "cloudfront-waf",
    "CKV_AWS_310": "cloudfront-origin-failover",
    "CKV_AWS_91": "elb-access-logging",
    "CKV_AWS_2": "elb-https-only",
    "CKV_AWS_103": "elb-tls-policy",
    "CKV_AWS_150": "elb-deletion-protection",
    "CKV_AWS_131": "elb-drop-invalid-headers",
    "CKV2_AWS_20": "elb-http-redirect",
    "CKV2_AWS_28": "elb-waf",
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def normalize_concept(finding: Dict[str, Any]) -> str:
    """The normalized rule concept — the first third of the §4.3 dedupe key.

    Resolution order:
      1. An explicit ``concept`` on the finding. This is how an LLM finding says
         "I found the same thing Checkov's CKV_AWS_18 finds" and gets merged
         rather than duplicated.
      2. The curated ``CONCEPT_MAP``, keyed by rule ID.
      3. A namespaced slug of the rule ID itself. Cannot false-merge.
    """
    explicit = (finding.get("concept") or "").strip().lower()
    if explicit:
        return _SLUG_RE.sub("-", explicit).strip("-")

    rule_id = (finding.get("ruleId") or "").strip()
    if rule_id in CONCEPT_MAP:
        return CONCEPT_MAP[rule_id]

    # "rule-" is a reserved prefix: no curated concept starts with it, so a rule
    # with no map entry can never accidentally merge with a concept.
    return "rule-" + _SLUG_RE.sub("-", rule_id.lower()).strip("-")


def dedupe_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """``(normalized-rule-concept, file, resourceAddress)`` — SPEC §4.3."""
    location = finding.get("location") or {}
    return (
        normalize_concept(finding),
        location.get("file") or "",
        location.get("resourceAddress") or "",
    )


# ---------------------------------------------------------------------------
# The dependency graph (SPEC §4.2) — free, from tfparse's `references`
# ---------------------------------------------------------------------------

_PROVIDER_PREFIXES = ("aws_", "azurerm_", "google_")

# Resources that put something on the internet, or that describe a path to it.
INTERNET_EXPOSED_TYPES = frozenset(
    {
        "aws_internet_gateway",
        "aws_lb",
        "aws_alb",
        "aws_elb",
        "aws_lb_listener",
        "aws_api_gateway_rest_api",
        "aws_api_gateway_stage",
        "aws_apigatewayv2_api",
        "aws_cloudfront_distribution",
        "aws_eip",
        "aws_route53_record",
    }
)

# Resources that hold, gate, or key the data. The far end of an exposure chain.
DATA_TYPES = frozenset(
    {
        "aws_s3_bucket",
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_dynamodb_table",
        "aws_efs_file_system",
        "aws_elasticache_cluster",
        "aws_redshift_cluster",
        "aws_secretsmanager_secret",
        "aws_ssm_parameter",
        "aws_kms_key",
        "aws_glue_catalog_database",
        "aws_athena_workgroup",
        "aws_ecr_repository",
        "aws_backup_vault",
    }
)

# The middle of a chain: something that runs code and can carry a credential.
COMPUTE_TYPES = frozenset(
    {
        "aws_instance",
        "aws_launch_template",
        "aws_launch_configuration",
        "aws_lambda_function",
        "aws_ecs_task_definition",
        "aws_ecs_service",
        "aws_eks_cluster",
        "aws_autoscaling_group",
        "aws_batch_job_definition",
    }
)

# Hub types. EVERY resource in a VPC references the VPC and its route tables, so a
# path routed through one is not evidence of anything — it is the graph equivalent
# of "both resources are in AWS". They are excluded as intermediate hops, which is
# the difference between an exposure chain that means something and one that fires
# on every fixture.
TRANSIT_HUB_TYPES = frozenset(
    {
        "aws_vpc",
        "aws_route_table",
        "aws_default_route_table",
        "aws_route_table_association",
        "aws_default_vpc",
    }
)

# Connector types. The inverse of a transit hub: a node we route THROUGH for free.
#
# In a serverless architecture the data path is IAM-mediated, not network-mediated.
# A Lambda does not reference the DynamoDB table it reads; it references a role, and
# a SEPARATE aws_iam_role_policy references both the role and the table ARN. The edge
# exists, but it costs two hops of IAM plumbing to cross, which pushed the real chain
# (apigw -> lambda -> role -> policy -> table) past a 4-hop budget and made the
# exposure pass blind to the single most common AWS architecture.
#
# So IAM resources do not consume the hop budget. They are how permission flows, and
# permission is exactly what an exposure chain is made of — a path through a role and
# its policy is MORE interesting than a path through a subnet, not less.
CONNECTOR_TYPES = frozenset(
    {
        # IAM: how permission flows.
        "aws_iam_role",
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_role_policy_attachment",
        "aws_iam_policy_attachment",
        "aws_iam_user_policy",
        "aws_iam_user_policy_attachment",
        "aws_iam_group_policy",
        "aws_iam_instance_profile",
        # API Gateway wiring: how a request reaches a function. Same argument —
        # a method/integration is plumbing between the API and the Lambda, not a
        # hop in its own right.
        "aws_api_gateway_resource",
        "aws_api_gateway_method",
        "aws_api_gateway_integration",
        "aws_api_gateway_deployment",
        "aws_api_gateway_authorizer",
        "aws_apigatewayv2_route",
        "aws_apigatewayv2_integration",
        "aws_lambda_permission",
        "aws_lb_target_group_attachment",
    }
)

#: The hops that actually COST something: a real component on the path, as opposed
#: to the wiring between components. The budget is spent on these.
SUBSTANTIVE_TYPES = (
    INTERNET_EXPOSED_TYPES
    | DATA_TYPES
    | COMPUTE_TYPES
    | frozenset(
        {
            "aws_security_group",
            "aws_security_group_rule",
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_egress_rule",
            "aws_network_acl",
            "aws_subnet",
        }
    )
)

#: Observers. A CloudWatch alarm references the ALB it watches AND the SNS topic it
#: notifies, so an undirected walk will happily route "ALB -> alarm -> SNS -> another
#: alarm -> ECS service" and present it as an exposure path. Monitoring resources
#: WATCH the infrastructure; they are not a way to get through it. Excluded from
#: traversal for the same reason as a VPC, and they are the reason tf-04 was
#: reporting a chain that ran through its own alerting stack.
OBSERVER_TYPES = frozenset(
    {
        "aws_cloudwatch_metric_alarm",
        "aws_cloudwatch_dashboard",
        "aws_cloudwatch_composite_alarm",
        "aws_sns_topic_subscription",
        "aws_cloudwatch_log_metric_filter",
    }
)

#: Never routed through.
EXCLUDED_FROM_TRAVERSAL = TRANSIT_HUB_TYPES | OBSERVER_TYPES

OPEN_CIDRS = ("0.0.0.0/0", "::/0")

#: Budget in SUBSTANTIVE hops. Connectors (IAM, API-GW wiring) are free; hubs (VPC)
#: are excluded entirely.
MAX_CHAIN_DEPTH = 4

#: A hard cap on total path length, so "free" hops cannot make the search unbounded.
MAX_CHAIN_NODES = 8


def _is_resource_ref(ref: Dict[str, Any]) -> bool:
    label = (ref.get("label") or "")
    return bool(ref.get("name")) and label.startswith(_PROVIDER_PREFIXES)


def build_graph(resources: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the resource dependency graph from tfparse's ``references``.

    ``references`` is a list of ``{id, label, name}``. When ``label`` is a
    provider-prefixed resource type and ``name`` is non-empty, the edge is a real
    resource->resource dependency (``aws_athena_workgroup.main``). Refs to
    variables and locals have an empty ``name`` and are skipped.
    """
    by_address: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Set[str]] = {}
    reverse: Dict[str, Set[str]] = {}

    for resource in resources:
        location = resource.get("location") or {}
        address = location.get("resourceAddress") or resource.get("full_name") or ""
        if not address:
            continue
        by_address[address] = resource
        edges.setdefault(address, set())
        reverse.setdefault(address, set())

    for resource in resources:
        location = resource.get("location") or {}
        address = location.get("resourceAddress") or resource.get("full_name") or ""
        if not address:
            continue
        for ref in resource.get("references") or []:
            if not _is_resource_ref(ref):
                continue
            target = "%s.%s" % (ref["label"], ref["name"])
            if target == address:
                continue
            edges[address].add(target)
            reverse.setdefault(target, set()).add(address)
            edges.setdefault(target, set())

    return {"byAddress": by_address, "edges": edges, "reverse": reverse}


def _attrs_blob(resource: Optional[Dict[str, Any]]) -> str:
    if not resource:
        return ""
    try:
        return json.dumps(resource.get("attributes") or {})
    except (TypeError, ValueError):
        return ""


def is_public_facing(address: str, graph: Dict[str, Any]) -> bool:
    """A resource is public-facing if it IS an internet-exposed type, if it is
    wired to one, or if it carries an open CIDR."""
    resource = graph["byAddress"].get(address)
    location = (resource or {}).get("location") or {}
    rtype = location.get("resourceType") or ""

    if rtype in INTERNET_EXPOSED_TYPES:
        return True
    if any(cidr in _attrs_blob(resource) for cidr in OPEN_CIDRS):
        return True

    neighbors = graph["edges"].get(address, set()) | graph["reverse"].get(address, set())
    for neighbor in neighbors:
        n_res = graph["byAddress"].get(neighbor)
        n_type = ((n_res or {}).get("location") or {}).get("resourceType") or ""
        if n_type in INTERNET_EXPOSED_TYPES:
            return True
        if n_type in ("aws_security_group", "aws_security_group_rule") and any(
            cidr in _attrs_blob(n_res) for cidr in OPEN_CIDRS
        ):
            return True
    return False


def affects_critical_resource(address: str, graph: Dict[str, Any]) -> bool:
    resource = graph["byAddress"].get(address)
    rtype = ((resource or {}).get("location") or {}).get("resourceType") or ""
    return rtype in DATA_TYPES


def _neighbors(address: str, graph: Dict[str, Any]) -> Set[str]:
    return graph["edges"].get(address, set()) | graph["reverse"].get(address, set())


def connected_within(address: str, graph: Dict[str, Any], depth: int = 2) -> Set[str]:
    """Every resource within ``depth`` undirected hops of ``address``."""
    seen: Set[str] = {address}
    frontier: Set[str] = {address}
    for _ in range(max(0, depth)):
        nxt: Set[str] = set()
        for node in frontier:
            nxt |= _neighbors(node, graph) - seen
        if not nxt:
            break
        seen |= nxt
        frontier = nxt
    seen.discard(address)
    return seen


def find_exposure_chains(
    graph: Dict[str, Any], findings_by_address: Dict[str, List[Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    """SPEC §4.2 — the pass that finds resources which are individually fine and
    dangerous in combination.

    A chain is an undirected path

        <internet-exposed or open-CIDR resource>  ->  ...  ->  <data resource>

    where at least two distinct resources on the path carry a finding. The
    two-finding floor is what keeps this from reporting the entire VPC: a path with
    a single finding on it is just that finding, and it is already reported.

    The traversal is undirected, because reachability is not directional: the
    Terraform reference `aws_iam_role_policy -> aws_dynamodb_table` and the runtime
    data flow `lambda -> table` point opposite ways, and only the undirected view
    sees the actual path.

    Three rules keep undirected traversal from manufacturing nonsense:

      * ``TRANSIT_HUB_TYPES`` (VPC, route tables) are EXCLUDED. Everything in a VPC
        references the VPC, so any two resources are 2 hops apart through it.
      * ``CONNECTOR_TYPES`` (IAM) are FREE — routed through without consuming the
        hop budget. This is what makes the serverless (IAM-mediated) data path
        visible; without it the whole pattern is invisible.
      * The budget, ``MAX_CHAIN_DEPTH``, is counted in NON-CONNECTOR hops, so IAM
        plumbing can never crowd out a real hop.

    Checkov emits each hop as an independent medium and cannot see the path. This
    is the finding it structurally cannot produce.
    """

    def rtype(address: str) -> str:
        return (
            (graph["byAddress"].get(address) or {}).get("location") or {}
        ).get("resourceType") or ""

    entrypoints = [
        addr for addr in graph["byAddress"] if _is_chain_entrypoint(addr, graph)
    ]
    chains: List[Dict[str, Any]] = []
    # One chain per (entrypoint, terminus). BFS visits shortest-first, so the first
    # path found for a pair is the tightest way to tell that story; the other 70
    # permutations through the same plumbing are the same story, and printing all
    # of them trains the user to skip the section.
    seen_pairs: Set[Tuple[str, str]] = set()

    for start in sorted(entrypoints):
        # Bounded BFS over undirected edges. `cost` counts SUBSTANTIVE hops only.
        queue: List[Tuple[List[str], int]] = [([start], 0)]
        while queue:
            path, cost = queue.pop(0)
            node = path[-1]

            if len(path) > 1 and affects_critical_resource(node, graph):
                pair = (start, node)
                with_findings = [a for a in path if findings_by_address.get(a)]
                if len(with_findings) >= 2 and pair not in seen_pairs:
                    seen_pairs.add(pair)
                    chains.append(_describe_chain(path, graph, findings_by_address))
                # A data resource is a terminus. Do not chain through it.
                continue

            if cost >= MAX_CHAIN_DEPTH or len(path) >= MAX_CHAIN_NODES:
                continue
            for neighbor in sorted(_neighbors(node, graph)):
                if neighbor in path:
                    continue
                n_type = rtype(neighbor)
                if n_type in EXCLUDED_FROM_TRAVERSAL:
                    continue
                # Substantive hops cost; wiring (IAM, API-GW plumbing) is free.
                step = 1 if n_type in SUBSTANTIVE_TYPES else 0
                queue.append((path + [neighbor], cost + step))

    return _drop_subsumed_chains(chains)


def _drop_subsumed_chains(chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop any chain whose path is a strict suffix of a longer chain's path.

    `lb_listener -> ecs_service -> task_def -> ecr` and
    `lb -> lb_listener -> ecs_service -> task_def -> ecr` are the same story told
    from one hop further back. Report the one with more context, once.
    """
    paths = [tuple(c["path"]) for c in chains]
    keep = []
    for chain, path in zip(chains, paths):
        subsumed = any(
            other != path and len(other) > len(path) and other[-len(path):] == path
            for other in paths
        )
        if not subsumed:
            keep.append(chain)
    return keep


def _is_chain_entrypoint(address: str, graph: Dict[str, Any]) -> bool:
    """A chain must START at something genuinely reachable from the internet.

    Deliberately STRICTER than ``is_public_facing()`` (which is a scoring boost, and
    is happy to call a resource public-facing because it sits next to an ALB). For a
    chain start, adjacency is not enough: if every neighbor of an internet-facing
    resource were an entrypoint, an undirected walk would enumerate every permutation
    of the API-Gateway plumbing and bury the one real path in a few hundred
    near-identical ones. Measured: this rule is the difference between 356 chains on
    tf-02 and 3.
    """
    resource = graph["byAddress"].get(address)
    rtype = ((resource or {}).get("location") or {}).get("resourceType") or ""
    if rtype in EXCLUDED_FROM_TRAVERSAL or rtype in CONNECTOR_TYPES:
        return False
    if rtype in INTERNET_EXPOSED_TYPES:
        return True
    # Or it carries an open CIDR itself — an SG with 0.0.0.0/0 IS the front door.
    return any(cidr in _attrs_blob(resource) for cidr in OPEN_CIDRS)


def _describe_chain(
    path: List[str], graph: Dict[str, Any], findings_by_address: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    finding_ids: List[str] = []
    for address in path:
        for finding in findings_by_address.get(address, []):
            finding_ids.append(finding["id"])

    hop_types = []
    for address in path:
        rtype = ((graph["byAddress"].get(address) or {}).get("location") or {}).get(
            "resourceType"
        ) or "?"
        hop_types.append(rtype)

    terminus = path[-1]
    return {
        "id": "chain-" + "->".join(path),
        "path": path,
        "resourceTypes": hop_types,
        "entrypoint": path[0],
        "terminus": terminus,
        "findingIds": finding_ids,
        "summary": (
            "%s is reachable from the internet and is wired, via %s, to %s — a data "
            "resource. Each hop carries its own finding; the combination is an "
            "internet-to-data path that no single-resource rule can see."
            % (
                path[0],
                " -> ".join(path[1:-1]) or "a direct edge",
                terminus,
            )
        ),
    }


# ---------------------------------------------------------------------------
# Merge (SPEC §4.3)
# ---------------------------------------------------------------------------


class MergeIntegrityError(RuntimeError):
    """A Checkov finding did not survive the merge. This must never happen; it is
    the one invariant the whole hybrid design rests on."""


def _new_record(finding: Dict[str, Any], source: List[str]) -> Dict[str, Any]:
    """Copy a raw layer finding into a merged record, with the §5 schema defaults.

    ``exploitability`` and ``remediationComplexity`` are seeded to their schema
    defaults here rather than left absent: they are inputs to ``priorityScore``, and
    a finding that reaches the report with neither an LLM answer nor a default is a
    finding with an empty severity column.
    """
    record = copy.deepcopy(finding)
    record["source"] = list(source)
    record["concept"] = normalize_concept(finding)
    record.setdefault("exploitability", "moderate")
    record.setdefault("remediationComplexity", "moderate")
    record.setdefault("dependenciesToCheck", [])
    record.setdefault("testingSteps", [])
    return record


def _seed_severity(finding: Dict[str, Any], severity_map: SeverityMap) -> Dict[str, Any]:
    """Resolve the baseline severity from the checked-in map. The ONLY sanctioned
    source of a baseline severity (IMPLEMENTATION_PLAN §3)."""
    seed = severity_map.resolve(finding.get("ruleId") or "")
    finding["severity"] = seed.severity
    finding["severitySource"] = seed.source
    if not seed.is_mapped:
        finding["severityRationale"] = seed.rationale
    return finding


def _rescore(finding: Dict[str, Any]) -> Dict[str, Any]:
    finding["priorityScore"] = priority_score(
        finding.get("severity") or UNMAPPED,
        finding.get("exploitability") or "moderate",
        finding.get("remediationComplexity") or "moderate",
        affects_critical_resource=bool(finding.get("affectsCriticalResource")),
        is_public_facing=bool(finding.get("isPublicFacing")),
        verification=finding.get("verification") or "static-only",
    )
    finding["isQuickWin"] = is_quick_win(
        finding.get("severity") or UNMAPPED, finding.get("remediationComplexity") or "moderate"
    )
    return finding


#: Fields an LLM enrichment payload is allowed to write onto a finding.
#: Note what is NOT here: ``ruleId``, ``id``, ``location``, ``source``, ``severity``.
#: The model cannot rewrite a finding's identity, move its line numbers, or set its
#: severity directly (that goes through the +/-1 audited path below).
ENRICHABLE_FIELDS = (
    "businessImpact",
    "attackScenario",
    "remediationApproach",
    "dependenciesToCheck",
    "testingSteps",
    "exploitability",
    "remediationComplexity",
    "relatedFindings",
    "enrichmentTier",
)

REQUIRED_ENRICHMENT_FIELDS = (
    "businessImpact",
    "attackScenario",
    "remediationApproach",
    "dependenciesToCheck",
    "testingSteps",
    "exploitability",
    "remediationComplexity",
)


def apply_enrichment(
    finding: Dict[str, Any],
    payload: Dict[str, Any],
    severity_map: SeverityMap,
    suppression_log: Optional[List[Dict[str, Any]]] = None,
    injection_log: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Absorb one LLM enrichment payload into a finding.

    This function is the trust boundary. Everything the model said passes through
    it, and it can only ever ADD to a finding:

      * Only ``ENRICHABLE_FIELDS`` are copied. Identity, location and source are
        not writable by the model.
      * A severity change goes through ``findings.adjust_severity()``: +/-1 max, a
        written reason mandatory, never on an unmapped rule. A rejected adjustment
        is recorded on the finding and the baseline stands.
      * A suppression is a REQUEST. It is logged, flagged on the finding, and the
        finding is still returned. There is no branch here that returns None.
    """
    for key in ENRICHABLE_FIELDS:
        if key in payload and payload[key] not in (None, "", []):
            finding[key] = payload[key]

    proposed = payload.get("_severityAdjustment") or payload.get("severityAdjustment")
    reason = (
        payload.get("_severityAdjustmentReason")
        or payload.get("severityAdjustmentReason")
        or ""
    )
    if proposed and proposed in SEVERITIES and proposed != finding.get("severity"):
        seed = severity_map.resolve(finding.get("ruleId") or "")
        try:
            for key, value in adjust_severity(seed, proposed, reason).items():
                finding[key] = value
        except SeverityAdjustmentError as exc:
            # Refused, and the refusal is visible. A model that tries to walk a
            # critical down to informational does not get to do it quietly.
            finding["severityAdjustmentRejected"] = str(exc)
            print("severity adjustment REJECTED: %s" % exc, file=sys.stderr)

    suppression = payload.get("_suppressionRequest") or payload.get("suppressionRequest")
    if suppression:
        finding["llmSuppressionRequested"] = True
        finding["llmSuppressionReason"] = str(suppression).strip()
        entry = {
            "findingId": finding["id"],
            "ruleId": finding.get("ruleId"),
            "file": (finding.get("location") or {}).get("file"),
            "resourceAddress": (finding.get("location") or {}).get("resourceAddress"),
            "reason": finding["llmSuppressionReason"],
            "action": "LOGGED — finding still reported. The LLM cannot suppress a finding.",
        }
        if suppression_log is not None:
            suppression_log.append(entry)
        print(
            "LLM SUPPRESSION REQUEST (logged, NOT honored): %s on %s — %s"
            % (entry["ruleId"], entry["resourceAddress"], entry["reason"]),
            file=sys.stderr,
        )

    injection = payload.get("_injectionAttempt") or payload.get("injectionAttempt")
    if injection:
        finding["injectionAttemptDetected"] = str(injection).strip()
        entry = {
            "findingId": finding["id"],
            "file": (finding.get("location") or {}).get("file"),
            "quotedText": finding["injectionAttemptDetected"],
        }
        if injection_log is not None:
            injection_log.append(entry)
        print(
            "PROMPT-INJECTION ATTEMPT reported by analyst in %s: %s"
            % (entry["file"], entry["quotedText"]),
            file=sys.stderr,
        )

    return _rescore(finding)


def _assert_checkov_survives(
    checkov_findings: List[Dict[str, Any]], merged: List[Dict[str, Any]]
) -> None:
    """The invariant. Every Checkov finding is present in the merged output.

    Blowing up here is correct behavior: a scanner that quietly drops a
    deterministic finding is worse than a scanner that crashes, because the user
    reads the empty report as a clean bill of health.
    """
    merged_keys = {dedupe_key(f) for f in merged}
    lost = [f for f in checkov_findings if dedupe_key(f) not in merged_keys]
    if lost:
        raise MergeIntegrityError(
            "%d Checkov finding(s) did not survive the merge — this is a hard bug, not "
            "a suppression: %s"
            % (len(lost), ", ".join(sorted(f.get("ruleId", "?") for f in lost)))
        )


def merge(
    checkov_findings: List[Dict[str, Any]],
    llm_findings: Optional[List[Dict[str, Any]]] = None,
    *,
    parse_result: Optional[Dict[str, Any]] = None,
    severity_map: Optional[SeverityMap] = None,
    enrichments: Optional[Dict[str, Dict[str, Any]]] = None,
    related_depth: int = 2,
) -> Dict[str, Any]:
    """Join the two layers, dedupe, enrich, and build the exposure chains.

    ``enrichments`` maps a finding id -> enrichment payload (an already-parsed
    ``parse_deep_enrichment_response`` / ``parse_batch_enrichment_response``
    result). It is applied through ``apply_enrichment``, i.e. through the trust
    boundary — never spliced in directly.
    """
    severity_map = severity_map or SeverityMap.load()
    llm_findings = list(llm_findings or [])
    checkov_findings = list(checkov_findings or [])

    suppression_log: List[Dict[str, Any]] = []
    injection_log: List[Dict[str, Any]] = []

    merged: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    duplicates: List[Dict[str, Any]] = []

    # --- Checkov first. It owns the ID and the line range on any collision. ---
    for finding in checkov_findings:
        key = dedupe_key(finding)
        if key in merged:
            # Checkov can itself double-report a concept (e.g. the four
            # public-access-block rules on one bucket). One concept, one finding.
            duplicates.append({"key": list(key), "droppedRuleId": finding.get("ruleId")})
            existing = merged[key]
            existing.setdefault("coveringRuleIds", [existing["ruleId"]])
            existing["coveringRuleIds"].append(finding.get("ruleId"))
            continue
        # Deep copy: the merged record must not alias the adapter's location dict,
        # or an edit downstream would silently rewrite the input we later audit
        # against in _assert_checkov_survives.
        record = _new_record(finding, ["checkov"])
        merged[key] = _seed_severity(record, severity_map)

    # --- Then the LLM. It may only enrich an existing key, or add a new one. ---
    for finding in llm_findings:
        key = dedupe_key(finding)
        if key in merged:
            # SPEC §4.3: keep the Checkov rule ID and line precision, absorb the
            # LLM's enrichment. Concurrence is a confidence signal — say so.
            target = merged[key]
            if "checkov" in target["source"] and "llm" not in target["source"]:
                target["source"] = ["checkov", "llm"]
            payload = {k: v for k, v in finding.items() if k in ENRICHABLE_FIELDS}
            for passthrough in (
                "_severityAdjustment",
                "_severityAdjustmentReason",
                "_suppressionRequest",
                "_injectionAttempt",
            ):
                if passthrough in finding:
                    payload[passthrough] = finding[passthrough]
            apply_enrichment(target, payload, severity_map, suppression_log, injection_log)
            if finding.get("ruleId") and finding["ruleId"] != target["ruleId"]:
                target.setdefault("alsoReportedAs", []).append(finding["ruleId"])
        else:
            record = _new_record(finding, ["llm"])
            record.setdefault(
                "id",
                _finding_id(
                    record.get("ruleId") or "",
                    (record.get("location") or {}).get("file") or "",
                    (record.get("location") or {}).get("resourceAddress") or "",
                ),
            )
            merged[key] = _seed_severity(record, severity_map)

    findings_list = list(merged.values())

    # --- Graph-derived context: scoring boosts, relatedFindings, chains (§4.2) ---
    resources = (parse_result or {}).get("resources") or []
    graph = build_graph(resources)

    by_address: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings_list:
        address = (finding.get("location") or {}).get("resourceAddress") or ""
        if address:
            by_address.setdefault(address, []).append(finding)

    for finding in findings_list:
        address = (finding.get("location") or {}).get("resourceAddress") or ""
        if address and address in graph["byAddress"]:
            finding["isPublicFacing"] = is_public_facing(address, graph)
            finding["affectsCriticalResource"] = affects_critical_resource(address, graph)
            related: List[str] = list(finding.get("relatedFindings") or [])
            for neighbor in sorted(connected_within(address, graph, related_depth)):
                for other in by_address.get(neighbor, []):
                    if other["id"] != finding["id"] and other["id"] not in related:
                        related.append(other["id"])
            finding["relatedFindings"] = related
        finding.setdefault("isPublicFacing", False)
        finding.setdefault("affectsCriticalResource", False)
        finding.setdefault("relatedFindings", [])

    chains = find_exposure_chains(graph, by_address)
    chain_finding_ids = {fid for chain in chains for fid in chain["findingIds"]}
    for finding in findings_list:
        finding["inExposureChain"] = finding["id"] in chain_finding_ids

    # --- Enrichment payloads, through the trust boundary ---
    for finding in findings_list:
        payload = (enrichments or {}).get(finding["id"])
        if payload:
            apply_enrichment(finding, payload, severity_map, suppression_log, injection_log)
        else:
            _rescore(finding)

    findings_list.sort(
        key=lambda f: (-int(f.get("priorityScore") or 0), f.get("ruleId") or "", f["id"])
    )

    _assert_checkov_survives(checkov_findings, findings_list)

    checkov_count = sum(1 for f in findings_list if "checkov" in f["source"])
    return {
        "findings": findings_list,
        "exposureChains": chains,
        "suppressionLog": suppression_log,
        "injectionAttempts": injection_log,
        "duplicatesCollapsed": duplicates,
        "summary": {
            "total": len(findings_list),
            "fromCheckov": checkov_count,
            "fromLLMOnly": sum(1 for f in findings_list if f["source"] == ["llm"]),
            "corroborated": sum(1 for f in findings_list if len(f["source"]) > 1),
            "checkovInputCount": len(checkov_findings),
            "quickWins": sum(1 for f in findings_list if f.get("isQuickWin")),
            "unmapped": sum(1 for f in findings_list if f.get("severity") == UNMAPPED),
            "exposureChains": len(chains),
            "suppressionRequests": len(suppression_log),
            "injectionAttempts": len(injection_log),
        },
    }


def _finding_id(rule_id: str, file: str, resource_address: str) -> str:
    import hashlib

    key = "%s:%s:%s" % (rule_id, file, resource_address)
    return "finding-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Prompt emission — what the iac-security-analyst agent consumes
# ---------------------------------------------------------------------------


def build_enrichment_tasks(
    merged: Dict[str, Any], parse_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Tier the merged findings and emit one prompt per unit of work (§4.4).

    ``deep`` and ``batch`` become agent tasks. ``minimal`` is answered here, with
    no model call at all, by ``minimal_enrichment()`` — it still fills all seven
    contract fields.
    """
    findings = merged["findings"]
    by_id = {f["id"]: f for f in findings}
    tiers = tier_findings(findings)

    resources = (parse_result or {}).get("resources") or []
    graph = build_graph(resources)
    chains_by_finding: Dict[str, List[str]] = {}
    for chain in merged.get("exposureChains") or []:
        for fid in chain["findingIds"]:
            chains_by_finding.setdefault(fid, []).append(chain["summary"])

    tasks: List[Dict[str, Any]] = []

    for finding in tiers["deep"]:
        address = (finding.get("location") or {}).get("resourceAddress") or ""
        context = {
            "isPublicFacing": finding.get("isPublicFacing"),
            "affectsCriticalResource": finding.get("affectsCriticalResource"),
            "dependsOn": sorted(graph["edges"].get(address, set())),
            "dependedOnBy": sorted(graph["reverse"].get(address, set())),
            "exposureChain": (chains_by_finding.get(finding["id"]) or [None])[0],
        }
        candidate_related = [
            {
                "id": rid,
                "ruleId": by_id[rid].get("ruleId"),
                "resourceAddress": (by_id[rid].get("location") or {}).get("resourceAddress"),
                "title": by_id[rid].get("title"),
            }
            for rid in (finding.get("relatedFindings") or [])
            if rid in by_id
        ]
        tasks.append(
            {
                "tier": "deep",
                "findingIds": [finding["id"]],
                "prompt": deep_enrichment_prompt(
                    finding, context=context, candidate_related=candidate_related
                ),
            }
        )

    for group in tiers["batch"]:
        tasks.append(
            {
                "tier": "batch",
                "batchGroupId": group["batchGroupId"],
                "findingIds": [f["id"] for f in group["findings"]],
                "prompt": batch_enrichment_prompt(group),
            }
        )

    minimal = {f["id"]: minimal_enrichment(f) for f in tiers["minimal"]}

    return {
        "tasks": tasks,
        "minimalEnrichments": minimal,
        "tierCounts": {
            "deep": len(tiers["deep"]),
            "batch": len(tiers["batch"]),
            "batchFindings": sum(len(g["findings"]) for g in tiers["batch"]),
            "minimal": len(tiers["minimal"]),
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Merge Checkov + LLM findings, dedupe, enrich, build exposure chains."
    )
    parser.add_argument("--checkov", required=True, help="run_checkov.py output JSON")
    parser.add_argument("--parse", required=True, help="parse_iac.py --json-only output JSON")
    parser.add_argument("--llm", help="LLM findings/enrichment JSON (optional)")
    parser.add_argument(
        "--emit-prompts",
        action="store_true",
        help="Emit the tiered enrichment prompts instead of the merged findings.",
    )
    parser.add_argument("--severity-map", help="Override data/rule-severity.json")
    parser.add_argument("--out", default="-", help="Output path (default: stdout)")
    args = parser.parse_args(argv)

    try:
        checkov = _load(args.checkov)
        parse_result = _load(args.parse)
        llm_payload = _load(args.llm) if args.llm else {}
    except (OSError, json.JSONDecodeError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    llm_findings = (
        llm_payload.get("findings") if isinstance(llm_payload, dict) else llm_payload
    ) or []
    enrichments = llm_payload.get("enrichments") if isinstance(llm_payload, dict) else None

    try:
        severity_map = SeverityMap.load(args.severity_map)
        result = merge(
            checkov.get("findings") or [],
            llm_findings,
            parse_result=parse_result,
            severity_map=severity_map,
            enrichments=enrichments,
        )
        # Degradation is carried, never swallowed (SPEC §9.1).
        result["degraded"] = bool(checkov.get("degraded")) or bool(parse_result.get("degraded"))
        result["degradationReasons"] = [
            r
            for r in (
                checkov.get("degradationReason"),
                parse_result.get("degradationReason"),
            )
            if r
        ]
        if args.emit_prompts:
            result = build_enrichment_tasks(result, parse_result)
    except MergeIntegrityError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — a scan error exits 2 (SPEC §9.2)
        print("error: merge failed: %s" % exc, file=sys.stderr)
        return 2

    text = json.dumps(result, indent=2)
    if args.out == "-":
        sys.stdout.write(text + "\n")
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
