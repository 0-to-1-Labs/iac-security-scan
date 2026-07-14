"""
WS-1 acceptance tests for the vendored parser.

The contract under test:
  - tfparse runs UNCONDITIONALLY (no `.terraform/` gate, no `terraform init`)
  - every resource carries a §5-shaped `location` with real line numbers
  - `parseTier` / `degraded` are emitted top-level
  - modules, for_each and dynamic blocks resolve
  - fallback tiers are DEGRADED and say so
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PARSER_PATH = REPO_ROOT / "skills" / "iac-security-scan" / "scripts" / "parse_iac.py"
FIXTURES = REPO_ROOT / "tests" / "fixtures"

# Measured against the corpus during pre-flight (IMPLEMENTATION_PLAN §1.1).
EXPECTED_RESOURCE_COUNTS = {
    "tf-01-three-tier-webapp": 63,
    "tf-02-serverless-api": 51,
    "tf-03-data-lake": 61,
    "tf-04-container-platform": 79,
    "tf-05-cicd-pipeline": 39,
}

CONSTRUCTS_FIXTURE = "tf-parser-constructs"


def _load_parser():
    spec = importlib.util.spec_from_file_location("parse_iac", PARSER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


parse_iac = _load_parser()


@pytest.fixture(scope="module")
def parsed_corpus():
    return {
        name: parse_iac.parse_terraform(str(FIXTURES / name))
        for name in EXPECTED_RESOURCE_COUNTS
    }


# --------------------------------------------------------------------------
# Tier 1: tfparse, unconditionally, with no terraform init
# --------------------------------------------------------------------------

def test_no_terraform_init_anywhere_in_the_corpus():
    """The whole point: tfparse must work with no `.terraform/` directory."""
    for name in EXPECTED_RESOURCE_COUNTS:
        assert not (FIXTURES / name / ".terraform").exists(), (
            f"{name} has a .terraform/ dir — the no-init claim is untested"
        )


@pytest.mark.parametrize("fixture", sorted(EXPECTED_RESOURCE_COUNTS))
def test_fixture_uses_tfparse_tier_and_is_not_degraded(parsed_corpus, fixture):
    result = parsed_corpus[fixture]
    assert "error" not in result, result.get("error")
    assert result["parseTier"] == "tfparse"
    assert result["degraded"] is False
    assert result["lineProvenance"] is True
    assert result["format"] == "terraform"


@pytest.mark.parametrize("fixture", sorted(EXPECTED_RESOURCE_COUNTS))
def test_fixture_resource_counts(parsed_corpus, fixture):
    result = parsed_corpus[fixture]
    assert result["total_resources"] == EXPECTED_RESOURCE_COUNTS[fixture]
    assert len(result["resources"]) == EXPECTED_RESOURCE_COUNTS[fixture]


@pytest.mark.parametrize("fixture", sorted(EXPECTED_RESOURCE_COUNTS))
def test_one_hundred_percent_line_provenance(parsed_corpus, fixture):
    result = parsed_corpus[fixture]
    assert result["resources_missing_line_provenance"] == []
    assert result["resources_with_line_provenance"] == result["total_resources"]

    for resource in result["resources"]:
        loc = resource["location"]
        assert isinstance(loc["startLine"], int), resource["full_name"]
        assert isinstance(loc["endLine"], int), resource["full_name"]
        assert loc["startLine"] >= 1
        assert loc["endLine"] >= loc["startLine"]


@pytest.mark.parametrize("fixture", sorted(EXPECTED_RESOURCE_COUNTS))
def test_location_matches_spec_shape(parsed_corpus, fixture):
    """The §5 `location` contract. Other workstreams join against these names."""
    expected_keys = {
        "file", "startLine", "endLine", "resourceAddress", "resourceType", "service",
    }
    for resource in parsed_corpus[fixture]["resources"]:
        loc = resource["location"]
        assert set(loc) == expected_keys, resource["full_name"]

        # repo-relative, no leading slash, always
        assert not loc["file"].startswith("/")
        assert not loc["file"].startswith("./")
        assert not os.path.isabs(loc["file"])
        assert (FIXTURES / fixture / loc["file"]).exists()

        assert loc["resourceType"] == resource["type"]
        assert loc["resourceAddress"] == resource["full_name"]
        assert loc["resourceAddress"].find(loc["resourceType"]) != -1
        assert loc["service"] and "_" not in loc["service"].split("_")[0]


@pytest.mark.parametrize("fixture", sorted(EXPECTED_RESOURCE_COUNTS))
def test_line_ranges_point_at_the_real_resource_block(parsed_corpus, fixture):
    """Spot-check provenance is real, not fabricated: the start line must
    actually contain the resource declaration."""
    checked = 0
    for resource in parsed_corpus[fixture]["resources"]:
        loc = resource["location"]
        src = (FIXTURES / fixture / loc["file"]).read_text().splitlines()
        assert loc["endLine"] <= len(src), resource["full_name"]
        decl = src[loc["startLine"] - 1]
        assert f'"{loc["resourceType"]}"' in decl, (
            f'{resource["full_name"]} @ {loc["file"]}:{loc["startLine"]} -> {decl!r}'
        )
        checked += 1
    assert checked == EXPECTED_RESOURCE_COUNTS[fixture]


def test_service_derivation():
    assert parse_iac.derive_service("aws_s3_bucket") == "s3"
    assert parse_iac.derive_service("aws_cloudwatch_log_group") == "cloudwatch"
    assert parse_iac.derive_service("aws_iam_role") == "iam"
    assert parse_iac.derive_service("aws_api_gateway_rest_api") == "apigateway"


def test_references_are_preserved(parsed_corpus):
    """__tfmeta.references are free dependency edges for the exposure chain."""
    total_refs = 0
    for fixture in EXPECTED_RESOURCE_COUNTS:
        for resource in parsed_corpus[fixture]["resources"]:
            assert isinstance(resource["references"], list)
            total_refs += len(resource["references"])
    assert total_refs > 0, "no references survived from __tfmeta"


def test_data_sources_are_not_counted_as_resources(parsed_corpus):
    """tfparse flattens data sources into top-level keys named after the DATA
    type. Only __tfmeta.type distinguishes them. Miss it and counts inflate."""
    tf05 = parsed_corpus["tf-05-cicd-pipeline"]
    addresses = {r["full_name"] for r in tf05["resources"]}
    assert not any(a.startswith("data.") for a in addresses)
    assert any(
        d["address"] == "data.aws_caller_identity.current"
        for d in tf05["data_sources"]
    )


# --------------------------------------------------------------------------
# The constructs that infrabot's regex parser got wrong
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def constructs():
    return parse_iac.parse_terraform(str(FIXTURES / CONSTRUCTS_FIXTURE))


def test_constructs_fixture_actually_contains_the_constructs():
    """Guard the guard: if someone strips these from the fixture, fail loudly."""
    src = (FIXTURES / CONSTRUCTS_FIXTURE / "main.tf").read_text()
    assert "for_each" in src
    assert 'dynamic "ingress"' in src
    assert 'module "storage"' in src


def test_for_each_expands_to_one_resource_per_key(constructs):
    addresses = {r["full_name"] for r in constructs["resources"]}
    assert 'aws_s3_bucket.each["alpha"]' in addresses
    assert 'aws_s3_bucket.each["beta"]' in addresses

    for addr in ('aws_s3_bucket.each["alpha"]', 'aws_s3_bucket.each["beta"]'):
        r = next(x for x in constructs["resources"] if x["full_name"] == addr)
        assert r["location"]["startLine"] == 11
        assert r["location"]["resourceType"] == "aws_s3_bucket"
        assert r["location"]["service"] == "s3"


def test_for_each_expands_in_the_real_corpus(parsed_corpus):
    """tf-04's ECR repos are for_each'd over 3 keys."""
    tf04 = parsed_corpus["tf-04-container-platform"]
    ecr = [r for r in tf04["resources"] if r["type"] == "aws_ecr_repository"]
    assert len(ecr) == 3
    assert {r["full_name"] for r in ecr} == {
        'aws_ecr_repository.repos["api"]',
        'aws_ecr_repository.repos["webapp"]',
        'aws_ecr_repository.repos["worker"]',
    }
    assert all(isinstance(r["location"]["startLine"], int) for r in ecr)


def test_dynamic_blocks_expand(constructs):
    sg = next(
        r for r in constructs["resources"] if r["type"] == "aws_security_group"
    )
    ingress = sg["attributes"]["ingress"]
    assert isinstance(ingress, list)
    assert len(ingress) == 2  # one per element of var.ingress_ports
    ports = sorted(rule["from_port"] for rule in ingress)
    assert ports == [443, 8443]
    # and the 0.0.0.0/0 that a security scanner exists to find survives
    assert all("0.0.0.0/0" in rule["cidr_blocks"] for rule in ingress)


def test_dynamic_block_in_the_real_corpus(parsed_corpus):
    """tf-05's codepipeline uses a dynamic block; the resource must still parse
    with full line provenance."""
    tf05 = parsed_corpus["tf-05-cicd-pipeline"]
    pipeline = [r for r in tf05["resources"] if r["type"] == "aws_codepipeline"]
    assert pipeline
    assert all(isinstance(r["location"]["startLine"], int) for r in pipeline)


def test_module_resources_resolve(constructs):
    """Module contents must be traversed — resources inside a module are
    resources we are responsible for scanning."""
    addresses = {r["full_name"] for r in constructs["resources"]}
    assert "module.storage.aws_s3_bucket.inner" in addresses
    assert "module.storage.aws_s3_bucket_versioning.inner" in addresses

    inner = next(
        r for r in constructs["resources"]
        if r["full_name"] == "module.storage.aws_s3_bucket.inner"
    )
    assert inner["module"] is True
    assert inner["location"]["file"] == "modules/bucket/main.tf"
    assert inner["location"]["startLine"] == 5
    assert inner["location"]["endLine"] == 7
    assert inner["location"]["resourceType"] == "aws_s3_bucket"
    assert inner["name"] == "inner"


def test_module_block_is_recorded(constructs):
    assert any(m["name"] == "storage" for m in constructs["modules"])


# --------------------------------------------------------------------------
# Degradation: a fallback is a DEGRADED SCAN, not graceful degradation
# --------------------------------------------------------------------------

def test_hcl2_fallback_is_degraded(monkeypatch):
    monkeypatch.setenv("IAC_PARSER_FORCE_TIER", "hcl2")
    result = parse_iac.parse_terraform(str(FIXTURES / "tf-03-data-lake"))

    assert result["parseTier"] == "hcl2"
    assert result["degraded"] is True
    assert result["lineProvenance"] is False
    assert result["resources_with_line_provenance"] == 0
    assert "degradationReason" in result
    assert result["resources"], "hcl2 tier still has to return resources"

    # The whole reason it's degraded: no line numbers.
    for resource in result["resources"]:
        assert resource["location"]["startLine"] is None
        assert resource["location"]["endLine"] is None
        assert not resource["location"]["file"].startswith("/")


def test_regex_fallback_is_degraded(monkeypatch):
    monkeypatch.setenv("IAC_PARSER_FORCE_TIER", "regex")
    result = parse_iac.parse_terraform(str(FIXTURES / "tf-03-data-lake"))

    assert result["parseTier"] == "regex"
    assert result["degraded"] is True
    assert result["lineProvenance"] is False
    assert "degradationReason" in result
    for resource in result["resources"]:
        assert resource["location"]["startLine"] is None


def test_degraded_tiers_lose_the_constructs(monkeypatch):
    """Documents WHY a fallback is a degraded scan and not merely a slower one:
    the hcl2 tier does not expand for_each and never enters the module."""
    monkeypatch.setenv("IAC_PARSER_FORCE_TIER", "hcl2")
    result = parse_iac.parse_terraform(str(FIXTURES / CONSTRUCTS_FIXTURE))
    addresses = {r["full_name"] for r in result["resources"]}

    assert 'aws_s3_bucket.each["alpha"]' not in addresses  # not expanded
    assert "module.storage.aws_s3_bucket.inner" not in addresses  # not traversed
    assert result["degraded"] is True


# --------------------------------------------------------------------------
# CLI contract (§8.2): format keywords, JSON on stdout, non-zero exit on error
# --------------------------------------------------------------------------

def _run_cli(*args):
    return subprocess.run(
        [sys.executable, str(PARSER_PATH), *args],
        capture_output=True, text=True, timeout=180,
    )


def test_cli_emits_json_and_exits_zero():
    proc = _run_cli("terraform", str(FIXTURES / "tf-03-data-lake"))
    assert proc.returncode == 0
    assert "PARSE RESULT:" in proc.stdout
    payload = proc.stdout.split("=" * 60)[-1]
    result = json.loads(payload)
    assert result["parseTier"] == "tfparse"
    assert result["degraded"] is False
    assert result["total_resources"] == 61


def test_cli_json_only_stdout_is_pure_json():
    proc = _run_cli("terraform", str(FIXTURES / "tf-03-data-lake"), "--json-only")
    assert proc.returncode == 0
    result = json.loads(proc.stdout)
    assert result["total_resources"] == 61
    assert result["resources"][0]["location"]["startLine"] >= 1


def test_cli_unsupported_format_exits_nonzero():
    proc = _run_cli("pulumi", str(FIXTURES / "tf-03-data-lake"))
    assert proc.returncode != 0


def test_cli_missing_path_exits_nonzero():
    proc = _run_cli("terraform", str(FIXTURES / "does-not-exist"))
    assert proc.returncode != 0


def test_cli_no_args_exits_nonzero():
    proc = _run_cli()
    assert proc.returncode != 0


def test_format_keywords_preserved():
    """Phase 3 depends on these being untouched."""
    src = PARSER_PATH.read_text()
    for keyword in ("terraform", "cloudformation", "kubernetes", "docker-compose"):
        assert f'iac_format == "{keyword}"' in src


def test_degraded_cli_run_prints_an_unmissable_banner(monkeypatch):
    env = dict(os.environ, IAC_PARSER_FORCE_TIER="hcl2")
    proc = subprocess.run(
        [sys.executable, str(PARSER_PATH), "terraform", str(FIXTURES / "tf-03-data-lake")],
        capture_output=True, text=True, timeout=180, env=env,
    )
    assert proc.returncode == 0
    assert "DEGRADED SCAN" in proc.stdout
