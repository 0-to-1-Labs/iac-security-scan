"""
WS-12 acceptance tests: line provenance for the YAML-based formats.

WS-1 gave the Terraform path a first-class §5 `location` object plus top-level
`parseTier` / `degraded`. That work was Terraform-only. Everything downstream --
SARIF, the report's file:line, the finding schema -- joins on `location`, so the
three YAML formats (CloudFormation, Kubernetes, Docker Compose) need the exact
same shape. This module proves they now emit it.

The contract under test, per format:
  - the FULL tier (cfn-lint for CFN, ruamel for K8s/Compose) runs and is NOT
    degraded, with a real startLine on every resource;
  - the `location` object is field-for-field identical to the Terraform path's;
  - the pre-existing contract (resource keys, JSON on stdout, format keywords) is
    preserved;
  - a fallback with no line numbers is a DEGRADED scan and says so loudly.
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

CFN_FIXTURES = [
    "cfn-01-wordpress-ec2-rds",
    "cfn-02-ml-platform",
    "cfn-03-iot-ingestion",
    "cfn-04-event-driven",
    "cfn-05-static-website",
]

# Resource counts measured against the copied fixtures with cfn-lint installed.
EXPECTED_CFN_RESOURCE_COUNTS = {
    "cfn-01-wordpress-ec2-rds": 39,
    "cfn-02-ml-platform": 45,
    "cfn-03-iot-ingestion": 23,
    "cfn-04-event-driven": 25,
    "cfn-05-static-website": 17,
}

LOCATION_KEYS = {
    "file",
    "startLine",
    "endLine",
    "resourceAddress",
    "resourceType",
    "service",
}


def _load_parser():
    spec = importlib.util.spec_from_file_location("parse_iac", PARSER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


parse_iac = _load_parser()


# ===========================================================================
# CloudFormation -- cfn-lint FULL tier
# ===========================================================================


@pytest.fixture(scope="module")
def cfn_corpus():
    return {
        name: parse_iac.parse_cloudformation(str(FIXTURES / name / "template.yaml"))
        for name in CFN_FIXTURES
    }


def test_cfn_lint_is_available():
    """The full tier depends on it. If it is gone the whole premise degrades."""
    assert parse_iac.CFNLINT_AVAILABLE, "cfn-lint must be installed for CFN provenance"


@pytest.mark.parametrize("fixture", CFN_FIXTURES)
def test_cfn_uses_cfnlint_tier_and_is_not_degraded(cfn_corpus, fixture):
    result = cfn_corpus[fixture]
    assert "error" not in result, result.get("error")
    assert result["parseTier"] == "cfn-lint"
    assert result["degraded"] is False
    assert result["lineProvenance"] is True


@pytest.mark.parametrize("fixture", CFN_FIXTURES)
def test_cfn_resource_counts(cfn_corpus, fixture):
    result = cfn_corpus[fixture]
    assert len(result["resources"]) == EXPECTED_CFN_RESOURCE_COUNTS[fixture]


@pytest.mark.parametrize("fixture", CFN_FIXTURES)
def test_cfn_one_hundred_percent_line_provenance(cfn_corpus, fixture):
    result = cfn_corpus[fixture]
    resources = result["resources"]
    with_lines = [r for r in resources if r["location"]["startLine"]]
    assert len(with_lines) == len(resources), (
        f"{fixture}: {len(resources) - len(with_lines)} resources missing a startLine"
    )
    assert result["resources_missing_line_provenance"] == []


@pytest.mark.parametrize("fixture", CFN_FIXTURES)
def test_cfn_location_matches_spec_shape(cfn_corpus, fixture):
    """The location object is the join key -- it must be exactly the §5 shape the
    Terraform path emits, no more fields, no fewer."""
    for r in cfn_corpus[fixture]["resources"]:
        loc = r["location"]
        assert set(loc) == LOCATION_KEYS, set(loc) ^ LOCATION_KEYS
        assert loc["file"] == "template.yaml", loc["file"]
        assert isinstance(loc["startLine"], int) and loc["startLine"] > 0
        assert isinstance(loc["endLine"], int) and loc["endLine"] >= loc["startLine"]
        # resourceAddress is the logical ID for CFN (SPEC §5).
        assert loc["resourceAddress"] == r["logical_id"]
        assert loc["resourceType"] == r["type"]
        assert loc["service"]


@pytest.mark.parametrize("fixture", CFN_FIXTURES)
def test_cfn_line_range_points_at_the_real_block(cfn_corpus, fixture):
    """Spot-proof the marks are real: the logical ID must appear on its startLine."""
    template = (FIXTURES / fixture / "template.yaml").read_text().splitlines()
    for r in cfn_corpus[fixture]["resources"]:
        start = r["location"]["startLine"]
        line = template[start - 1]
        assert r["logical_id"] in line, (
            f"{fixture}: {r['logical_id']} expected on line {start}, found: {line!r}"
        )


def test_cfn_preserves_the_existing_resource_contract(cfn_corpus):
    """WS-1 kept the CFN contract identical; WS-12 only ADDS location. The
    pre-existing keys must all survive."""
    r = cfn_corpus["cfn-05-static-website"]["resources"][0]
    for key in ("logical_id", "type", "provider", "service", "properties",
                "depends_on", "metadata"):
        assert key in r, f"lost contract key {key}"


def test_cfn_yaml_fallback_is_degraded():
    """cfn-lint absent (or failing) -> PyYAML tier, NO line numbers, and it must
    announce itself as a degraded scan, not a clean one."""
    result = parse_iac.parse_cloudformation_with_yaml(
        str(FIXTURES / "cfn-05-static-website" / "template.yaml")
    )
    assert result["parseTier"] == "yaml"
    assert result["degraded"] is True
    assert result["lineProvenance"] is False
    assert result["degradationReason"]
    # Locations still present (contract), but with no line numbers.
    for r in result["resources"]:
        assert r["location"]["startLine"] is None
        assert set(r["location"]) == LOCATION_KEYS


# ===========================================================================
# Kubernetes -- ruamel FULL tier
# ===========================================================================


K8S_MANIFEST = """apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: prod
spec:
  selector:
    app: web
  ports:
    - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-deploy
  namespace: prod
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
"""


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return p


def test_kubernetes_full_tier_has_line_provenance(tmp_path):
    _write(tmp_path, "app.yaml", K8S_MANIFEST)
    result = parse_iac.parse_kubernetes(str(tmp_path))
    assert result["parseTier"] == "ruamel"
    assert result["degraded"] is False
    assert result["lineProvenance"] is True
    assert result["resources_missing_line_provenance"] == []

    by_addr = {r["location"]["resourceAddress"]: r for r in result["resources"]}
    assert set(by_addr) == {"Service/web", "Deployment/web-deploy"}
    for addr, r in by_addr.items():
        loc = r["location"]
        assert set(loc) == LOCATION_KEYS
        assert loc["file"] == "app.yaml"
        assert loc["startLine"] and loc["endLine"] >= loc["startLine"]
        assert loc["resourceType"] == r["kind"]
        assert loc["service"] == "kubernetes"

    # The Service starts before the Deployment (document order preserved).
    assert (
        by_addr["Service/web"]["location"]["startLine"]
        < by_addr["Deployment/web-deploy"]["location"]["startLine"]
    )


def test_kubernetes_startline_points_at_the_document(tmp_path):
    p = _write(tmp_path, "app.yaml", K8S_MANIFEST)
    lines = p.read_text().splitlines()
    result = parse_iac.parse_kubernetes(str(tmp_path))
    for r in result["resources"]:
        start = r["location"]["startLine"]
        # The document's first line is its apiVersion.
        assert "apiVersion" in lines[start - 1], lines[start - 1]


def test_kubernetes_degrades_without_ruamel(tmp_path, monkeypatch):
    _write(tmp_path, "app.yaml", K8S_MANIFEST)
    monkeypatch.setattr(parse_iac, "RUAMEL_AVAILABLE", False)
    result = parse_iac.parse_kubernetes(str(tmp_path))
    assert result["parseTier"] == "yaml"
    assert result["degraded"] is True
    assert result["lineProvenance"] is False
    assert result["degradationReason"]
    # The data still parses; only the line numbers are gone.
    for r in result["resources"]:
        assert r["location"]["startLine"] is None
        assert set(r["location"]) == LOCATION_KEYS


# ===========================================================================
# Docker Compose -- ruamel FULL tier
# ===========================================================================


COMPOSE_FILE = """version: '3.8'
services:
  web:
    image: nginx:1.25
    ports:
      - "80:80"
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: hunter2
"""


def test_compose_full_tier_has_line_provenance(tmp_path):
    p = _write(tmp_path, "docker-compose.yaml", COMPOSE_FILE)
    result = parse_iac.parse_docker_compose(str(p))
    assert result["parseTier"] == "ruamel"
    assert result["degraded"] is False
    assert result["lineProvenance"] is True
    assert result["resources_missing_line_provenance"] == []

    by_name = {s["location"]["resourceAddress"]: s for s in result["services"]}
    assert set(by_name) == {"web", "db"}
    for name, s in by_name.items():
        loc = s["location"]
        assert set(loc) == LOCATION_KEYS
        assert loc["file"] == "docker-compose.yaml"
        assert loc["startLine"] and loc["endLine"] >= loc["startLine"]
        assert loc["resourceAddress"] == s["name"]
        assert loc["service"] == "docker-compose"
    assert (
        by_name["web"]["location"]["startLine"]
        < by_name["db"]["location"]["startLine"]
    )


def test_compose_startline_points_at_the_service_key(tmp_path):
    p = _write(tmp_path, "docker-compose.yaml", COMPOSE_FILE)
    lines = p.read_text().splitlines()
    result = parse_iac.parse_docker_compose(str(p))
    for s in result["services"]:
        start = s["location"]["startLine"]
        assert s["name"] + ":" in lines[start - 1].strip(), lines[start - 1]


def test_compose_degrades_without_ruamel(tmp_path, monkeypatch):
    p = _write(tmp_path, "docker-compose.yaml", COMPOSE_FILE)
    monkeypatch.setattr(parse_iac, "RUAMEL_AVAILABLE", False)
    result = parse_iac.parse_docker_compose(str(p))
    assert result["parseTier"] == "yaml"
    assert result["degraded"] is True
    assert result["lineProvenance"] is False
    assert result["degradationReason"]
    for s in result["services"]:
        assert s["location"]["startLine"] is None
        assert set(s["location"]) == LOCATION_KEYS


# ===========================================================================
# CLI contract (JSON on stdout, non-zero exit on error) -- preserved
# ===========================================================================


def test_cfn_cli_json_only_stdout_is_pure_json():
    proc = subprocess.run(
        [
            sys.executable,
            str(PARSER_PATH),
            "cloudformation",
            str(FIXTURES / "cfn-05-static-website" / "template.yaml"),
            "--json-only",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)  # pure JSON on stdout, chatter on stderr
    assert payload["parseTier"] == "cfn-lint"
    assert payload["degraded"] is False
    assert all(r["location"]["startLine"] for r in payload["resources"])
