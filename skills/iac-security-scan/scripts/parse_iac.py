#!/usr/bin/env python3
"""
IaC Parser
Parses Infrastructure as Code files and extracts resource information.
Supports: Terraform, CloudFormation, Kubernetes, Docker Compose
Accepts: Local paths or GitHub repository URLs

Vendored from iac-diagram-generator with three changes for iac-security-scan:

  1. tfparse is tried UNCONDITIONALLY (the old `.terraform/` existence gate is
     gone). tfparse works fine with no `terraform init`, and it is the only tier
     that yields line numbers.
  2. Every Terraform resource record carries a first-class `location` object
     (file / startLine / endLine / resourceAddress / resourceType / service),
     plus `references` lifted out of tfparse's `__tfmeta`.
  3. The result carries top-level `parseTier` ("tfparse" | "hcl2" | "regex") and
     `degraded` (bool). Any tier below tfparse yields NO line numbers, which
     means no SARIF and no patches. That is a DEGRADED SCAN, not graceful
     degradation, and it must be reported as one.

The rest of the contract is unchanged: same format keywords, JSON on stdout,
non-zero exit on error, GitHub URL handling.
"""

import os
import sys
import json
import glob as file_glob
import tempfile
import shutil
import subprocess
import re
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is not installed.")
    print("Please install it with: pip install pyyaml")
    sys.exit(1)

# tfparse: accurate Terraform parsing with line provenance.
# NOTE: it does NOT require `terraform init`. Always try it first.
try:
    from tfparse import load_from_path as tfparse_load
    TFPARSE_AVAILABLE = True
except ImportError:
    TFPARSE_AVAILABLE = False

# Test/debug escape hatch: force a specific parser tier.
#   IAC_PARSER_FORCE_TIER=hcl2|regex
FORCE_TIER_ENV = "IAC_PARSER_FORCE_TIER"

# Terraform block types that are not resources.
TF_NON_RESOURCE_BLOCKS = (
    'variable', 'output', 'locals', 'terraform', 'provider', 'module', 'data',
)

# Services whose Terraform type prefix spans more than one underscore token.
SERVICE_ALIASES = {
    'api_gateway': 'apigateway',
    'apigatewayv2': 'apigatewayv2',
    'elasticache': 'elasticache',
    'load_balancer': 'elb',
}

# Optional: python-hcl2 for HCL2 parsing without terraform init
try:
    import hcl2
    HCL2_AVAILABLE = True
except ImportError:
    HCL2_AVAILABLE = False

# Optional: cfn-lint for accurate CloudFormation parsing
try:
    from cfnlint.decode import cfn_yaml, cfn_json
    from cfnlint.template import Template as CfnTemplate
    CFNLINT_AVAILABLE = True
except ImportError:
    CFNLINT_AVAILABLE = False

# Optional: ruamel.yaml for line-preserving YAML parsing (Kubernetes / Compose).
# This is to the YAML formats what tfparse is to Terraform: the ONLY tier that
# yields per-resource line provenance. Its round-trip loader records `.lc.line`
# on every node. Absent it, the YAML formats fall back to PyYAML, which has no
# line numbers -> a DEGRADED scan (no SARIF, no patches), reported as one.
try:
    from ruamel.yaml import YAML as _RuamelYAML
    RUAMEL_AVAILABLE = True
except ImportError:
    RUAMEL_AVAILABLE = False


def is_github_url(path):
    """Check if the path is a GitHub URL."""
    github_patterns = [
        r'^https?://github\.com/[\w\-\.]+/[\w\-\.]+',
        r'^git@github\.com:[\w\-\.]+/[\w\-\.]+',
        r'^github\.com/[\w\-\.]+/[\w\-\.]+',
    ]
    for pattern in github_patterns:
        if re.match(pattern, path):
            return True
    return False


def normalize_github_url(url):
    """Normalize GitHub URL to HTTPS clone format."""
    # Remove trailing slashes, then a single trailing ".git" suffix.
    # (rstrip('.git') would strip any trailing '.', 'g', 'i', 't' chars,
    # corrupting repo names like "...config" or "...integration".)
    url = url.rstrip('/')
    if url.endswith('.git'):
        url = url[:-len('.git')]

    # Handle different formats
    if url.startswith('git@github.com:'):
        # git@github.com:user/repo -> https://github.com/user/repo
        url = url.replace('git@github.com:', 'https://github.com/')
    elif url.startswith('github.com/'):
        # github.com/user/repo -> https://github.com/user/repo
        url = 'https://' + url
    elif not url.startswith('http'):
        url = 'https://' + url

    return url + '.git'


def clone_repository(url, subpath=None):
    """
    Clone a GitHub repository to a temporary directory.

    Args:
        url: GitHub repository URL
        subpath: Optional subdirectory within the repo to use

    Returns:
        tuple: (temp_dir, target_path) where target_path is the directory to parse
    """
    normalized_url = normalize_github_url(url)

    # Create temp directory
    temp_dir = tempfile.mkdtemp(prefix='iac_parser_')

    print(f"Cloning repository: {normalized_url}")
    print(f"  Temp directory: {temp_dir}")

    try:
        # Clone with depth=1 for speed (we only need latest files)
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', normalized_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=120  # 2 minute timeout
        )

        if result.returncode != 0:
            print(f"ERROR: Git clone failed: {result.stderr}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None, None

        print("  Clone successful!")

        # Determine target path
        target_path = temp_dir
        if subpath:
            target_path = os.path.join(temp_dir, subpath.lstrip('/'))
            if not os.path.exists(target_path):
                print(f"ERROR: Subpath does not exist in repo: {subpath}")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return None, None

        return temp_dir, target_path

    except subprocess.TimeoutExpired:
        print("ERROR: Git clone timed out (120s)")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, None
    except FileNotFoundError:
        print("ERROR: Git is not installed or not in PATH")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, None
    except Exception as e:
        print(f"ERROR: Failed to clone repository: {str(e)}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, None


def cleanup_temp_dir(temp_dir):
    """Clean up temporary directory."""
    if temp_dir and os.path.exists(temp_dir):
        print(f"\nCleaning up temp directory: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)


# CloudFormation YAML intrinsic function constructors
def cloudformation_constructor(loader, tag_suffix, node):
    """Generic constructor for CloudFormation intrinsic functions."""
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    elif isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node)}
    elif isinstance(node, yaml.MappingNode):
        return {tag_suffix: loader.construct_mapping(node)}
    else:
        return {tag_suffix: None}


# Register CloudFormation intrinsic functions
yaml.add_multi_constructor('!', cloudformation_constructor, Loader=yaml.SafeLoader)


def normalize_repo_path(file_path, root=None):
    """
    Normalize a source file path to a repo-relative POSIX path with NO leading
    slash. This is the join key every downstream consumer (Checkov adapter,
    SARIF emitter, patcher) keys off, so it has exactly one shape.
    """
    if not file_path:
        return ""

    p = str(file_path).replace("\\", "/")

    if root:
        root_abs = os.path.abspath(root)
        if os.path.isfile(root_abs):
            root_abs = os.path.dirname(root_abs)
        if os.path.isabs(p):
            try:
                p = os.path.relpath(os.path.abspath(p), root_abs).replace("\\", "/")
            except ValueError:
                pass
        else:
            # Strip a redundant leading copy of the scan root, if present.
            root_rel = str(root).replace("\\", "/").rstrip("/")
            if root_rel and p.startswith(root_rel + "/"):
                p = p[len(root_rel) + 1:]

    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def derive_service(resource_type):
    """
    Derive the cloud service from a Terraform resource type.
      aws_s3_bucket        -> s3
      aws_cloudwatch_...   -> cloudwatch
      aws_api_gateway_...  -> apigateway
    """
    if not resource_type or "_" not in resource_type:
        return resource_type or "unknown"

    parts = resource_type.split("_")
    remainder = parts[1:]
    if not remainder:
        return "unknown"

    two = "_".join(remainder[:2])
    if two in SERVICE_ALIASES:
        return SERVICE_ALIASES[two]
    if remainder[0] in SERVICE_ALIASES:
        return SERVICE_ALIASES[remainder[0]]
    return remainder[0]


def split_resource_address(address, resource_type):
    """
    Split a tfparse address into (resourceType, resourceName).

    Handles module-nested and for_each-expanded addresses:
      aws_s3_bucket.each["alpha"]                -> (aws_s3_bucket, each["alpha"])
      module.storage.aws_s3_bucket.inner         -> (aws_s3_bucket, inner)
    """
    if not address:
        return resource_type, "unknown"

    marker = f"{resource_type}."
    idx = address.find(marker)
    if idx == -1:
        return resource_type, address
    return resource_type, address[idx + len(marker):]


def build_location(file_path, start_line, end_line, address, resource_type, root=None):
    """Build the §5 `location` object. The public contract — do not improvise."""
    return {
        "file": normalize_repo_path(file_path, root),
        "startLine": start_line,
        "endLine": end_line,
        "resourceAddress": address,
        "resourceType": resource_type,
        "service": derive_service(resource_type),
    }


def build_yaml_location(file_path, start_line, end_line, address, resource_type,
                        service, root=None):
    """The same §5 `location` shape as build_location, but for the YAML-based
    formats (CloudFormation / Kubernetes / Docker Compose) whose `service` is not
    derivable from an AWS `aws_*` resource-type slug. Field-for-field identical to
    what the Terraform path emits — downstream code (SARIF, report, findings)
    joins on it, so it must not improvise fields.
    """
    # Absolute-ize the file so normalize_repo_path can always take the relpath
    # against the scan root — including the single-file case (CFN template,
    # compose file) where the given path IS the root, which the relative-path
    # branch would otherwise leave un-shortened.
    norm_file = os.path.abspath(file_path) if file_path else file_path
    return {
        "file": normalize_repo_path(norm_file, root),
        "startLine": start_line,
        "endLine": end_line,
        "resourceAddress": address,
        "resourceType": resource_type,
        "service": service,
    }


def _mark_line(node, attr):
    """1-based line for a cfn-lint decoded node's start/end mark, or None.

    cfn-lint decorates every decoded node with 0-based `start_mark` / `end_mark`.
    """
    mark = getattr(node, attr, None)
    line = getattr(mark, "line", None)
    return (line + 1) if line is not None else None


def cfn_resource_line_index(resources_node):
    """{logical_id: (startLine, endLine)} 1-based, from cfn-lint's line marks.

    `startLine` is the line of the logical-ID key (what Checkov reports too).
    `endLine` is the resource value's end mark, capped at the next resource's
    start so trailing comments/blank lines don't bleed one block into the next.
    Returns {} if the node carries no marks (e.g. a plain dict from a JSON reload).
    """
    entries = []
    try:
        keys = list(resources_node.keys())
    except AttributeError:
        return {}
    for key in keys:
        value = resources_node[key]
        start = _mark_line(key, "start_mark")
        raw_end = getattr(getattr(value, "end_mark", None), "line", None)
        entries.append((str(key), start, raw_end))

    index = {}
    for i, (lid, start, raw_end) in enumerate(entries):
        end = raw_end
        next_start = entries[i + 1][1] if i + 1 < len(entries) else None
        if next_start is not None:
            capped = next_start - 1
            if end is None or end > capped:
                end = capped
        if start is not None and end is not None and end < start:
            end = start
        index[lid] = (start, end)
    return index


def _file_line_count(path):
    try:
        with open(path, "r") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return None


def kubernetes_line_index(yaml_file):
    """{(kind, name): (startLine, endLine)} 1-based for one manifest file.

    A Kubernetes resource IS a YAML document, so its block spans from the
    document's first line to the line before the next document (or EOF for the
    last). Returns None when ruamel is unavailable (the DEGRADED signal).
    """
    if not RUAMEL_AVAILABLE:
        return None
    try:
        ry = _RuamelYAML()
        with open(yaml_file, "r") as fh:
            docs = list(ry.load_all(fh))
    except Exception:
        return None

    total = _file_line_count(yaml_file)
    starts = []
    for doc in docs:
        line = getattr(getattr(doc, "lc", None), "line", None)
        starts.append((line + 1) if line is not None else None)

    index = {}
    for i, doc in enumerate(docs):
        if not isinstance(doc, dict):
            continue
        start = starts[i]
        end = None
        for j in range(i + 1, len(starts)):
            if starts[j] is not None:
                end = starts[j] - 1
                break
        if end is None:
            end = total
        if start is not None and end is not None and end < start:
            end = start
        kind = doc.get("kind")
        name = (doc.get("metadata") or {}).get("name")
        index[(str(kind), str(name))] = (start, end)
    return index


def compose_line_index(path):
    """{service_name: (startLine, endLine)} 1-based for a Docker Compose file.

    Each service block runs from its key line to the line before the next
    service (or EOF for the last). Returns None when ruamel is unavailable.
    """
    if not RUAMEL_AVAILABLE:
        return None
    try:
        ry = _RuamelYAML()
        with open(path, "r") as fh:
            data = ry.load(fh)
    except Exception:
        return None
    if not isinstance(data, dict):
        return {}
    services = data.get("services")
    if not isinstance(services, dict):
        return {}

    total = _file_line_count(path)
    lc = getattr(services, "lc", None)
    lc_data = getattr(lc, "data", None) if lc is not None else None

    key_lines = {}
    for name in services.keys():
        info = lc_data.get(name) if isinstance(lc_data, dict) else None
        key_lines[str(name)] = (info[0] + 1) if info else None

    ordered = sorted(
        ((n, s) for n, s in key_lines.items() if s is not None),
        key=lambda pair: pair[1],
    )
    index = {}
    for idx, (name, start) in enumerate(ordered):
        end = ordered[idx + 1][1] - 1 if idx + 1 < len(ordered) else total
        if end is not None and end < start:
            end = start
        index[name] = (start, end)
    for name, start in key_lines.items():
        index.setdefault(name, (start, start))
    return index


def parse_terraform(path):
    """
    Parse Terraform files (.tf) to extract resources.

    Tiered, but not equal tiers:
      1. tfparse  — ALWAYS tried first. No `terraform init` required.
                    The ONLY tier that yields line provenance.       [FULL]
      2. python-hcl2 — resources, NO line numbers.                   [DEGRADED]
      3. regex       — best effort, NO line numbers.                 [DEGRADED]

    A fallback is a degraded scan: without line numbers there is no SARIF and no
    patching. Callers must surface `degraded: true` loudly.
    """
    print(f"Parsing Terraform files in: {path}")

    forced = os.environ.get(FORCE_TIER_ENV, "").strip().lower()
    if forced:
        print(f"  {FORCE_TIER_ENV}={forced} — parser tier forced (test/debug path)")

    # Tier 1: tfparse — unconditionally. No `.terraform/` gate.
    if TFPARSE_AVAILABLE and not forced:
        print("  Using tfparse (line provenance available)")
        result = parse_terraform_with_tfparse(path)
        if "error" not in result:
            return result
        print(f"  tfparse failed: {result.get('error')}, falling back to a DEGRADED tier...")
    elif not TFPARSE_AVAILABLE:
        print("  WARNING: tfparse is not installed — install it with: pip install tfparse")

    # Tier 2: python-hcl2 — DEGRADED (no line numbers)
    if HCL2_AVAILABLE and forced != "regex":
        print("  Using python-hcl2 [DEGRADED: no line numbers]")
        result = parse_terraform_with_hcl2(path)
        if "error" not in result:
            return result
        print(f"  hcl2 failed: {result.get('error')}, falling back...")

    # Tier 3: regex — DEGRADED (no line numbers)
    print("  Using regex fallback [DEGRADED: basic extraction, no line numbers]")
    return parse_terraform_with_regex(path)


def parse_terraform_with_tfparse(path):
    """
    Parse Terraform using tfparse (Cloud Custodian).

    Full expression evaluation, module traversal, for_each/dynamic expansion, and
    — the reason this is tier 1 — per-resource line provenance via `__tfmeta`.
    Does NOT require `terraform init`.
    """
    try:
        parsed = tfparse_load(path)

        resources = []
        dependencies = {}
        modules = []
        data_sources = []
        missing_provenance = []

        for block_type, instances in parsed.items():
            if block_type in ('variable', 'output', 'locals', 'terraform', 'provider'):
                continue

            if block_type == 'module':
                for instance in instances:
                    meta = instance.get('__tfmeta', {}) or {}
                    address = meta.get('path') or ''
                    modules.append({
                        "name": address[len("module."):] if address.startswith("module.") else address,
                        "address": address,
                        "source": instance.get('source', ''),
                        "location": {
                            "file": normalize_repo_path(meta.get('filename'), path),
                            "startLine": meta.get('line_start'),
                            "endLine": meta.get('line_end'),
                        },
                    })
                continue

            for instance in instances:
                meta = instance.get('__tfmeta', {}) or {}
                meta_type = meta.get('type')

                # tfparse flattens data sources into top-level keys named after
                # the DATA type (e.g. `aws_caller_identity`). Only `__tfmeta.type`
                # distinguishes them from resources. Miss this and every data
                # source is counted as a resource.
                if meta_type == 'data':
                    data_sources.append({
                        "type": block_type,
                        "address": meta.get('path', 'unknown'),
                        "name": (meta.get('path') or '').split('.')[-1],
                        "location": {
                            "file": normalize_repo_path(meta.get('filename'), path),
                            "startLine": meta.get('line_start'),
                            "endLine": meta.get('line_end'),
                        },
                    })
                    continue

                if meta_type != 'resource':
                    continue

                resource_type = block_type
                address = meta.get('path') or f"{resource_type}.unknown"
                _, resource_name = split_resource_address(address, resource_type)

                provider = resource_type.split("_")[0] if "_" in resource_type else "unknown"

                location = build_location(
                    meta.get('filename'),
                    meta.get('line_start'),
                    meta.get('line_end'),
                    address,
                    resource_type,
                    root=path,
                )

                if location["startLine"] is None or location["endLine"] is None:
                    missing_provenance.append(address)

                resource_data = {
                    "type": resource_type,
                    "name": resource_name,
                    "full_name": address,
                    "provider": provider,
                    "module": address.startswith("module."),
                    "location": location,
                    # __tfmeta.references are free dependency edges — the
                    # exposure-chain pass consumes these.
                    "references": meta.get('references', []) or [],
                    "attributes": {k: v for k, v in instance.items() if not k.startswith('__')},
                }
                resources.append(resource_data)

                deps = extract_tfparse_dependencies(instance, resource_type)
                if deps:
                    dependencies[address] = deps

        total = len(resources)
        with_lines = total - len(missing_provenance)

        return {
            "format": "terraform",
            "parser": "tfparse",
            "parseTier": "tfparse",
            "degraded": False,
            "lineProvenance": True,
            "resources": resources,
            "modules": modules,
            "data_sources": data_sources,
            "total_resources": total,
            "resources_with_line_provenance": with_lines,
            "resources_missing_line_provenance": missing_provenance,
            "dependencies": dependencies,
        }

    except Exception as e:
        return {"error": f"tfparse failed: {str(e)}"}


def extract_tfparse_dependencies(resource_attrs, resource_type):
    """
    Extract resource dependencies from tfparse output.
    Looks for references in attribute values.
    """
    dependencies = set()

    def find_references(obj, path=""):
        """Recursively find resource references in attribute values."""
        if isinstance(obj, str):
            # Look for resource references like "aws_subnet.main.id"
            ref_pattern = r'([a-z_]+\.[a-z0-9_-]+)(?:\.[a-z_]+)?'
            for match in re.finditer(ref_pattern, obj):
                ref = match.group(1)
                # Filter out common non-resource patterns
                if not ref.startswith(('var.', 'local.', 'data.', 'module.', 'path.', 'terraform.')):
                    # Validate it looks like a resource reference
                    parts = ref.split('.')
                    if len(parts) == 2 and '_' in parts[0]:
                        dependencies.add(ref)
        elif isinstance(obj, dict):
            for key, value in obj.items():
                if not key.startswith('__'):
                    find_references(value, f"{path}.{key}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                find_references(item, f"{path}[{i}]")

    find_references(resource_attrs)
    return list(dependencies)


def parse_terraform_with_hcl2(path):
    """
    Parse Terraform using python-hcl2.
    Good for syntax parsing without terraform init.
    """
    try:
        # Find all .tf files
        if os.path.isfile(path):
            tf_files = [path]
        else:
            tf_files = file_glob.glob(os.path.join(path, "**/*.tf"), recursive=True)

        if not tf_files:
            return {"error": "No Terraform files found", "resources": [], "dependencies": {}}

        resources = []
        variables = {}
        modules = []
        locals_block = {}
        outputs = {}
        all_content = {}

        for tf_file in tf_files:
            print(f"    Reading: {tf_file}")
            try:
                with open(tf_file, 'r') as f:
                    parsed = hcl2.load(f)
                    all_content[tf_file] = parsed

                # Extract resources.
                # python-hcl2 <5 yields {type: [{name: attrs}]}; >=5 yields
                # {type: {name: attrs}}. Tolerate both — a shape mismatch here
                # silently produced ZERO resources, which is the exact failure
                # mode ("found nothing because it couldn't read the files") the
                # degradation notice exists to prevent.
                for resource_block in parsed.get('resource', []):
                    for resource_type, instances in resource_block.items():
                        if isinstance(instances, dict):
                            instances = [instances]
                        for instance in instances:
                            if not isinstance(instance, dict):
                                continue
                            for resource_name, attrs in instance.items():
                                full_name = f"{resource_type}.{resource_name}"
                                provider = resource_type.split("_")[0] if "_" in resource_type else "unknown"

                                resources.append({
                                    "type": resource_type,
                                    "name": resource_name,
                                    "full_name": full_name,
                                    "provider": provider,
                                    "file": tf_file,
                                    # DEGRADED: python-hcl2 preserves no line numbers.
                                    "location": build_location(
                                        tf_file, None, None, full_name, resource_type, root=path
                                    ),
                                    "references": [],
                                    "attributes": attrs,
                                })

                # Extract variables
                for var_block in parsed.get('variable', []):
                    for var_name, var_config in var_block.items():
                        variables[var_name] = {
                            "name": var_name,
                            "file": tf_file,
                            "default": var_config.get('default'),
                            "type": var_config.get('type'),
                            "description": var_config.get('description'),
                        }

                # Extract modules
                for module_block in parsed.get('module', []):
                    for module_name, module_config in module_block.items():
                        modules.append({
                            "name": module_name,
                            "source": module_config.get('source', ''),
                            "file": tf_file,
                        })

                # Extract locals
                for locals_block_item in parsed.get('locals', []):
                    locals_block.update(locals_block_item)

                # Extract outputs
                for output_block in parsed.get('output', []):
                    for output_name, output_config in output_block.items():
                        outputs[output_name] = {
                            "name": output_name,
                            "value": output_config.get('value'),
                            "file": tf_file,
                        }

            except Exception as e:
                print(f"    Warning: Error parsing {tf_file}: {e}")
                continue

        # Extract dependencies from resource attributes
        dependencies = extract_hcl2_dependencies(resources)

        return {
            "format": "terraform",
            "parser": "hcl2",
            "parseTier": "hcl2",
            "degraded": True,
            "degradationReason": (
                "Fell back to python-hcl2. This tier yields NO line numbers, so "
                "findings cannot populate SARIF and cannot be auto-patched. "
                "Module contents, for_each and dynamic blocks are NOT expanded."
            ),
            "lineProvenance": False,
            "resources": resources,
            "variables": variables,
            "modules": modules,
            "locals": locals_block,
            "outputs": outputs,
            "total_resources": len(resources),
            "resources_with_line_provenance": 0,
            "dependencies": dependencies,
        }

    except Exception as e:
        return {"error": f"hcl2 parsing failed: {str(e)}"}


def extract_hcl2_dependencies(resources):
    """
    Extract dependencies from HCL2 parsed resources by analyzing attribute references.
    """
    dependencies = {}

    # Build a set of known resource full names
    known_resources = {r["full_name"] for r in resources}

    def find_refs_in_value(value):
        """Find resource references in a value (handles ${} interpolation)."""
        refs = set()

        if isinstance(value, str):
            # Match patterns like: aws_subnet.main.id, ${aws_vpc.main.id}
            patterns = [
                r'\$\{([a-z_]+\.[a-z0-9_-]+)(?:\.[a-z_]+)*\}',  # ${resource.name.attr}
                r'([a-z_]+\.[a-z0-9_-]+)(?:\.[a-z_]+)',  # resource.name.attr
            ]
            for pattern in patterns:
                for match in re.finditer(pattern, value):
                    ref = match.group(1)
                    if ref in known_resources:
                        refs.add(ref)
        elif isinstance(value, dict):
            for v in value.values():
                refs.update(find_refs_in_value(v))
        elif isinstance(value, list):
            for item in value:
                refs.update(find_refs_in_value(item))

        return refs

    for resource in resources:
        full_name = resource["full_name"]
        attrs = resource.get("attributes", {})

        # Find all references in attributes
        refs = find_refs_in_value(attrs)

        # Also check depends_on if present
        depends_on = attrs.get("depends_on", [])
        if isinstance(depends_on, list):
            for dep in depends_on:
                if isinstance(dep, str):
                    # Clean up the reference
                    dep_clean = dep.replace("${", "").replace("}", "").split(".")[0:2]
                    if len(dep_clean) == 2:
                        refs.add(".".join(dep_clean))

        if refs:
            dependencies[full_name] = list(refs)

    return dependencies


def parse_terraform_with_regex(path):
    """
    Parse Terraform using regex (fallback).
    Basic extraction without full HCL understanding.
    """
    # Find all .tf files
    if os.path.isfile(path):
        tf_files = [path]
    else:
        tf_files = file_glob.glob(os.path.join(path, "**/*.tf"), recursive=True)

    if not tf_files:
        return {"error": "No Terraform files found", "resources": [], "dependencies": {}}

    resources = []
    variables = {}
    modules = []

    for tf_file in tf_files:
        print(f"    Reading: {tf_file}")
        try:
            with open(tf_file, 'r') as f:
                content = f.read()

            # Extract resources
            resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s+\{'
            for match in re.finditer(resource_pattern, content):
                resource_type = match.group(1)
                resource_name = match.group(2)
                full_name = f"{resource_type}.{resource_name}"
                resources.append({
                    "type": resource_type,
                    "name": resource_name,
                    "full_name": full_name,
                    "file": tf_file,
                    # DEGRADED: no line numbers, no module/for_each/dynamic expansion.
                    "location": build_location(
                        tf_file, None, None, full_name, resource_type, root=path
                    ),
                    "references": [],
                    "provider": resource_type.split("_")[0] if "_" in resource_type else "unknown"
                })

            # Extract variables
            var_pattern = r'variable\s+"([^"]+)"\s+\{'
            for match in re.finditer(var_pattern, content):
                var_name = match.group(1)
                variables[var_name] = {"name": var_name, "file": tf_file}

            # Extract modules
            module_pattern = r'module\s+"([^"]+)"\s+\{'
            for match in re.finditer(module_pattern, content):
                module_name = match.group(1)
                modules.append({"name": module_name, "file": tf_file})

        except Exception as e:
            print(f"    Warning: Error reading {tf_file}: {e}")
            continue

    return {
        "format": "terraform",
        "parser": "regex",
        "parseTier": "regex",
        "degraded": True,
        "degradationReason": (
            "Fell back to the regex parser. This tier yields NO line numbers, so "
            "findings cannot populate SARIF and cannot be auto-patched. Heredocs, "
            "dynamic blocks, for_each and multi-line expressions are NOT handled "
            "correctly — resources may be missed entirely."
        ),
        "lineProvenance": False,
        "resources": resources,
        "variables": variables,
        "modules": modules,
        "total_resources": len(resources),
        "resources_with_line_provenance": 0,
        "dependencies": extract_regex_dependencies(resources)
    }


def extract_regex_dependencies(resources):
    """Extract basic dependency information using pattern inference (fallback)."""
    dependencies = {}

    # Group resources by type for basic relationship inference
    resource_types = {}
    for resource in resources:
        r_type = resource["type"]
        if r_type not in resource_types:
            resource_types[r_type] = []
        resource_types[r_type].append(resource["name"])

    # Infer common patterns
    for resource in resources:
        deps = []
        r_type = resource["type"]

        # Common AWS patterns
        if r_type == "aws_instance":
            if "aws_vpc" in resource_types:
                deps.extend([f"aws_vpc.{name}" for name in resource_types["aws_vpc"]])
            if "aws_subnet" in resource_types:
                deps.extend([f"aws_subnet.{name}" for name in resource_types["aws_subnet"]])
            if "aws_security_group" in resource_types:
                deps.extend([f"aws_security_group.{name}" for name in resource_types["aws_security_group"]])

        elif r_type in ("aws_elb", "aws_lb", "aws_alb"):
            if "aws_subnet" in resource_types:
                deps.extend([f"aws_subnet.{name}" for name in resource_types["aws_subnet"]])
            if "aws_security_group" in resource_types:
                deps.extend([f"aws_security_group.{name}" for name in resource_types["aws_security_group"]])

        elif r_type == "aws_db_instance":
            if "aws_db_subnet_group" in resource_types:
                deps.extend([f"aws_db_subnet_group.{name}" for name in resource_types["aws_db_subnet_group"]])
            if "aws_security_group" in resource_types:
                deps.extend([f"aws_security_group.{name}" for name in resource_types["aws_security_group"]])

        elif r_type == "aws_subnet":
            if "aws_vpc" in resource_types:
                deps.extend([f"aws_vpc.{name}" for name in resource_types["aws_vpc"]])

        elif r_type == "aws_security_group":
            if "aws_vpc" in resource_types:
                deps.extend([f"aws_vpc.{name}" for name in resource_types["aws_vpc"]])

        elif r_type == "aws_lambda_function":
            if "aws_iam_role" in resource_types:
                deps.extend([f"aws_iam_role.{name}" for name in resource_types["aws_iam_role"]])

        if deps:
            dependencies[resource["full_name"]] = deps

    return dependencies


def parse_cloudformation(path):
    """
    Parse CloudFormation template (YAML or JSON).

    Uses a tiered approach:
    1. cfn-lint (most accurate, resolves intrinsic functions)
    2. PyYAML fallback (basic parsing)
    """
    print(f"Parsing CloudFormation template: {path}")

    # Try cfn-lint first (most accurate)
    if CFNLINT_AVAILABLE:
        print("  Using cfn-lint")
        result = parse_cloudformation_with_cfnlint(path)
        if "error" not in result:
            return result
        print(f"  cfn-lint failed: {result.get('error')}, falling back...")

    # Fall back to basic YAML parsing
    print("  Using PyYAML fallback")
    return parse_cloudformation_with_yaml(path)


def _cfn_decode(path):
    """Decode a CFN template via cfn-lint, tolerant of the loader's return shape.

    Older cfn-lint returned `(template, matches)`; current versions return just
    the decorated template node. Handle both so the line-mark tier does not
    silently regress to the PyYAML fallback on a version bump.
    """
    loaded = cfn_json.load(path) if path.endswith('.json') else cfn_yaml.load(path)
    if isinstance(loaded, tuple):
        return loaded[0]
    return loaded


def parse_cloudformation_with_cfnlint(path):
    """
    Parse CloudFormation using cfn-lint.
    Provides intrinsic function resolution and accurate dependency tracking, and
    — the reason this is the FULL tier — per-resource line provenance from
    cfn-lint's decoded line marks.
    """
    try:
        template_data = _cfn_decode(path)

        if template_data is None:
            return {"error": "Failed to decode template"}

        resources = []
        cfn_resources = template_data.get('Resources', {})
        parameters = template_data.get('Parameters', {})
        outputs = template_data.get('Outputs', {})
        conditions = template_data.get('Conditions', {})

        # Per-logical-ID line ranges from cfn-lint's marks. If the marks are
        # absent (e.g. a version that returns plain dicts) the index is empty and
        # this tier degrades to no line numbers, surfaced via `degraded` below.
        line_index = cfn_resource_line_index(cfn_resources)
        missing_provenance = []

        for logical_id, resource in cfn_resources.items():
            logical_id = str(logical_id)
            resource_type = str(resource.get('Type', 'Unknown'))
            properties = resource.get('Properties', {})

            # Extract provider and service from type (AWS::EC2::Instance -> AWS, EC2)
            provider_parts = resource_type.split('::')
            provider = provider_parts[0] if len(provider_parts) > 0 else 'Unknown'
            service = provider_parts[1] if len(provider_parts) > 1 else 'Unknown'
            resource_name = provider_parts[2] if len(provider_parts) > 2 else 'Unknown'

            # Get condition if present
            condition = resource.get('Condition')

            start_line, end_line = line_index.get(logical_id, (None, None))
            if start_line is None or end_line is None:
                missing_provenance.append(logical_id)

            location = build_yaml_location(
                path, start_line, end_line, logical_id, resource_type, service,
                root=path,
            )

            resources.append({
                "logical_id": logical_id,
                "type": resource_type,
                "provider": provider,
                "service": service,
                "resource_name": resource_name,
                "location": location,
                "properties": properties,
                "condition": condition,
                "depends_on": resource.get('DependsOn', []),
                "metadata": resource.get('Metadata', {}),
            })

        # Extract dependencies using cfn-lint's graph capabilities
        dependencies = extract_cfnlint_dependencies(cfn_resources, parameters)

        degraded = len(missing_provenance) == len(resources) and len(resources) > 0

        return {
            "format": "cloudformation",
            "parser": "cfn-lint",
            "parseTier": "cfn-lint",
            "degraded": degraded,
            "degradationReason": (
                "cfn-lint decoded the template but carried no line marks, so "
                "findings cannot populate SARIF and cannot be auto-patched."
            ) if degraded else None,
            "lineProvenance": not degraded,
            "resources_with_line_provenance": len(resources) - len(missing_provenance),
            "resources_missing_line_provenance": missing_provenance,
            "resources": resources,
            "parameters": {k: {
                "type": v.get('Type', 'String'),
                "default": v.get('Default'),
                "description": v.get('Description'),
                "allowed_values": v.get('AllowedValues'),
            } for k, v in parameters.items()},
            "outputs": {k: {
                "value": v.get('Value'),
                "description": v.get('Description'),
                "export": v.get('Export', {}).get('Name'),
            } for k, v in outputs.items()},
            "conditions": list(conditions.keys()),
            "total_resources": len(resources),
            "dependencies": dependencies,
        }

    except Exception as e:
        return {"error": f"cfn-lint parsing failed: {str(e)}"}


def extract_cfnlint_dependencies(resources, parameters):
    """
    Extract dependencies from CloudFormation resources using deep intrinsic function analysis.
    """
    dependencies = {}
    resource_ids = set(resources.keys())
    parameter_ids = set(parameters.keys())

    for logical_id, resource in resources.items():
        deps = set()

        # Explicit dependencies
        depends_on = resource.get('DependsOn', [])
        if isinstance(depends_on, str):
            deps.add(depends_on)
        elif isinstance(depends_on, list):
            deps.update(depends_on)

        # Deep scan for Ref and GetAtt in all properties
        refs = extract_cloudformation_refs_deep(resource, resource_ids, parameter_ids)
        deps.update(refs)

        # Filter to only include resource dependencies (not parameters)
        resource_deps = [d for d in deps if d in resource_ids]

        if resource_deps:
            dependencies[logical_id] = resource_deps

    return dependencies


def extract_cloudformation_refs_deep(obj, resource_ids, parameter_ids, refs=None):
    """
    Recursively extract Ref and GetAtt references from CloudFormation template.
    Handles all intrinsic function formats including short and long forms.
    """
    if refs is None:
        refs = set()

    if isinstance(obj, dict):
        # Handle Ref
        if 'Ref' in obj:
            ref_value = obj['Ref']
            if isinstance(ref_value, str) and ref_value in resource_ids:
                refs.add(ref_value)

        # Handle Fn::GetAtt (long form)
        elif 'Fn::GetAtt' in obj:
            get_att = obj['Fn::GetAtt']
            if isinstance(get_att, list) and len(get_att) > 0:
                if get_att[0] in resource_ids:
                    refs.add(get_att[0])
            elif isinstance(get_att, str):
                # Format: "LogicalId.AttributeName"
                logical_id = get_att.split('.')[0]
                if logical_id in resource_ids:
                    refs.add(logical_id)

        # Handle !GetAtt short form (already parsed as Fn::GetAtt by cfn-lint)

        # Handle Fn::Sub - extract ${Resource} and ${Resource.Attr} references
        elif 'Fn::Sub' in obj:
            sub_value = obj['Fn::Sub']
            if isinstance(sub_value, str):
                # Find ${LogicalId} or ${LogicalId.Attribute} patterns
                for match in re.finditer(r'\$\{([^}!]+?)(?:\.[^}]+)?\}', sub_value):
                    ref = match.group(1)
                    if ref in resource_ids:
                        refs.add(ref)
            elif isinstance(sub_value, list) and len(sub_value) >= 1:
                # [string, {var: value}] format
                if isinstance(sub_value[0], str):
                    for match in re.finditer(r'\$\{([^}!]+?)(?:\.[^}]+)?\}', sub_value[0]):
                        ref = match.group(1)
                        if ref in resource_ids:
                            refs.add(ref)

        # Handle Fn::If - scan condition branches
        elif 'Fn::If' in obj:
            if_value = obj['Fn::If']
            if isinstance(if_value, list):
                for item in if_value[1:]:  # Skip condition name
                    extract_cloudformation_refs_deep(item, resource_ids, parameter_ids, refs)

        # Handle other Fn:: functions that might contain refs
        else:
            for key, value in obj.items():
                if key.startswith('Fn::'):
                    extract_cloudformation_refs_deep(value, resource_ids, parameter_ids, refs)
                elif not key.startswith('!'):
                    extract_cloudformation_refs_deep(value, resource_ids, parameter_ids, refs)

    elif isinstance(obj, list):
        for item in obj:
            extract_cloudformation_refs_deep(item, resource_ids, parameter_ids, refs)

    return refs


def parse_cloudformation_with_yaml(path):
    """
    Parse CloudFormation using PyYAML (fallback).
    Basic parsing without intrinsic function resolution.
    """
    try:
        with open(path, 'r') as f:
            if path.endswith('.json'):
                template = json.load(f)
            else:
                template = yaml.safe_load(f)

        resources = []
        parameters = template.get('Parameters', {})
        outputs = template.get('Outputs', {})
        cfn_resources = template.get('Resources', {})

        for logical_id, resource in cfn_resources.items():
            resource_type = resource.get('Type', 'Unknown')
            properties = resource.get('Properties', {})

            # Extract provider from type (AWS::EC2::Instance -> AWS)
            provider_parts = resource_type.split('::')
            provider = provider_parts[0] if len(provider_parts) > 0 else 'Unknown'
            service = provider_parts[1] if len(provider_parts) > 1 else 'Unknown'

            resources.append({
                "logical_id": logical_id,
                "type": resource_type,
                "provider": provider,
                "service": service,
                # DEGRADED: PyYAML preserves no line numbers.
                "location": build_yaml_location(
                    path, None, None, logical_id, resource_type, service, root=path
                ),
                "properties": properties,
                "depends_on": resource.get('DependsOn', [])
            })

        # Extract dependencies from Ref and GetAtt
        dependencies = {}
        resource_ids = set(cfn_resources.keys())
        parameter_ids = set(parameters.keys()) if parameters else set()

        for logical_id, resource in cfn_resources.items():
            deps = set()

            # Explicit dependencies
            depends_on = resource.get('DependsOn', [])
            if isinstance(depends_on, str):
                deps.add(depends_on)
            elif isinstance(depends_on, list):
                deps.update(depends_on)

            # Implicit dependencies from references
            refs = extract_cloudformation_refs_deep(resource, resource_ids, parameter_ids)
            deps.update(refs)

            if deps:
                dependencies[logical_id] = list(deps)

        return {
            "format": "cloudformation",
            "parser": "yaml",
            "parseTier": "yaml",
            "degraded": True,
            "degradationReason": (
                "Fell back to PyYAML (cfn-lint unavailable or failed). This tier "
                "yields NO line numbers, so findings cannot populate SARIF and "
                "cannot be auto-patched. Intrinsic functions are not resolved."
            ),
            "lineProvenance": False,
            "resources": resources,
            "parameters": list(parameters.keys()) if parameters else [],
            "outputs": list(outputs.keys()) if outputs else [],
            "total_resources": len(resources),
            "resources_with_line_provenance": 0,
            "dependencies": dependencies
        }

    except Exception as e:
        return {"error": f"Failed to parse CloudFormation template: {str(e)}"}


def extract_cloudformation_refs(obj, refs=None):
    """Recursively extract Ref and GetAtt references from CloudFormation template."""
    if refs is None:
        refs = set()

    if isinstance(obj, dict):
        if 'Ref' in obj:
            ref_value = obj['Ref']
            # Filter out pseudo-parameters
            if not ref_value.startswith('AWS::'):
                refs.add(ref_value)
        elif 'Fn::GetAtt' in obj:
            get_att = obj['Fn::GetAtt']
            if isinstance(get_att, list) and len(get_att) > 0:
                refs.add(get_att[0])
            elif isinstance(get_att, str):
                # Format: "LogicalId.AttributeName"
                refs.add(get_att.split('.')[0])
        else:
            for value in obj.values():
                extract_cloudformation_refs(value, refs)
    elif isinstance(obj, list):
        for item in obj:
            extract_cloudformation_refs(item, refs)

    return refs


def parse_kubernetes(path):
    """
    Parse Kubernetes manifests (YAML) with enhanced relationship detection.

    Identifies four relationship types (inspired by KubeDiagrams):
    - REFERENCE: Direct resource references
    - SELECTOR: Label-based selection (Service -> Pod)
    - OWNER: Ownership hierarchies (Deployment -> ReplicaSet -> Pod)
    - COMMUNICATION: Network policies between pods
    """
    print(f"Parsing Kubernetes manifests in: {path}")

    # Find all YAML files
    if os.path.isfile(path):
        yaml_files = [path]
    else:
        yaml_files = file_glob.glob(os.path.join(path, "**/*.yaml"), recursive=True)
        yaml_files.extend(file_glob.glob(os.path.join(path, "**/*.yml"), recursive=True))

    if not yaml_files:
        return {"error": "No Kubernetes manifest files found", "resources": []}

    resources = []
    # ruamel gives per-document line provenance; PyYAML (below) gives the data.
    # If ruamel is unavailable, no line index -> a DEGRADED scan (no SARIF/patches).
    any_line_index = RUAMEL_AVAILABLE
    missing_provenance = []

    for yaml_file in yaml_files:
        print(f"  Reading: {yaml_file}")
        line_index = kubernetes_line_index(yaml_file)
        if line_index is None:
            any_line_index = False
            line_index = {}
        try:
            with open(yaml_file, 'r') as f:
                # Handle multi-document YAML (--- separator)
                documents = yaml.safe_load_all(f)

                for doc in documents:
                    if doc is None or not isinstance(doc, dict):
                        continue

                    kind = doc.get('kind', 'Unknown')
                    api_version = doc.get('apiVersion', 'Unknown')
                    metadata = doc.get('metadata', {})
                    spec = doc.get('spec', {})

                    name = metadata.get('name', 'unnamed')
                    namespace = metadata.get('namespace', 'default')
                    labels = metadata.get('labels', {})
                    annotations = metadata.get('annotations', {})
                    owner_refs = metadata.get('ownerReferences', [])

                    start_line, end_line = line_index.get(
                        (str(kind), str(name)), (None, None)
                    )
                    address = f"{kind}/{name}"
                    if start_line is None:
                        missing_provenance.append(address)

                    resource = {
                        "kind": kind,
                        "apiVersion": api_version,
                        "name": name,
                        "namespace": namespace,
                        "labels": labels,
                        "annotations": annotations,
                        "owner_references": owner_refs,
                        "file": yaml_file,
                        "location": build_yaml_location(
                            yaml_file, start_line, end_line, address, kind,
                            "kubernetes", root=path,
                        ),
                        "spec": spec,  # Keep full spec for relationship analysis
                    }

                    # Extract kind-specific fields
                    resource.update(extract_kubernetes_kind_fields(kind, spec, metadata, doc))

                    resources.append(resource)

        except Exception as e:
            print(f"  Warning: Error reading {yaml_file}: {e}")
            continue

    # Extract relationships using enhanced detection
    relationships = extract_kubernetes_relationships_enhanced(resources)

    # Group resources by namespace and kind
    by_namespace = {}
    by_kind = {}
    for r in resources:
        ns = r["namespace"]
        kind = r["kind"]
        if ns not in by_namespace:
            by_namespace[ns] = []
        by_namespace[ns].append(f"{kind}/{r['name']}")
        if kind not in by_kind:
            by_kind[kind] = []
        by_kind[kind].append(r["name"])

    degraded = not any_line_index
    return {
        "format": "kubernetes",
        "parser": "ruamel" if any_line_index else "yaml",
        "parseTier": "ruamel" if any_line_index else "yaml",
        "degraded": degraded,
        "degradationReason": (
            "ruamel.yaml is unavailable, so Kubernetes manifests were parsed "
            "without line numbers. Findings cannot populate SARIF and cannot be "
            "auto-patched. Install it with: pip install ruamel.yaml"
        ) if degraded else None,
        "lineProvenance": not degraded,
        "resources_with_line_provenance": len(resources) - len(missing_provenance),
        "resources_missing_line_provenance": missing_provenance,
        "resources": resources,
        "total_resources": len(resources),
        "namespaces": list(set(r["namespace"] for r in resources)),
        "by_namespace": by_namespace,
        "by_kind": by_kind,
        "relationships": relationships,
        "dependencies": convert_relationships_to_dependencies(relationships),
    }


def extract_kubernetes_kind_fields(kind, spec, metadata, doc=None):
    """Extract kind-specific fields for Kubernetes resources.

    `doc` is the full manifest document; some fields (ConfigMap `data`,
    Secret `data`/`type`) live at the document top level, not under spec
    or metadata.
    """
    fields = {}
    if doc is None:
        doc = {}

    if kind == 'Service':
        fields["selector"] = spec.get('selector', {})
        fields["ports"] = spec.get('ports', [])
        fields["type"] = spec.get('type', 'ClusterIP')
        fields["cluster_ip"] = spec.get('clusterIP')

    elif kind in ('Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet'):
        fields["replicas"] = spec.get('replicas', 1)
        fields["selector"] = spec.get('selector', {})
        # Extract pod template labels
        template = spec.get('template', {})
        template_metadata = template.get('metadata', {})
        fields["pod_labels"] = template_metadata.get('labels', {})
        # Extract container info
        pod_spec = template.get('spec', {})
        containers = pod_spec.get('containers', [])
        fields["containers"] = [{
            "name": c.get('name'),
            "image": c.get('image'),
            "ports": c.get('ports', []),
        } for c in containers]
        # Extract volume claims
        fields["volume_claims"] = spec.get('volumeClaimTemplates', [])

    elif kind == 'Ingress':
        fields["rules"] = spec.get('rules', [])
        fields["tls"] = spec.get('tls', [])
        fields["ingress_class"] = spec.get('ingressClassName')

    elif kind == 'ConfigMap':
        # `data` and `binaryData` are top-level keys on the document.
        data_keys = list(doc.get('data', {}).keys())
        data_keys += list(doc.get('binaryData', {}).keys())
        fields["data_keys"] = data_keys

    elif kind == 'Secret':
        # `type`, `data`, and `stringData` are top-level keys on the document.
        fields["type"] = doc.get('type', 'Opaque')
        data_keys = list(doc.get('data', {}).keys())
        data_keys += list(doc.get('stringData', {}).keys())
        fields["data_keys"] = data_keys

    elif kind == 'PersistentVolumeClaim':
        fields["storage_class"] = spec.get('storageClassName')
        fields["access_modes"] = spec.get('accessModes', [])
        resources_spec = spec.get('resources', {})
        requests = resources_spec.get('requests', {})
        fields["storage"] = requests.get('storage')

    elif kind == 'PersistentVolume':
        fields["storage_class"] = spec.get('storageClassName')
        fields["capacity"] = spec.get('capacity', {}).get('storage')
        fields["access_modes"] = spec.get('accessModes', [])

    elif kind == 'NetworkPolicy':
        fields["pod_selector"] = spec.get('podSelector', {})
        fields["ingress_rules"] = spec.get('ingress', [])
        fields["egress_rules"] = spec.get('egress', [])
        fields["policy_types"] = spec.get('policyTypes', [])

    elif kind == 'ServiceAccount':
        fields["secrets"] = spec.get('secrets', []) if spec else []

    elif kind == 'Role' or kind == 'ClusterRole':
        fields["rules"] = spec.get('rules', []) if spec else []

    elif kind == 'RoleBinding' or kind == 'ClusterRoleBinding':
        fields["role_ref"] = spec.get('roleRef', {}) if spec else {}
        fields["subjects"] = spec.get('subjects', []) if spec else []

    elif kind == 'Job':
        fields["completions"] = spec.get('completions', 1)
        fields["parallelism"] = spec.get('parallelism', 1)
        template = spec.get('template', {})
        pod_spec = template.get('spec', {})
        containers = pod_spec.get('containers', [])
        fields["containers"] = [{"name": c.get('name'), "image": c.get('image')} for c in containers]

    elif kind == 'CronJob':
        fields["schedule"] = spec.get('schedule')
        job_template = spec.get('jobTemplate', {})
        job_spec = job_template.get('spec', {})
        template = job_spec.get('template', {})
        pod_spec = template.get('spec', {})
        containers = pod_spec.get('containers', [])
        fields["containers"] = [{"name": c.get('name'), "image": c.get('image')} for c in containers]

    return fields


def extract_kubernetes_relationships_enhanced(resources):
    """
    Extract relationships between Kubernetes resources using enhanced detection.

    Relationship types:
    - SELECTOR: Label-based selection (Service -> Pods)
    - OWNER: Ownership hierarchy (Deployment -> ReplicaSet -> Pod)
    - REFERENCE: Direct resource references (Ingress -> Service)
    - COMMUNICATION: Network policies
    - MOUNT: Volume/ConfigMap/Secret mounts
    """
    relationships = []

    # Build indexes for efficient lookup
    by_kind_namespace = {}  # {(kind, namespace): [resources]}
    by_labels = {}  # {namespace: {label_key: {label_value: [resources]}}}

    for resource in resources:
        key = (resource["kind"], resource["namespace"])
        if key not in by_kind_namespace:
            by_kind_namespace[key] = []
        by_kind_namespace[key].append(resource)

        # Index by labels
        ns = resource["namespace"]
        if ns not in by_labels:
            by_labels[ns] = {}
        for label_key, label_value in resource.get("labels", {}).items():
            if label_key not in by_labels[ns]:
                by_labels[ns][label_key] = {}
            if label_value not in by_labels[ns][label_key]:
                by_labels[ns][label_key][label_value] = []
            by_labels[ns][label_key][label_value].append(resource)

    for resource in resources:
        kind = resource["kind"]
        name = resource["name"]
        namespace = resource["namespace"]
        spec = resource.get("spec", {})

        # === SELECTOR relationships ===

        # Service -> Pods (via selector)
        if kind == "Service":
            selector = resource.get("selector", {})
            if selector:
                matching_pods = find_resources_by_selector(
                    selector, namespace, ["Pod", "Deployment", "StatefulSet", "DaemonSet"],
                    by_kind_namespace, resources
                )
                for target in matching_pods:
                    relationships.append({
                        "from": f"Service/{name}",
                        "to": f"{target['kind']}/{target['name']}",
                        "type": "SELECTOR",
                        "namespace": namespace,
                        "selector": selector,
                    })

        # === OWNER relationships ===

        # Deployment/StatefulSet/DaemonSet -> ReplicaSet/Pods (implicit)
        if kind in ("Deployment", "StatefulSet", "DaemonSet"):
            relationships.append({
                "from": f"{kind}/{name}",
                "to": f"Pod/{name}-*",
                "type": "OWNER",
                "namespace": namespace,
                "description": f"{kind} manages Pod replicas",
            })

        # CronJob -> Job
        if kind == "CronJob":
            relationships.append({
                "from": f"CronJob/{name}",
                "to": f"Job/{name}-*",
                "type": "OWNER",
                "namespace": namespace,
            })

        # === REFERENCE relationships ===

        # Ingress -> Service
        if kind == "Ingress":
            rules = resource.get("rules", [])
            for rule in rules:
                host = rule.get("host", "*")
                http = rule.get("http", {})
                for path_config in http.get("paths", []):
                    backend = path_config.get("backend", {})
                    service_name = None
                    service_port = None

                    # Handle different API versions
                    if "serviceName" in backend:  # networking.k8s.io/v1beta1
                        service_name = backend["serviceName"]
                        service_port = backend.get("servicePort")
                    elif "service" in backend:  # networking.k8s.io/v1
                        service_name = backend["service"].get("name")
                        port_info = backend["service"].get("port", {})
                        service_port = port_info.get("number") or port_info.get("name")

                    if service_name:
                        relationships.append({
                            "from": f"Ingress/{name}",
                            "to": f"Service/{service_name}",
                            "type": "REFERENCE",
                            "namespace": namespace,
                            "host": host,
                            "path": path_config.get("path", "/"),
                            "port": service_port,
                        })

        # RoleBinding/ClusterRoleBinding -> Role/ClusterRole
        if kind in ("RoleBinding", "ClusterRoleBinding"):
            role_ref = resource.get("role_ref", {})
            if role_ref:
                role_kind = role_ref.get("kind", "Role")
                role_name = role_ref.get("name")
                if role_name:
                    relationships.append({
                        "from": f"{kind}/{name}",
                        "to": f"{role_kind}/{role_name}",
                        "type": "REFERENCE",
                        "namespace": namespace if kind == "RoleBinding" else "cluster",
                    })

            # Also link to subjects
            subjects = resource.get("subjects", [])
            for subject in subjects:
                subj_kind = subject.get("kind")
                subj_name = subject.get("name")
                subj_ns = subject.get("namespace", namespace)
                if subj_kind and subj_name:
                    relationships.append({
                        "from": f"{kind}/{name}",
                        "to": f"{subj_kind}/{subj_name}",
                        "type": "REFERENCE",
                        "namespace": subj_ns,
                        "description": "grants permissions to",
                    })

        # === MOUNT relationships (ConfigMap, Secret, PVC references) ===

        # Extract volume mounts from workload resources
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"):
            template = spec.get("template", spec)  # Pod doesn't have template
            pod_spec = template.get("spec", {})
            volumes = pod_spec.get("volumes", [])

            for volume in volumes:
                vol_name = volume.get("name")

                # ConfigMap volume
                if "configMap" in volume:
                    cm_name = volume["configMap"].get("name")
                    if cm_name:
                        relationships.append({
                            "from": f"{kind}/{name}",
                            "to": f"ConfigMap/{cm_name}",
                            "type": "MOUNT",
                            "namespace": namespace,
                            "volume": vol_name,
                        })

                # Secret volume
                if "secret" in volume:
                    secret_name = volume["secret"].get("secretName")
                    if secret_name:
                        relationships.append({
                            "from": f"{kind}/{name}",
                            "to": f"Secret/{secret_name}",
                            "type": "MOUNT",
                            "namespace": namespace,
                            "volume": vol_name,
                        })

                # PVC volume
                if "persistentVolumeClaim" in volume:
                    pvc_name = volume["persistentVolumeClaim"].get("claimName")
                    if pvc_name:
                        relationships.append({
                            "from": f"{kind}/{name}",
                            "to": f"PersistentVolumeClaim/{pvc_name}",
                            "type": "MOUNT",
                            "namespace": namespace,
                            "volume": vol_name,
                        })

        # === COMMUNICATION relationships (NetworkPolicy) ===

        if kind == "NetworkPolicy":
            pod_selector = resource.get("pod_selector", {})
            ingress_rules = resource.get("ingress_rules", [])
            egress_rules = resource.get("egress_rules", [])

            # NetworkPolicy applies to pods matching selector
            relationships.append({
                "from": f"NetworkPolicy/{name}",
                "to": f"Pods matching {pod_selector}",
                "type": "COMMUNICATION",
                "namespace": namespace,
                "description": "applies network rules to",
            })

            # Ingress rules (who can talk to these pods)
            for rule in ingress_rules:
                from_selectors = rule.get("from", [])
                for from_sel in from_selectors:
                    if "podSelector" in from_sel:
                        relationships.append({
                            "from": f"Pods matching {from_sel['podSelector']}",
                            "to": f"Pods matching {pod_selector}",
                            "type": "COMMUNICATION",
                            "namespace": namespace,
                            "direction": "ingress",
                        })

            # Egress rules (who these pods can talk to)
            for rule in egress_rules:
                to_selectors = rule.get("to", [])
                for to_sel in to_selectors:
                    if "podSelector" in to_sel:
                        relationships.append({
                            "from": f"Pods matching {pod_selector}",
                            "to": f"Pods matching {to_sel['podSelector']}",
                            "type": "COMMUNICATION",
                            "namespace": namespace,
                            "direction": "egress",
                        })

    return relationships


def find_resources_by_selector(selector, namespace, target_kinds, by_kind_namespace, all_resources):
    """Find resources that match a label selector."""
    matching = []

    for target_kind in target_kinds:
        key = (target_kind, namespace)
        candidates = by_kind_namespace.get(key, [])

        for candidate in candidates:
            # Get the labels to match against
            if target_kind in ("Deployment", "StatefulSet", "DaemonSet"):
                # Match against pod template labels
                labels_to_check = candidate.get("pod_labels", {})
            else:
                labels_to_check = candidate.get("labels", {})

            # Check if all selector labels match
            if selector and labels_to_check:
                match = all(
                    labels_to_check.get(k) == v
                    for k, v in selector.items()
                )
                if match:
                    matching.append(candidate)

    return matching


def convert_relationships_to_dependencies(relationships):
    """Convert relationships list to a dependencies dict for diagram generation."""
    dependencies = {}

    for rel in relationships:
        from_resource = rel["from"]
        to_resource = rel["to"]

        if from_resource not in dependencies:
            dependencies[from_resource] = []

        # Only add concrete resource references (not wildcards)
        if "*" not in to_resource and "matching" not in to_resource:
            dependencies[from_resource].append(to_resource)

    return dependencies


def parse_docker_compose(path):
    """Parse Docker Compose file (YAML)."""
    print(f"Parsing Docker Compose file: {path}")

    try:
        with open(path, 'r') as f:
            compose = yaml.safe_load(f)

        services = compose.get('services', {})
        networks = compose.get('networks', {})
        volumes = compose.get('volumes', {})

        # ruamel supplies per-service line provenance; None -> DEGRADED scan.
        line_index = compose_line_index(path)
        any_line_index = line_index is not None
        if line_index is None:
            line_index = {}
        missing_provenance = []

        service_list = []
        dependencies = {}

        for service_name, service_config in services.items():
            depends_on = service_config.get('depends_on', [])

            # depends_on can be a list or a dict
            if isinstance(depends_on, dict):
                depends_on = list(depends_on.keys())

            service_networks = service_config.get('networks', [])
            if isinstance(service_networks, dict):
                service_networks = list(service_networks.keys())

            service_volumes = service_config.get('volumes', [])

            start_line, end_line = line_index.get(str(service_name), (None, None))
            if start_line is None:
                missing_provenance.append(service_name)

            service_list.append({
                "name": service_name,
                "image": service_config.get('image'),
                "build": service_config.get('build'),
                "ports": service_config.get('ports', []),
                "environment": service_config.get('environment', {}),
                "networks": service_networks,
                "volumes": service_volumes,
                "location": build_yaml_location(
                    path, start_line, end_line, service_name, "service",
                    "docker-compose", root=path,
                ),
            })

            dependencies[service_name] = {
                "depends_on": depends_on,
                "networks": service_networks
            }

        degraded = not any_line_index
        return {
            "format": "docker-compose",
            "parser": "ruamel" if any_line_index else "yaml",
            "parseTier": "ruamel" if any_line_index else "yaml",
            "degraded": degraded,
            "degradationReason": (
                "ruamel.yaml is unavailable, so the Compose file was parsed "
                "without line numbers. Findings cannot populate SARIF and cannot "
                "be auto-patched. Install it with: pip install ruamel.yaml"
            ) if degraded else None,
            "lineProvenance": not degraded,
            "resources_with_line_provenance": len(service_list) - len(missing_provenance),
            "resources_missing_line_provenance": missing_provenance,
            "services": service_list,
            "networks": list(networks.keys()),
            "volumes": list(volumes.keys()),
            "total_services": len(service_list),
            "dependencies": dependencies
        }

    except Exception as e:
        return {"error": f"Failed to parse Docker Compose file: {str(e)}"}


def extract_github_subpath(url):
    """
    Extract subpath from GitHub URL if specified.

    Examples:
        https://github.com/user/repo/tree/main/terraform -> ('https://github.com/user/repo', 'terraform')
        https://github.com/user/repo -> ('https://github.com/user/repo', None)
    """
    # Match URLs with /tree/branch/path or /blob/branch/path
    match = re.match(r'^(https?://github\.com/[\w\-\.]+/[\w\-\.]+)(?:/(?:tree|blob)/[^/]+)?(?:/(.+))?$', url)
    if match:
        base_url = match.group(1)
        subpath = match.group(2)
        return base_url, subpath
    return url, None


def main():
    """Main entry point for the IaC parser."""
    if len(sys.argv) < 3:
        print("ERROR: Missing required arguments.")
        print("\nUsage: python parse_iac.py <format> <path>")
        print("\nSupported formats:")
        print("  terraform       - Parse Terraform .tf files")
        print("  cloudformation  - Parse CloudFormation templates (.yaml, .json)")
        print("  kubernetes      - Parse Kubernetes manifests (.yaml)")
        print("  docker-compose  - Parse Docker Compose files")
        print("\nPath can be:")
        print("  - Local file or directory")
        print("  - GitHub repository URL (will be cloned automatically)")
        print("\nExamples:")
        print("  python parse_iac.py terraform ./infrastructure")
        print("  python parse_iac.py cloudformation template.yaml")
        print("  python parse_iac.py kubernetes ./k8s")
        print("  python parse_iac.py docker-compose docker-compose.yaml")
        print("\n  # GitHub repositories:")
        print("  python parse_iac.py terraform https://github.com/user/repo")
        print("  python parse_iac.py terraform https://github.com/user/repo/tree/main/terraform")
        print("  python parse_iac.py cloudformation github.com/user/repo")
        sys.exit(1)

    # Additive flag: emit ONLY the JSON document on stdout (machine consumers).
    # Default behavior is unchanged.
    json_only = "--json-only" in sys.argv[3:]

    iac_format = sys.argv[1].lower()
    path = sys.argv[2]

    if json_only:
        # Keep stdout a clean JSON channel; progress chatter goes to stderr.
        sys.stdout = sys.stderr

    temp_dir = None  # Track temp directory for cleanup

    # Check if path is a GitHub URL
    if is_github_url(path):
        # Extract base URL and optional subpath
        base_url, subpath = extract_github_subpath(path)

        # Clone the repository
        temp_dir, path = clone_repository(base_url, subpath)
        if not path:
            sys.exit(1)
    else:
        # Validate local path
        if not os.path.exists(path):
            print(f"ERROR: Path does not exist: {path}")
            sys.exit(1)

    try:
        # Parse based on format
        if iac_format == "terraform":
            result = parse_terraform(path)
        elif iac_format == "cloudformation":
            result = parse_cloudformation(path)
        elif iac_format == "kubernetes":
            result = parse_kubernetes(path)
        elif iac_format == "docker-compose":
            result = parse_docker_compose(path)
        else:
            print(f"ERROR: Unsupported format: {iac_format}")
            print("Supported formats: terraform, cloudformation, kubernetes, docker-compose")
            sys.exit(1)

        # A degraded scan must never look like a clean one.
        if result.get("degraded"):
            print("\n" + "!"*60)
            print("DEGRADED SCAN — parser tier: " + str(result.get("parseTier")))
            print(result.get("degradationReason", ""))
            print("!"*60)

        # Output JSON result
        if json_only:
            print(json.dumps(result, indent=2), file=sys.__stdout__)
        else:
            print("\n" + "="*60)
            print("PARSE RESULT:")
            print("="*60)
            print(json.dumps(result, indent=2))

        # Check for errors
        if "error" in result:
            sys.exit(1)

    finally:
        # Always clean up temp directory
        if temp_dir:
            cleanup_temp_dir(temp_dir)
        sys.stdout = sys.__stdout__


if __name__ == "__main__":
    main()
