#!/usr/bin/env python3
"""
run_checkov.py — the Checkov adapter for iac-security-scan (WS-2).

Invoke Checkov, normalize its output into the SPEC §5 finding shape, and
ISOLATE it. This is the ONLY file in the codebase that is allowed to know
what Checkov's JSON looks like (SPEC §14.1 risk #1): swapping in tfsec or
Trivy must remain a one-file change, so no Checkov-native field name
(`check_id`, `file_line_range`, `resource`, ...) may leak past this module.

Key behaviors:
  * Captures BOTH failed_checks and passed_checks. The passing set is what
    §7.2's "controls SATISFIED by the current IaC" is derived from, and it is
    the reason we do NOT pass Checkov's `--quiet` flag (which silently drops
    passed_checks from the JSON).
  * Normalizes Checkov's `/athena.tf` (leading slash, relative to scan root)
    to the repo-relative `athena.tf` that the WS-1 parser emits. The downstream
    join key is (normalized-rule-concept, file, resourceAddress); a silent
    mismatch here breaks EVERY join and yields a scan that finds nothing while
    looking perfectly healthy.
  * Emits severity as null, always. Checkov community edition does not populate
    severity (it is a Bridgecrew/Prisma paid feature). We do not invent one and
    we do not default to medium — WS-3's data/rule-severity.json owns that.
  * If Checkov is absent: LOUD degradation. Print the `pip install checkov`
    line to stderr, set degraded=true in the output, and continue so the caller
    can run the LLM-only path. A scan that found nothing because the tool was
    missing must never look like a scan that found nothing because the code was
    clean.

Usage:
    python3 run_checkov.py <path> [--framework terraform]

Emits JSON on stdout. Exit codes: 0 ok (including "degraded"), 2 scan error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# Pinned expectation. Checkov's rule set moves; an unpinned upgrade reads as a
# regression in our code (plan risk #10). We do not enforce this at runtime,
# but we report what we actually ran so drift is visible.
EXPECTED_CHECKOV_VERSION = "3.2.500"

INSTALL_HINT = "pip install checkov==%s" % EXPECTED_CHECKOV_VERSION

CHECKOV_TIMEOUT_SECONDS = 600


# ---------------------------------------------------------------------------
# Normalization helpers (the adapter boundary)
# ---------------------------------------------------------------------------


def normalize_path(file_path: Optional[str]) -> str:
    """Normalize a Checkov file path to the repo-relative form the parser uses.

    Checkov reports paths relative to the scan root but with a leading slash:
        "/athena.tf"            -> "athena.tf"
        "/modules/vpc/main.tf"  -> "modules/vpc/main.tf"
        "./athena.tf"           -> "athena.tf"
        "athena.tf"             -> "athena.tf"       (already normal)

    tfparse reports `__tfmeta.filename` as "athena.tf". Both sides MUST land on
    the same string or the (rule, file, resourceAddress) join silently produces
    zero matches.
    """
    if not file_path:
        return ""
    path = file_path.replace("\\", "/").strip()
    # Strip any number of leading "./" segments, then any leading slashes.
    while path.startswith("./"):
        path = path[2:]
    path = path.lstrip("/")
    # Re-strip in case of "/./foo.tf".
    while path.startswith("./"):
        path = path[2:]
    return path


def split_resource_address(resource: Optional[str]) -> Tuple[str, str]:
    """Split a Terraform resource address into (address, resourceType).

    Verified in pre-flight: Checkov's `resource` field is byte-identical to
    tfparse's `__tfmeta.path` ("aws_athena_workgroup.main"), so the address
    joins natively and needs NO translation layer. We only derive the type.

        "aws_athena_workgroup.main"        -> ("aws_athena_workgroup.main", "aws_athena_workgroup")
        "module.vpc.aws_s3_bucket.logs"    -> ("module.vpc.aws_s3_bucket.logs", "aws_s3_bucket")
    """
    if not resource:
        return "", ""
    address = resource.strip()
    parts = address.split(".")
    resource_type = parts[-2] if len(parts) >= 2 else ""
    return address, resource_type


def service_from_resource_type(resource_type: str) -> str:
    """Derive the AWS service slug from a Terraform resource type.

        "aws_s3_bucket"           -> "s3"
        "aws_cloudwatch_log_group"-> "cloudwatch"
        "aws_athena_workgroup"    -> "athena"
    """
    if not resource_type:
        return ""
    parts = resource_type.split("_")
    if len(parts) >= 2 and parts[0] in ("aws", "azurerm", "google"):
        return parts[1]
    return parts[0]


def finding_id(rule_id: str, file: str, resource_address: str) -> str:
    """SPEC §5: finding-<sha256(ruleId + ':' + file + ':' + resourceAddress)[0:16]>"""
    key = "%s:%s:%s" % (rule_id, file, resource_address)
    return "finding-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _location(check: Dict[str, Any]) -> Dict[str, Any]:
    file = normalize_path(check.get("file_path"))
    address, resource_type = split_resource_address(check.get("resource"))
    line_range = check.get("file_line_range") or [0, 0]
    try:
        start_line, end_line = int(line_range[0]), int(line_range[1])
    except (TypeError, ValueError, IndexError):
        start_line, end_line = 0, 0
    return {
        "file": file,
        "startLine": start_line,
        "endLine": end_line,
        "resourceAddress": address,
        "resourceType": resource_type,
        "service": service_from_resource_type(resource_type),
    }


def normalize_check(check: Dict[str, Any]) -> Dict[str, Any]:
    """Map one Checkov check object into the SPEC §5 core finding shape.

    Nothing Checkov-native crosses this boundary. Severity is deliberately
    null: Checkov community edition never populates it, and WS-3's severity
    seed is the only legitimate source.
    """
    rule_id = check.get("check_id") or ""
    location = _location(check)
    description = check.get("description") or check.get("short_description") or ""
    return {
        "id": finding_id(rule_id, location["file"], location["resourceAddress"]),
        "ruleId": rule_id,
        "title": check.get("check_name") or rule_id,
        "description": description,
        "source": ["checkov"],
        "location": location,
        "severity": None,  # Checkov CE emits none. Never fabricate. WS-3 seeds it.
        "guideline": check.get("guideline") or None,
    }


def normalize_results(payload: Any) -> Dict[str, List[Dict[str, Any]]]:
    """Pull failed/passed/skipped out of Checkov's JSON.

    Checkov emits a single object for one framework and a LIST of such objects
    when several frameworks (or check types) run. Handle both.
    """
    blocks = payload if isinstance(payload, list) else [payload]
    failed: List[Dict[str, Any]] = []
    passed: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    summary = {"failed": 0, "passed": 0, "skipped": 0, "parsingErrors": 0, "resourceCount": 0}

    for block in blocks:
        if not isinstance(block, dict):
            continue
        results = block.get("results") or {}
        for check in results.get("failed_checks") or []:
            failed.append(normalize_check(check))
        for check in results.get("passed_checks") or []:
            passed.append(normalize_check(check))
        for check in results.get("skipped_checks") or []:
            skipped.append(normalize_check(check))
        block_summary = block.get("summary") or {}
        summary["failed"] += int(block_summary.get("failed") or 0)
        summary["passed"] += int(block_summary.get("passed") or 0)
        summary["skipped"] += int(block_summary.get("skipped") or 0)
        summary["parsingErrors"] += int(block_summary.get("parsing_errors") or 0)
        summary["resourceCount"] += int(block_summary.get("resource_count") or 0)

    return {"failed": failed, "passed": passed, "skipped": skipped, "summary": summary}


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------


def find_checkov() -> Optional[str]:
    """Locate the checkov binary. CHECKOV_BIN overrides (used by tests)."""
    override = os.environ.get("CHECKOV_BIN")
    if override:
        return override if shutil.which(override) or os.path.isfile(override) else None
    return shutil.which("checkov")


def checkov_version(binary: str) -> Optional[str]:
    try:
        proc = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=60
        )
        return (proc.stdout or "").strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def degraded_result(path: str, reason: str) -> Dict[str, Any]:
    """The loud-degradation payload. Never a silent thin scan (SPEC §4.1)."""
    return {
        "tool": "checkov",
        "toolVersion": None,
        "expectedVersion": EXPECTED_CHECKOV_VERSION,
        "scanRoot": os.path.abspath(path),
        "degraded": True,
        "degradationReason": reason,
        "installHint": INSTALL_HINT,
        "findings": [],
        "passedChecks": [],
        "skippedChecks": [],
        "summary": {
            "failed": 0,
            "passed": 0,
            "skipped": 0,
            "parsingErrors": 0,
            "resourceCount": 0,
        },
    }


def run_checkov(path: str, framework: str = "terraform") -> Dict[str, Any]:
    """Run Checkov against `path` and return the normalized adapter payload."""
    binary = find_checkov()
    if not binary:
        reason = (
            "Checkov is not installed. The deterministic rule layer did NOT run; "
            "these results come from the LLM pass alone and are NOT a clean bill "
            "of health. Install it with: %s" % INSTALL_HINT
        )
        # Loud. stderr, so it survives stdout being piped into a JSON consumer.
        print("=" * 72, file=sys.stderr)
        print("DEGRADED SCAN: checkov not found on PATH", file=sys.stderr)
        print("  %s" % reason, file=sys.stderr)
        print("=" * 72, file=sys.stderr)
        return degraded_result(path, reason)

    # NOTE: --quiet is deliberately NOT passed. It suppresses passed_checks from
    # the JSON, and §7.2's "controls satisfied" section is derived from those.
    cmd = [
        binary,
        "-d",
        path,
        "--framework",
        framework,
        "--output",
        "json",
        "--compact",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CHECKOV_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        reason = "Checkov timed out after %ds." % CHECKOV_TIMEOUT_SECONDS
        print("DEGRADED SCAN: %s" % reason, file=sys.stderr)
        return degraded_result(path, reason)
    except OSError as exc:
        reason = "Could not execute checkov (%s). Install it with: %s" % (exc, INSTALL_HINT)
        print("DEGRADED SCAN: %s" % reason, file=sys.stderr)
        return degraded_result(path, reason)

    # Checkov exits 1 whenever it has failed checks — that is a normal scan, not
    # an error. Only an unparseable stdout is an error.
    stdout = proc.stdout or ""
    if not stdout.strip():
        reason = "Checkov produced no output (exit %d): %s" % (
            proc.returncode,
            (proc.stderr or "").strip()[:400],
        )
        print("DEGRADED SCAN: %s" % reason, file=sys.stderr)
        return degraded_result(path, reason)

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        reason = "Checkov output was not valid JSON (%s)." % exc
        print("DEGRADED SCAN: %s" % reason, file=sys.stderr)
        return degraded_result(path, reason)

    normalized = normalize_results(payload)
    version = checkov_version(binary)

    return {
        "tool": "checkov",
        "toolVersion": version,
        "expectedVersion": EXPECTED_CHECKOV_VERSION,
        "scanRoot": os.path.abspath(path),
        "degraded": False,
        "degradationReason": None,
        "installHint": None,
        "findings": normalized["failed"],
        "passedChecks": normalized["passed"],
        "skippedChecks": normalized["skipped"],
        "summary": normalized["summary"],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run Checkov and normalize its output to the iac-security-scan finding schema."
    )
    parser.add_argument("path", help="Directory to scan")
    parser.add_argument("--framework", default="terraform", help="Checkov framework (default: terraform)")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.path):
        print("error: not a directory: %s" % args.path, file=sys.stderr)
        return 2

    try:
        result = run_checkov(args.path, args.framework)
    except Exception as exc:  # noqa: BLE001 - scan error must exit 2 (SPEC §9.2)
        print("error: checkov adapter failed: %s" % exc, file=sys.stderr)
        return 2

    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
