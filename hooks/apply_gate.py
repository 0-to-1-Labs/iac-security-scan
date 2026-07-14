#!/usr/bin/env python3
"""
apply_gate.py -- an OPT-IN PreToolUse hook that gates ``terraform apply`` on
unfixed security findings at or above a configurable severity floor (WS-18,
Phase 4).

READ THIS FIRST -- the two design rules that keep this hook from getting the
whole plugin uninstalled on day one:

1. IT SHIPS DISABLED. Installing the plugin arms NOTHING. This hook is not
   wired in ``.claude-plugin/plugin.json`` and there is deliberately no
   auto-discovered ``hooks/hooks.json``. Two independent gates must BOTH be
   off-by-default before this ever runs:
     (a) the user has to register it (copy ``hooks/hooks.json.example`` into
         their own ``.claude/settings.json``), and
     (b) even once registered, the FIRST thing ``decide()`` does is check an
         explicit local enable flag and no-op instantly if it is absent.
   A plugin that can block someone's ``terraform apply`` the moment they
   install it gets uninstalled the same minute. So it can't.

2. IT FAILS OPEN. If the scanner errors, times out, cannot find checkov, or
   this hook throws for any reason, the apply is ALLOWED, loudly, with an
   explanation. A security tool that bricks ``terraform apply`` because it
   crashed is strictly worse than one that occasionally waves a bad deploy
   through. We choose the latter, on purpose. The deny path is reachable ONLY
   when a scan actually ran and actually found a blocking finding.

Enablement (all local, never plugin.json):

  .claude/iac-security-scan.local.md   (project-local, YAML frontmatter)
  ------------------------------------------------------------------------
  ---
  apply_gate: block            # off (default) | warn | ask | block
  apply_gate_severity: critical  # floor: critical | high | medium | low
  apply_gate_timeout: 120        # seconds; the scan is bounded
  ---

  Environment variables override the file (handy for CI):
    IAC_SECURITY_SCAN_APPLY_GATE           off | warn | ask | block
    IAC_SECURITY_SCAN_APPLY_GATE_SEVERITY  critical | high | medium | low
    IAC_SECURITY_SCAN_APPLY_GATE_TIMEOUT   integer seconds

Modes:
  off   -- disabled. Instant no-op. (This is the default when nothing is set.)
  warn  -- allow the apply, but surface a loud warning listing the findings.
  ask   -- ask the user to confirm before applying.
  block -- deny the apply, with the findings and a clear bypass.

The scan is deterministic and bounded: it runs the Checkov adapter on the
TARGET directory only (honoring ``terraform -chdir=DIR``), seeds severities
from the checked-in ``data/rule-severity.json`` map, and counts findings whose
seeded severity is at or above the floor. No LLM, no network, no full-repo
walk -- a PreToolUse hook has to be fast and it has to be predictable.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional

# --- plugin layout -----------------------------------------------------------
# hooks/ lives at the plugin root; the scanner scripts live under
# skills/iac-security-scan/scripts/. Resolve both from this file's location so
# the hook is portable (${CLAUDE_PLUGIN_ROOT}-independent).
_HOOK_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.dirname(_HOOK_DIR)
_SCRIPTS_DIR = os.path.join(_PLUGIN_ROOT, "skills", "iac-security-scan", "scripts")
_RUN_CHECKOV = os.path.join(_SCRIPTS_DIR, "run_checkov.py")

if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

# Severity ordering, most severe first. Kept local so this hook never fails to
# LOAD just because the scanner package moved; findings.SeverityMap is imported
# lazily inside the scan so an import error there fails OPEN rather than at
# module import.
SEVERITY_ORDER: List[str] = ["critical", "high", "medium", "low", "informational"]

VALID_MODES = ("off", "warn", "ask", "block")
DEFAULT_MODE = "off"
DEFAULT_FLOOR = "critical"
DEFAULT_TIMEOUT = 120

CONFIG_RELPATH = os.path.join(".claude", "iac-security-scan.local.md")

ENV_MODE = "IAC_SECURITY_SCAN_APPLY_GATE"
ENV_FLOOR = "IAC_SECURITY_SCAN_APPLY_GATE_SEVERITY"
ENV_TIMEOUT = "IAC_SECURITY_SCAN_APPLY_GATE_TIMEOUT"

# The tools whose ``apply`` subcommand we gate. OpenTofu is a drop-in fork.
APPLY_BINARIES = ("terraform", "tofu")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ScanError(Exception):
    """The scan could not produce a trustworthy answer.

    Raised for a missing/timed-out/degraded scan. It ALWAYS results in a
    fail-open allow -- we never deny a deploy on the strength of a scan that
    did not actually run.
    """


# ---------------------------------------------------------------------------
# Command parsing -- is this a `terraform apply`, and where?
# ---------------------------------------------------------------------------


def _split_statements(command: str) -> List[str]:
    """Split a shell command into individual statements.

    Good enough for gate detection: break on ``&&``, ``||``, ``;``, ``|`` and
    newlines. We do NOT need a real shell grammar -- we only need to avoid
    treating ``cd foo && terraform apply`` as one opaque blob, and to avoid a
    later statement's ``apply`` bleeding into an earlier ``echo``.
    """
    out: List[str] = []
    buf: List[str] = []
    i = 0
    n = len(command)
    while i < n:
        two = command[i : i + 2]
        if two in ("&&", "||"):
            out.append("".join(buf))
            buf = []
            i += 2
            continue
        ch = command[i]
        if ch in (";", "|", "\n"):
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def _binary_basename(token: str) -> str:
    """`/usr/bin/terraform` -> `terraform`; `terraform.exe` -> `terraform`."""
    base = os.path.basename(token)
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def parse_apply(command: str) -> Optional[Dict[str, Any]]:
    """Return apply metadata if ``command`` runs ``terraform apply``, else None.

    Handles: global options before the subcommand (``terraform -chdir=x
    apply``), option-laden applies (``terraform apply -auto-approve``), chained
    statements (``cd d && terraform apply``), and absolute/`.exe` binary paths.

    Deliberately does NOT match ``terraform plan``/``validate``/``init``/``fmt``,
    nor ``echo terraform apply`` (the first token there is ``echo``), nor a
    ``terraform`` substring inside an unrelated word.

    Returns ``{"chdir": <str|None>}`` -- ``chdir`` is the value of a
    ``-chdir=DIR`` global flag if present, so the caller can scan the right
    directory.
    """
    for statement in _split_statements(command):
        try:
            tokens = shlex.split(statement)
        except ValueError:
            # Unbalanced quotes etc. -- can't reason about it; skip this
            # statement rather than guess.
            continue
        if not tokens:
            continue
        # Find the terraform/tofu invocation. It must be the command word of
        # the statement (index 0), possibly with an env-assignment prefix like
        # `TF_LOG=debug terraform ...`.
        idx = 0
        while idx < len(tokens) and "=" in tokens[idx] and not tokens[idx].startswith("-"):
            # leading VAR=value env assignments
            idx += 1
        if idx >= len(tokens):
            continue
        if _binary_basename(tokens[idx]) not in APPLY_BINARIES:
            continue
        # Walk the remaining tokens: global options (incl. -chdir=DIR) come
        # before the subcommand. The first non-option token is the subcommand.
        chdir: Optional[str] = None
        j = idx + 1
        subcommand: Optional[str] = None
        while j < len(tokens):
            tok = tokens[j]
            if tok.startswith("-chdir="):
                chdir = tok.split("=", 1)[1]
                j += 1
                continue
            if tok == "-chdir" and j + 1 < len(tokens):
                chdir = tokens[j + 1]
                j += 2
                continue
            if tok.startswith("-"):
                j += 1
                continue
            subcommand = tok
            break
        if subcommand == "apply":
            return {"chdir": chdir}
    return None


def resolve_target_dir(cwd: str, chdir: Optional[str]) -> str:
    """The directory to scan: ``-chdir`` resolved against cwd, else cwd."""
    if chdir:
        if os.path.isabs(chdir):
            return chdir
        return os.path.normpath(os.path.join(cwd, chdir))
    return cwd


# ---------------------------------------------------------------------------
# Enablement -- explicit, local, off by default
# ---------------------------------------------------------------------------


def _read_frontmatter(path: str) -> Dict[str, str]:
    """Parse the leading ``--- ... ---`` YAML frontmatter as flat key: value.

    Intentionally dependency-free (no PyYAML): we only support the flat scalar
    keys this hook uses. Anything fancier is ignored rather than erroring, so a
    stray list/comment in the file never turns the gate off-by-crash.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return {}
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    fields: Dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.split("#", 1)[0].strip().strip("'\"")
        if key:
            fields[key] = val
    return fields


class GateConfig:
    """Resolved enablement. ``enabled`` is False unless a mode is explicitly set."""

    def __init__(
        self, mode: str, floor: str, timeout: int, source: str
    ) -> None:
        self.mode = mode
        self.floor = floor
        self.timeout = timeout
        self.source = source  # human-readable provenance, for the fail/allow message

    @property
    def enabled(self) -> bool:
        return self.mode in ("warn", "ask", "block")


def resolve_config(cwd: str, env: Optional[Dict[str, str]] = None) -> GateConfig:
    """Resolve the gate configuration. Environment overrides the local file.

    When neither the env vars nor the local file set a mode (or it is set to
    ``off``), the gate is DISABLED -- this is the default and the whole point.
    """
    env = os.environ if env is None else env

    file_fields: Dict[str, str] = {}
    config_path = os.path.join(cwd, CONFIG_RELPATH)
    if os.path.isfile(config_path):
        file_fields = _read_frontmatter(config_path)

    # Mode: env wins, then file, then default off.
    mode = (env.get(ENV_MODE) or file_fields.get("apply_gate") or DEFAULT_MODE).strip().lower()
    if mode not in VALID_MODES:
        mode = DEFAULT_MODE

    floor = (
        env.get(ENV_FLOOR) or file_fields.get("apply_gate_severity") or DEFAULT_FLOOR
    ).strip().lower()
    if floor not in SEVERITY_ORDER:
        floor = DEFAULT_FLOOR

    raw_timeout = env.get(ENV_TIMEOUT) or file_fields.get("apply_gate_timeout")
    timeout = DEFAULT_TIMEOUT
    if raw_timeout:
        try:
            timeout = max(5, int(str(raw_timeout).strip()))
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT

    if env.get(ENV_MODE):
        source = "env (%s)" % ENV_MODE
    elif file_fields.get("apply_gate"):
        source = CONFIG_RELPATH
    else:
        source = "default"

    return GateConfig(mode=mode, floor=floor, timeout=timeout, source=source)


# ---------------------------------------------------------------------------
# The scan (injectable) -- deterministic, bounded, Checkov + seeded severity
# ---------------------------------------------------------------------------


def _at_or_above(severity: str, floor: str) -> bool:
    if severity not in SEVERITY_ORDER or floor not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(severity) <= SEVERITY_ORDER.index(floor)


def default_scan(target_dir: str, floor: str, timeout: int) -> List[Dict[str, Any]]:
    """Run the deterministic scan and return findings at/above ``floor``.

    Raises ``ScanError`` on anything that means "we don't have a trustworthy
    answer" -- checkov missing (degraded), timeout, bad output, no such dir.
    The caller turns every ScanError into a fail-open allow.

    This is the DEFAULT scan. Tests inject their own ``scan_fn`` instead; the
    real one is what makes the hook useful in the wild.
    """
    if not os.path.isdir(target_dir):
        raise ScanError("target directory does not exist: %s" % target_dir)

    try:
        proc = subprocess.run(
            [sys.executable, _RUN_CHECKOV, target_dir],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ScanError("scan timed out after %ds" % timeout)
    except OSError as exc:
        raise ScanError("could not launch scanner: %s" % exc)

    if not (proc.stdout or "").strip():
        raise ScanError(
            "scanner produced no output (exit %d): %s"
            % (proc.returncode, (proc.stderr or "").strip()[:300])
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScanError("scanner output was not valid JSON: %s" % exc)

    # A degraded scan (e.g. checkov not installed) did NOT run the rule engine.
    # We cannot assert the presence or absence of criticals, so we must not
    # block on it. Fail open, loudly.
    if payload.get("degraded"):
        raise ScanError(
            "scan was degraded (%s); the rule engine did not run"
            % (payload.get("degradationReason") or "unknown reason")
        )

    # Lazy import so a broken scanner package fails OPEN (ScanError) instead of
    # crashing this hook at load time.
    try:
        from findings import SeverityMap  # noqa: WPS433 (intentional local import)

        severity_map = SeverityMap.load()
    except Exception as exc:  # noqa: BLE001 - any failure here is a fail-open
        raise ScanError("could not load severity map: %s" % exc)

    blocking: List[Dict[str, Any]] = []
    for finding in payload.get("findings") or []:
        rule_id = finding.get("ruleId") or ""
        severity = severity_map.resolve(rule_id).severity
        if _at_or_above(severity, floor):
            loc = finding.get("location") or {}
            blocking.append(
                {
                    "ruleId": rule_id,
                    "severity": severity,
                    "title": finding.get("title") or rule_id,
                    "resourceAddress": loc.get("resourceAddress") or "",
                    "file": loc.get("file") or "",
                    "startLine": loc.get("startLine") or 0,
                }
            )
    # Most severe first, stable.
    blocking.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return blocking


# ---------------------------------------------------------------------------
# Output helpers (the PreToolUse contract)
# ---------------------------------------------------------------------------


def _passthrough() -> Dict[str, Any]:
    """No opinion. Claude Code proceeds as if the hook were not there."""
    return {}


def _decision(decision: str, reason: str, *, system_message: Optional[str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    if system_message:
        out["systemMessage"] = system_message
    return out


def _format_findings(findings: List[Dict[str, Any]], limit: int = 10) -> str:
    lines = []
    for f in findings[:limit]:
        where = f["resourceAddress"] or f["file"] or "?"
        loc = ""
        if f.get("file"):
            loc = " (%s:%s)" % (f["file"], f.get("startLine") or "?")
        lines.append(
            "  - [%s] %s -- %s%s" % (f["severity"].upper(), f["ruleId"], where, loc)
        )
    if len(findings) > limit:
        lines.append("  - ... and %d more" % (len(findings) - limit))
    return "\n".join(lines)


_BYPASS = (
    "To proceed anyway: fix the finding(s), or disable the gate "
    "(set `apply_gate: off` in .claude/iac-security-scan.local.md, or run with "
    "IAC_SECURITY_SCAN_APPLY_GATE=off)."
)


# ---------------------------------------------------------------------------
# Core decision
# ---------------------------------------------------------------------------


def decide(
    hook_input: Dict[str, Any],
    *,
    scan_fn: Callable[[str, str, int], List[Dict[str, Any]]] = default_scan,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Decide what to do with one PreToolUse event. Pure and injectable.

    ``scan_fn(target_dir, floor, timeout)`` returns the list of blocking
    findings (or raises to signal a scan error -> fail open). Tests pass a
    stub; production uses ``default_scan``.
    """
    cwd = hook_input.get("cwd") or os.getcwd()

    # STEP 1 -- enablement. The very first substantive thing we do. If the gate
    # is not explicitly enabled, we no-op instantly and do NO work. Installing
    # the plugin leaves it here forever.
    config = resolve_config(cwd, env)
    if not config.enabled:
        return _passthrough()

    # STEP 2 -- is this even a terraform apply? Only Bash commands, only apply.
    if hook_input.get("tool_name") != "Bash":
        return _passthrough()
    command = (hook_input.get("tool_input") or {}).get("command") or ""
    apply_meta = parse_apply(command)
    if apply_meta is None:
        return _passthrough()

    target_dir = resolve_target_dir(cwd, apply_meta.get("chdir"))

    # STEP 3 -- scan, bounded. ANY failure here fails OPEN. We never deny a
    # deploy because our own scan broke.
    try:
        blocking = scan_fn(target_dir, config.floor, config.timeout)
    except ScanError as exc:
        return _decision(
            "allow",
            "iac-security-scan apply-gate FAILED OPEN: %s. Allowing the apply "
            "rather than blocking on a scan that could not run. %s"
            % (exc, _BYPASS),
            system_message=(
                "iac-security-scan apply-gate could not complete a scan of %s "
                "(%s). Per its fail-open policy the apply was ALLOWED, not "
                "blocked. Treat this as an unscanned deploy." % (target_dir, exc)
            ),
        )
    except Exception as exc:  # noqa: BLE001 - unknown failure must still fail open
        return _decision(
            "allow",
            "iac-security-scan apply-gate FAILED OPEN (unexpected error: %s). "
            "Allowing the apply. %s" % (exc, _BYPASS),
        )

    # STEP 4 -- clean at/above the floor: proceed silently.
    if not blocking:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": (
                    "iac-security-scan apply-gate: no unfixed findings at or above "
                    "'%s' in %s." % (config.floor, target_dir)
                ),
            },
            "suppressOutput": True,
        }

    # STEP 5 -- there are unfixed findings at/above the floor. Act per mode.
    listing = _format_findings(blocking)
    headline = (
        "iac-security-scan apply-gate: %d unfixed finding(s) at or above '%s' in %s:\n%s"
        % (len(blocking), config.floor, target_dir, listing)
    )

    if config.mode == "warn":
        return _decision(
            "allow",
            headline + "\n\nMode is 'warn' -- the apply is NOT blocked. " + _BYPASS,
            system_message="WARNING -- deploying with unfixed security findings:\n" + headline,
        )
    if config.mode == "ask":
        return _decision(
            "ask",
            headline + "\n\nConfirm you want to apply with these unfixed findings. " + _BYPASS,
        )
    # block
    return _decision(
        "deny",
        headline + "\n\n" + _BYPASS,
        system_message="Blocked terraform apply -- unfixed security findings:\n" + headline,
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    """Read a PreToolUse event on stdin, write a decision on stdout.

    The outermost guarantee: this function NEVER exits non-zero and NEVER emits
    a deny by accident. Any unexpected error results in a passthrough allow, so
    a bug in the gate can't wedge someone's terraform apply.
    """
    try:
        raw = sys.stdin.read()
    except Exception:  # noqa: BLE001
        json.dump(_passthrough(), sys.stdout)
        return 0

    try:
        hook_input = json.loads(raw) if raw.strip() else {}
        if not isinstance(hook_input, dict):
            hook_input = {}
        result = decide(hook_input)
    except Exception as exc:  # noqa: BLE001 - fail open on anything
        result = _decision(
            "allow",
            "iac-security-scan apply-gate FAILED OPEN (%s). Allowing the apply." % exc,
        )

    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
