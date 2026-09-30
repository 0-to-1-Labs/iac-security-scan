"""Tests for the opt-in terraform-apply security gate (WS-18, Phase 4).

The whole reason this hook is allowed to exist at all is that it CANNOT hurt a
user who has not deliberately turned it on, and it CANNOT wedge an apply even
when it is on. These tests are built around those two guarantees:

  * SHIPS DISABLED  -- installing the plugin arms nothing. plugin.json does not
    wire it; there is no auto-discovered hooks/hooks.json; and the hook no-ops
    instantly when the enable flag is absent.
  * NEVER ALLOWS    -- the hook returns `ask` or `deny`, never `allow`. A scan
    error / timeout / crash / unparseable command / clean scan is `ask`: the
    user's normal permission prompt, with the gate's verdict attached.

The scan is injected (`decide(..., scan_fn=...)`) so every decision path is
tested without shelling out. Two `slow` tests exercise the real Checkov-backed
`default_scan` end to end.
"""

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS_DIR = os.path.join(REPO_ROOT, "hooks")
PLUGIN_JSON = os.path.join(REPO_ROOT, ".claude-plugin", "plugin.json")

sys.path.insert(0, HOOKS_DIR)

import apply_gate  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def bash_apply(cwd="/work", command="terraform apply"):
    return {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
    }


CRITICAL_FINDING = {
    "ruleId": "CKV_AWS_17",
    "severity": "critical",
    "title": "RDS is publicly accessible",
    "resourceAddress": "aws_db_instance.d",
    "file": "main.tf",
    "startLine": 1,
}


def scan_returns(findings):
    """Build an injectable scan_fn that returns a fixed list and records calls."""
    calls = []

    def _scan(target_dir, floor, timeout):
        calls.append((target_dir, floor, timeout))
        return list(findings)

    _scan.calls = calls
    return _scan


def scan_raises(exc):
    def _scan(target_dir, floor, timeout):
        raise exc

    return _scan


def decision_of(out):
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision")


# ---------------------------------------------------------------------------
# Acceptance #1 -- installing the plugin does NOT arm the hook
# ---------------------------------------------------------------------------


def test_plugin_json_does_not_wire_hooks():
    """plugin.json must not declare a hooks entry -- that would auto-arm on install."""
    with open(PLUGIN_JSON, encoding="utf-8") as fh:
        manifest = json.load(fh)
    assert "hooks" not in manifest, (
        "plugin.json must NOT wire the hook -- shipping it wired arms the gate "
        "the moment the plugin is installed, which is exactly what WS-18 forbids."
    )


def test_no_autodiscovered_hooks_json():
    """There must be no hooks/hooks.json (Claude Code auto-loads that = auto-arm).

    The registration snippet ships as hooks.json.EXAMPLE, which is never loaded.
    """
    assert not os.path.exists(os.path.join(HOOKS_DIR, "hooks.json")), (
        "hooks/hooks.json is auto-discovered and would arm the gate on install. "
        "Ship it as hooks.json.example instead."
    )
    assert os.path.exists(os.path.join(HOOKS_DIR, "hooks.json.example"))


def test_disabled_by_default_is_instant_passthrough():
    """No env, no config file -> no-op, and the scan is never even called."""
    scan = scan_returns([CRITICAL_FINDING])
    out = apply_gate.decide(bash_apply(), scan_fn=scan, env={})
    assert out == {}
    assert scan.calls == [], "the scan must not run when the gate is disabled"


def test_disabled_ignores_a_would_be_blocking_apply(tmp_path):
    """Even a dir full of criticals is untouched while the gate is off."""
    out = apply_gate.decide(
        bash_apply(cwd=str(tmp_path)), scan_fn=scan_returns([CRITICAL_FINDING]), env={}
    )
    assert out == {}


# ---------------------------------------------------------------------------
# Acceptance #4 -- non-apply commands pass through untouched
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "terraform plan",
        "terraform validate",
        "terraform init",
        "terraform fmt",
        "echo terraform apply",  # not an invocation of terraform
        "ls -la",
        "git commit -m 'terraform apply later'",  # apply inside a string argument
    ],
)
def test_non_apply_bash_passes_through_even_when_enabled(command):
    scan = scan_returns([CRITICAL_FINDING])
    out = apply_gate.decide(
        bash_apply(command=command), scan_fn=scan, env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"}
    )
    assert out == {}
    assert scan.calls == []


def test_non_bash_tool_passes_through():
    out = apply_gate.decide(
        {"tool_name": "Write", "tool_input": {"file_path": "/x"}, "cwd": "/w"},
        scan_fn=scan_returns([CRITICAL_FINDING]),
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"},
    )
    assert out == {}


# ---------------------------------------------------------------------------
# parse_apply -- the command detector
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command,expected_chdir,expected_cd",
    [
        ("terraform apply", None, None),
        ("terraform apply -auto-approve", None, None),
        ("terraform -chdir=infra apply", "infra", None),
        ("terraform -chdir=/abs/infra apply -auto-approve", "/abs/infra", None),
        ("cd stack && terraform apply", None, "stack"),
        ("cd a; cd b && terraform apply", None, os.path.join("a", "b")),
        ("cd /abs && terraform -chdir=infra apply", "infra", "/abs"),
        ("TF_LOG=debug terraform apply", None, None),
        ("terraform validate && terraform apply", None, None),
        ("/usr/local/bin/terraform apply", None, None),
        ("tofu apply", None, None),
        ("terragrunt apply", None, None),
        ("terragrunt run-all apply", None, None),
        ("env terraform apply", None, None),
        ("time terraform apply", None, None),
        ("sudo terraform apply", None, None),
        ("sh -c 'terraform apply'", None, None),
        ("bash -c 'cd infra && terraform apply'", None, "infra"),
        ("terraform apply\\\n -auto-approve", None, None),
    ],
)
def test_parse_apply_matches(command, expected_chdir, expected_cd):
    meta = apply_gate.parse_apply(command)
    assert meta is not None
    assert "unparseable" not in meta
    assert meta["chdir"] == expected_chdir
    assert meta["cd"] == expected_cd


@pytest.mark.parametrize(
    "command",
    [
        "t=terraform; $t apply",
        "terraform $(echo apply)",
        "terraform `echo apply`",
        "cd $DIR && terraform apply",
        "eval 'terraform apply'",
        'terraform apply -var "x=1',  # unbalanced quote
    ],
)
def test_parse_apply_flags_unparseable_applies(command):
    """A command that mentions an apply but hides it behind shell evaluation is
    reported as unparseable -- never silently treated as 'not an apply'."""
    meta = apply_gate.parse_apply(command)
    assert meta is not None
    assert meta.get("unparseable")


def test_unparseable_apply_asks():
    scan = scan_returns([])
    out = apply_gate.decide(
        bash_apply(command="terraform $(echo apply)"),
        scan_fn=scan,
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"},
    )
    assert decision_of(out) == "ask"
    assert "could not be parsed" in out["hookSpecificOutput"]["permissionDecisionReason"]
    assert scan.calls == []


@pytest.mark.parametrize(
    "command",
    [
        "terraform plan",
        "terraform destroy",
        "echo terraform apply",
        "cat apply.tf",
        "terraform  # apply later",
        "myterraform apply",  # different binary name
        "",
    ],
)
def test_parse_apply_rejects(command):
    assert apply_gate.parse_apply(command) is None


def test_resolve_target_dir():
    assert apply_gate.resolve_target_dir("/work", None) == "/work"
    assert apply_gate.resolve_target_dir("/work", "infra") == os.path.normpath("/work/infra")
    assert apply_gate.resolve_target_dir("/work", "/abs") == "/abs"
    assert apply_gate.resolve_target_dir("/work", None, cd="stack") == os.path.normpath("/work/stack")
    assert apply_gate.resolve_target_dir("/work", "infra", cd="stack") == os.path.normpath(
        "/work/stack/infra"
    )
    assert apply_gate.resolve_target_dir("/work", None, cd="/abs") == "/abs"


def test_cd_directs_the_scan():
    """`cd infra && terraform apply` scans infra, not the session cwd."""
    scan = scan_returns([])
    apply_gate.decide(
        bash_apply(cwd="/work", command="cd infra && terraform apply -auto-approve"),
        scan_fn=scan,
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"},
    )
    assert scan.calls[0][0] == os.path.normpath("/work/infra")


# ---------------------------------------------------------------------------
# Enabled decision paths (injected scan)
# ---------------------------------------------------------------------------


def test_block_mode_denies_on_critical():
    scan = scan_returns([CRITICAL_FINDING])
    out = apply_gate.decide(
        bash_apply(), scan_fn=scan, env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"}
    )
    assert decision_of(out) == "deny"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "CKV_AWS_17" in reason
    # Never permanently blocked: the deny must always name a bypass.
    assert "apply_gate: off" in reason
    assert scan.calls, "block mode must actually run the scan"


def test_warn_mode_asks_with_a_warning():
    """`warn` never pre-approves: it asks, with the findings in the prompt."""
    out = apply_gate.decide(
        bash_apply(), scan_fn=scan_returns([CRITICAL_FINDING]),
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "warn"},
    )
    assert decision_of(out) == "ask"
    assert "WARNING" in (out.get("systemMessage") or "")
    assert "CKV_AWS_17" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_ask_mode_asks():
    out = apply_gate.decide(
        bash_apply(), scan_fn=scan_returns([CRITICAL_FINDING]),
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "ask"},
    )
    assert decision_of(out) == "ask"


def test_clean_dir_asks_never_allows():
    """A clean scan leaves the user's normal permission prompt in place. The
    gate adds a check; it never removes one."""
    out = apply_gate.decide(
        bash_apply(), scan_fn=scan_returns([]), env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"}
    )
    assert decision_of(out) == "ask"
    assert "no unfixed findings" in out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "systemMessage" not in out


@pytest.mark.parametrize("mode", ["warn", "ask", "block"])
def test_no_path_returns_allow(mode):
    """The contract, stated once: every enabled decision is `ask` or `deny`."""
    for scan in (
        scan_returns([]),
        scan_returns([CRITICAL_FINDING]),
        scan_raises(apply_gate.ScanError("x")),
        scan_raises(RuntimeError("y")),
    ):
        out = apply_gate.decide(
            bash_apply(), scan_fn=scan, env={"IAC_SECURITY_SCAN_APPLY_GATE": mode}
        )
        assert decision_of(out) in ("ask", "deny")


def test_config_found_via_claude_project_dir(tmp_path):
    """After a `cd` the hook cwd is a subdirectory; the enable file at the
    project root (CLAUDE_PROJECT_DIR) must still be honored."""
    _write_config(tmp_path, "---\napply_gate: block\n---\n")
    sub = tmp_path / "infra"
    sub.mkdir()
    cfg = apply_gate.resolve_config(str(sub), env={"CLAUDE_PROJECT_DIR": str(tmp_path)})
    assert cfg.enabled and cfg.mode == "block"
    # and without the project dir, the subdirectory alone finds nothing
    assert not apply_gate.resolve_config(str(sub), env={}).enabled


def test_floor_is_passed_to_scan():
    scan = scan_returns([])
    apply_gate.decide(
        bash_apply(),
        scan_fn=scan,
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "block", "IAC_SECURITY_SCAN_APPLY_GATE_SEVERITY": "high"},
    )
    assert scan.calls[0][1] == "high"


def test_chdir_directs_the_scan():
    scan = scan_returns([])
    apply_gate.decide(
        bash_apply(cwd="/work", command="terraform -chdir=infra apply"),
        scan_fn=scan,
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"},
    )
    assert scan.calls[0][0] == os.path.normpath("/work/infra")


# ---------------------------------------------------------------------------
# A broken scan must never block -- and must never clear the apply either
# ---------------------------------------------------------------------------


def test_scan_error_asks():
    out = apply_gate.decide(
        bash_apply(),
        scan_fn=scan_raises(apply_gate.ScanError("checkov exploded")),
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"},
    )
    assert decision_of(out) == "ask"
    assert "NOT cleared" in out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "checkov exploded" in out["hookSpecificOutput"]["permissionDecisionReason"]
    # The user is told this was an unscanned deploy, not a clean one.
    assert "unscanned" in (out.get("systemMessage") or "").lower()


def test_unexpected_exception_asks():
    out = apply_gate.decide(
        bash_apply(),
        scan_fn=scan_raises(RuntimeError("kaboom")),
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"},
    )
    assert decision_of(out) == "ask"
    assert "NOT cleared" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_main_never_allows_on_garbage_stdin(monkeypatch, capsys):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("not json at all {{{"))
    rc = apply_gate.main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    # Garbage in -> never a deny, never an allow.
    assert decision_of(out) in (None, "ask")


def test_main_asks_when_decide_crashes(monkeypatch, capsys):
    import io

    def boom(_hook_input):
        raise RuntimeError("bug in the gate")

    monkeypatch.setattr(apply_gate, "decide", boom)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(bash_apply())))
    rc = apply_gate.main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert decision_of(out) == "ask"


def test_main_passthrough_when_disabled(monkeypatch, capsys):
    import io

    monkeypatch.delenv("IAC_SECURITY_SCAN_APPLY_GATE", raising=False)
    monkeypatch.setattr(
        sys, "stdin", io.StringIO(json.dumps(bash_apply(cwd="/nonexistent-xyz")))
    )
    rc = apply_gate.main()
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {}


# ---------------------------------------------------------------------------
# Config resolution -- env + local file
# ---------------------------------------------------------------------------


def _write_config(tmp_path, body):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir(exist_ok=True)
    (claude_dir / "iac-security-scan.local.md").write_text(body, encoding="utf-8")


def test_config_from_local_file(tmp_path):
    _write_config(
        tmp_path,
        "---\napply_gate: block\napply_gate_severity: high\napply_gate_timeout: 45\n---\n",
    )
    cfg = apply_gate.resolve_config(str(tmp_path), env={})
    assert cfg.enabled
    assert cfg.mode == "block"
    assert cfg.floor == "high"
    assert cfg.timeout == 45


def test_config_off_is_disabled(tmp_path):
    _write_config(tmp_path, "---\napply_gate: off\n---\n")
    assert not apply_gate.resolve_config(str(tmp_path), env={}).enabled


def test_config_absent_is_disabled(tmp_path):
    assert not apply_gate.resolve_config(str(tmp_path), env={}).enabled


def test_env_overrides_file(tmp_path):
    _write_config(tmp_path, "---\napply_gate: block\napply_gate_severity: high\n---\n")
    cfg = apply_gate.resolve_config(
        str(tmp_path),
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "warn", "IAC_SECURITY_SCAN_APPLY_GATE_SEVERITY": "low"},
    )
    assert cfg.mode == "warn"
    assert cfg.floor == "low"


def test_invalid_mode_falls_back_to_off(tmp_path):
    _write_config(tmp_path, "---\napply_gate: banana\n---\n")
    assert not apply_gate.resolve_config(str(tmp_path), env={}).enabled


def test_config_file_enables_full_decision(tmp_path):
    """End-to-end via the local file (not env): a critical -> deny."""
    _write_config(tmp_path, "---\napply_gate: block\n---\n")
    out = apply_gate.decide(
        bash_apply(cwd=str(tmp_path)), scan_fn=scan_returns([CRITICAL_FINDING]), env={}
    )
    assert decision_of(out) == "deny"


# ---------------------------------------------------------------------------
# Floor comparison + frontmatter parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity,floor,expected",
    [
        ("critical", "critical", True),
        ("high", "critical", False),
        ("critical", "high", True),
        ("medium", "high", False),
        ("high", "high", True),
        ("unmapped", "critical", False),  # governance: never block on an unseeded rule
        (None, "critical", False),
    ],
)
def test_at_or_above(severity, floor, expected):
    assert apply_gate._at_or_above(severity, floor) is expected


def test_frontmatter_parsing(tmp_path):
    p = tmp_path / "c.md"
    p.write_text(
        "---\n# a comment\napply_gate: block  # inline comment\nquoted: \"value\"\n---\nbody\n",
        encoding="utf-8",
    )
    fields = apply_gate._read_frontmatter(str(p))
    assert fields["apply_gate"] == "block"
    assert fields["quoted"] == "value"
    assert "# a comment" not in fields


def test_frontmatter_missing_file_is_empty():
    assert apply_gate._read_frontmatter("/no/such/file.md") == {}


# ---------------------------------------------------------------------------
# Slow: the real Checkov-backed default_scan end to end
# ---------------------------------------------------------------------------


def _checkov_available():
    scripts = os.path.join(REPO_ROOT, "skills", "iac-security-scan", "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import run_checkov  # noqa: E402

    return run_checkov.find_checkov() is not None


requires_checkov = pytest.mark.skipif(
    not _checkov_available(), reason="checkov not installed"
)

# A publicly-accessible RDS instance reliably fires CKV_AWS_17, which the
# checked-in rule-severity.json seeds as `critical`.
_RDS_CRITICAL_TF = """
resource "aws_db_instance" "d" {
  allocated_storage   = 10
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "insecurepassword"
  publicly_accessible = true
  skip_final_snapshot = true
}
"""

_CLEAN_TF = """
resource "aws_sns_topic" "t" {
  name              = "clean-topic"
  kms_master_key_id = "alias/aws/sns"
}
"""


@pytest.mark.slow
@requires_checkov
def test_real_scan_blocks_on_unfixed_critical(tmp_path):
    (tmp_path / "main.tf").write_text(_RDS_CRITICAL_TF, encoding="utf-8")
    out = apply_gate.decide(
        bash_apply(cwd=str(tmp_path), command="terraform apply -auto-approve"),
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"},
    )
    assert decision_of(out) == "deny"
    assert "CKV_AWS_17" in out["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.slow
@requires_checkov
def test_real_scan_clean_dir_asks(tmp_path):
    (tmp_path / "main.tf").write_text(_CLEAN_TF, encoding="utf-8")
    out = apply_gate.decide(
        bash_apply(cwd=str(tmp_path), command="terraform apply"),
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "block", "IAC_SECURITY_SCAN_APPLY_GATE_SEVERITY": "critical"},
    )
    # No critical -> not denied; the normal permission prompt applies.
    assert decision_of(out) == "ask"
    assert "no unfixed findings" in out["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.slow
@requires_checkov
def test_real_scan_degraded_asks(tmp_path, monkeypatch):
    """If checkov cannot run, the scan is degraded -> `ask`, never allow."""
    (tmp_path / "main.tf").write_text(_RDS_CRITICAL_TF, encoding="utf-8")
    # Force run_checkov to find no binary by pointing CHECKOV_BIN at nothing.
    monkeypatch.setenv("CHECKOV_BIN", "/nonexistent/checkov-binary")
    out = apply_gate.decide(
        bash_apply(cwd=str(tmp_path)),
        env={"IAC_SECURITY_SCAN_APPLY_GATE": "block"},
    )
    assert decision_of(out) == "ask"
    assert "NOT cleared" in out["hookSpecificOutput"]["permissionDecisionReason"]
