# hooks/ — the opt-in `terraform apply` security gate

This directory ships a PreToolUse hook that can gate `terraform apply` on unfixed
security findings. **It is disabled by default and does nothing until you turn it on.**
Two design rules make it safe to ship at all:

1. **Installing the plugin arms nothing.** The hook is *not* wired in
   `.claude-plugin/plugin.json`, and there is deliberately **no** `hooks/hooks.json`
   (Claude Code auto-loads that file, which would arm the gate on install). The
   registration snippet ships as `hooks.json.example`, which is never loaded.

2. **It never auto-approves.** The hook answers `ask` or `deny`, never `allow`. If
   Checkov is missing, the scan errors or times out, the command cannot be parsed, or
   the hook itself throws, you get your normal permission prompt with the gate's
   verdict attached — never a wedged deploy, and never a pre-approved one. The `deny`
   path is reachable only when a scan actually ran and actually found a blocking
   finding in `block` mode.

## Files

| File | Purpose |
|---|---|
| `apply_gate.py` | The hook. Deterministic Checkov scan of the target dir, seeded severities, decision per mode. |
| `hooks.json.example` | The registration snippet in plugin hooks-file shape. Never loaded; copy it into your `.claude/settings.json`. |
| `iac-security-scan.local.md.example` | Template for the per-project enable flag. Copy to `.claude/iac-security-scan.local.md`. |

## Enable (two independent gates, both off by default)

**Step 1 — register** the hook (this only makes it *run*, not *block*). Put the
`hooks` block into your project's `.claude/settings.json` with an absolute path to the
installed plugin (`claude plugin details iac-security-scan@0-to-1-labs` prints it).
The top-level `hooks` key is required; without it nothing is registered.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"/absolute/path/to/iac-security-scan/hooks/apply_gate.py\"",
            "timeout": 150
          }
        ]
      }
    ]
  }
}
```

`hooks.json.example` shows the same block with `"${CLAUDE_PLUGIN_ROOT}"`, which only
resolves inside a plugin's own hooks file. Do not copy files into the installed plugin
directory: it is replaced on every plugin update. Confirm the registration with
`/hooks` after restarting Claude Code.

**Step 2 — flip the flag** by creating `.claude/iac-security-scan.local.md` at the
project root:

```markdown
---
apply_gate: block            # off (default) | warn | ask | block
apply_gate_severity: critical  # critical | high | medium | low
apply_gate_timeout: 120        # seconds; scan is bounded, a timeout -> ask
---
```

Until this file sets a mode other than `off`, `apply_gate.py`'s first action is to
no-op. The file is looked up under `$CLAUDE_PROJECT_DIR` (the project root Claude Code
exports to hooks) first, then under the session's working directory, so a `cd` into a
subdirectory does not switch the gate off. Environment variables override the file
(useful in CI): `IAC_SECURITY_SCAN_APPLY_GATE`, `IAC_SECURITY_SCAN_APPLY_GATE_SEVERITY`,
`IAC_SECURITY_SCAN_APPLY_GATE_TIMEOUT`.

## Modes

- `off` — disabled (default). Instant no-op.
- `warn` — ask, with a loud warning listing the findings in the prompt.
- `ask` — ask you to confirm before applying, findings listed.
- `block` — deny the apply, listing the findings and how to bypass (fix, or set
  `apply_gate: off`).

A clean scan is `ask` in every mode: the gate does not pre-approve.

## Scope & bounds

Gated: `terraform apply`, `tofu apply`, `terragrunt apply` / `terragrunt run-all apply`,
including behind `env`, `time`, `sudo`, `sh -c '...'`, with `-chdir=DIR`, and after a
`cd DIR` earlier in the same command line (the scan follows the `cd`). A command that
mentions an apply but hides it behind `$(...)`, backticks, a `$VAR`, or `eval` cannot be
parsed and resolves to `ask`. Every other Bash command passes through untouched. The
scan is deterministic (Checkov + the checked-in `data/rule-severity.json` seed — no LLM,
no network) and runs against the **target directory only**, with a hard timeout.
Findings whose seeded severity is `unmapped` never gate an apply — we don't block on a
severity we didn't review.

Hook changes require restarting Claude Code (`/hooks` shows what's loaded).
