# hooks/ — the opt-in `terraform apply` security gate

This directory ships a PreToolUse hook that can gate `terraform apply` on unfixed
security findings. **It is disabled by default and does nothing until you turn it on.**
Two design rules make it safe to ship at all:

1. **Installing the plugin arms nothing.** The hook is *not* wired in
   `.claude-plugin/plugin.json`, and there is deliberately **no** `hooks/hooks.json`
   (Claude Code auto-loads that file, which would arm the gate on install). The
   registration snippet ships as `hooks.json.example`, which is never loaded.

2. **It fails open.** If Checkov is missing, the scan errors, times out, or the hook
   throws, the apply is **allowed** with a loud explanation — never denied. The deny
   path is reachable only when a scan actually ran and actually found a blocking finding.

## Files

| File | Purpose |
|---|---|
| `apply_gate.py` | The hook. Deterministic Checkov scan of the target dir, seeded severities, decision per mode. |
| `hooks.json.example` | Opt-in registration snippet. Copy into your `.claude/settings.json` (or to `hooks/hooks.json`) to register the hook. |
| `iac-security-scan.local.md.example` | Template for the per-project enable flag. Copy to `.claude/iac-security-scan.local.md`. |

## Enable (two independent gates, both off by default)

**Step 1 — register** the hook (this only makes it *run*, not *block*):

```jsonc
// .claude/settings.json
{
  "PreToolUse": [
    { "matcher": "Bash",
      "hooks": [ { "type": "command",
                   "command": "python3 /absolute/path/to/hooks/apply_gate.py",
                   "timeout": 150 } ] }
  ]
}
```

Inside the plugin you can instead copy `hooks.json.example` to `hooks/hooks.json` and use
`${CLAUDE_PLUGIN_ROOT}`.

**Step 2 — flip the flag** by creating `.claude/iac-security-scan.local.md`:

```markdown
---
apply_gate: block            # off (default) | warn | ask | block
apply_gate_severity: critical  # critical | high | medium | low
apply_gate_timeout: 120        # seconds; scan is bounded, times out -> fail open
---
```

Until this file sets a mode other than `off`, `apply_gate.py`'s first action is to
no-op. Environment variables override the file (useful in CI):
`IAC_SECURITY_SCAN_APPLY_GATE`, `IAC_SECURITY_SCAN_APPLY_GATE_SEVERITY`,
`IAC_SECURITY_SCAN_APPLY_GATE_TIMEOUT`.

## Modes

- `off` — disabled (default). Instant no-op.
- `warn` — allow the apply, surface a loud warning listing the findings.
- `ask` — ask you to confirm before applying.
- `block` — deny the apply, listing the findings and how to bypass (fix, or set
  `apply_gate: off`).

## Scope & bounds

Only `terraform apply` / `tofu apply` (honoring `terraform -chdir=DIR apply`) is gated;
every other Bash command passes through untouched. The scan is deterministic (Checkov +
the checked-in `data/rule-severity.json` seed — no LLM, no network) and runs against the
**target directory only**, with a hard timeout. Findings whose seeded severity is
`unmapped` never gate an apply — we don't block on a severity we didn't review.

Hook changes require restarting Claude Code (`/hooks` shows what's loaded).
