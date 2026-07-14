---
description: Scan Infrastructure as Code for security misconfigurations, map to NIST 800-53 / FedRAMP controls, and generate validated remediation IaC.
argument-hint: "[path] [--compliance 800-53] [--fix] [--format markdown|json|sarif] [--severity critical|high|medium|low]"
allowed-tools: Read, Bash, Glob, Grep, Edit, Agent
---

# /iac-scan

Scan the Infrastructure as Code at `$1` (default: current directory) for security
misconfigurations.

## Flags

| Flag | Values | Default | Meaning |
|---|---|---|---|
| `--compliance` | `800-53` | off | Add the control-coverage section |
| `--fix` | — | off | Apply `autoApplicable` fixes on a new branch |
| `--format` | `markdown`, `json`, `sarif` | `markdown` | Output format |
| `--severity` | `critical`, `high`, `medium`, `low` | `medium` | Reporting floor; also the CI gate threshold |
| `--live` | — | off | Read-only verification of static findings (Phase 4) |
| `--output-mode` | `diff`, `module` | `diff` | Shape of generated remediation |

## Exit codes

- `0` — clean at or above the `--severity` floor
- `1` — findings at or above the floor
- `2` — scan error

## Execution

Invoke the `iac-security-scan` skill with the parsed arguments. The skill owns the
full workflow: parse → Checkov → merge/enrich → fix → report.

**Non-negotiables, regardless of flags:**

- A degraded scan is reported as degraded, loudly. A scan that found nothing because
  it could not read the files must never look like a scan that found nothing because
  the files were clean.
- Compliance mappings and baseline severities come from checked-in data files only.
  Never generate a control ID or a baseline severity at runtime.
- `--fix` never touches a dirty tree, always works on a new branch, and never
  auto-applies an access-affecting change.
