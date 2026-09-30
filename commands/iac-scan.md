---
description: Scan Infrastructure as Code for security misconfigurations, map to NIST 800-53 / FedRAMP controls, and generate validated remediation IaC.
argument-hint: "[path] [--compliance 800-53] [--fix] [--format markdown|json|sarif] [--severity critical|high|medium|low] [--iac-format terraform|cloudformation|kubernetes|docker-compose]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Agent
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/iac-security-scan/scripts/parse_iac.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/iac-security-scan/scripts/run_checkov.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/iac-security-scan/scripts/merge_findings.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/iac-security-scan/scripts/report.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/iac-security-scan/scripts/emit_sarif.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/iac-security-scan/scripts/baseline.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/iac-security-scan/scripts/patch_terraform.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/iac-security-scan/scripts/patch_cloudformation.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/iac-security-scan/scripts/fix_apply.py *)
---

# /iac-scan

Arguments: `$ARGUMENTS`

The first token that does not start with `--` is the path to scan (default: the
current directory). Every other token is a flag from the table below.

## Flags

| Flag | Values | Default | Meaning |
|---|---|---|---|
| `--compliance` | `800-53` | off | Add the control-coverage section |
| `--fix` | — | off | Apply `autoApplicable` fixes on a new branch (Terraform, CloudFormation) |
| `--format` | `markdown`, `json`, `sarif` | `markdown` | Output format |
| `--severity` | `critical`, `high`, `medium`, `low` | `medium` | Reporting floor; also the CI gate threshold |
| `--iac-format` | `terraform`, `cloudformation`, `kubernetes`, `docker-compose` | detected | Parser and Checkov framework set. Kubernetes and Compose are findings-only |
| `--cross-check` | — | off | **Experimental, opt-in.** Second opinion from OpenAI Codex. Sends findings and IaC off the machine to OpenAI |
| `--live` | — | off | **Experimental, opt-in.** Read-only verification against the ambient AWS account. Not yet run against a real account |

## Exit codes

- `0` — clean at or above the `--severity` floor
- `1` — findings at or above the floor
- `2` — scan error

## Execution

Invoke the `iac-security-scan` skill with the parsed path and flags. The skill owns the
full workflow: parse → Checkov → merge/enrich → fix → report, and lists the exact script
invocations.

**Non-negotiables, regardless of flags:**

- A degraded scan is reported as degraded, loudly. A scan that found nothing because
  it could not read the files must never look like a scan that found nothing because
  the files were clean.
- Compliance mappings and baseline severities come from checked-in data files only.
  Never generate a control ID or a baseline severity at runtime.
- `--fix` never touches a dirty tree, always works on a new branch and returns to the
  original one, and never auto-applies an access-affecting change.
- `--cross-check` and `--live` run only when the user asked for them on this
  invocation; never enable either on your own.
