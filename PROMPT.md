# Session prompt: spec `iac-security-scan` (morph of infrabot)

Paste the block below into a fresh Claude Code session.

---

```text
You are helping John (0-to-1 Labs) re-form his existing `infrabot` project into a
new Claude Code marketplace plugin, `iac-security-scan`. Your ONLY job this session
is to produce a written SPEC (design doc) — do NOT implement it.

## Context
- `~/dev/infrabot` is today an AWS security-assessment CLI: multi-agent Claude that
  discovers live AWS resources, finds security issues, and generates remediation IaC.
  We are DISCARDING the CLI form factor and re-forming the useful parts as a plugin.
- Target plugin: `iac-security-scan`, published to John's marketplace. Conventions:
  each plugin is its own GitHub repo `johnpsasser/<repo>`, referenced from
  `0-to-1-Labs/claude-marketplace` (`.claude-plugin/marketplace.json`; the local
  marketplace name is `0-to-1-labs`). Plugin layout: `.claude-plugin/plugin.json`
  (its `name` MUST equal the catalog entry), auto-discovered `commands/`,
  `skills/<name>/SKILL.md`, `agents/`, `hooks/hooks.json`; script paths use
  `${CLAUDE_PLUGIN_ROOT}`. A non-interactive `claude plugin ...` CLI exists.
- Sibling to pair with: `iac-diagram-generator` (`~/dev/iac-diagram-generator`,
  handles Terraform / CloudFormation / Kubernetes / Docker Compose). This plugin
  should target the same IaC formats and complement it (scan + diagram).
- Read for packaging/UX conventions before writing: `~/dev/iac-diagram-generator`,
  `~/dev/codex-pr-review` (dual-track install.sh + /plugin), `~/dev/memex`.
- Models: current IDs ONLY — Claude Opus 4.8 (`claude-opus-4-8`) for analysis
  agents; a `codex-dispatch` pattern exists for routing to GPT-5.6 if a cross-family
  second opinion is wanted; Gemini is used only for diagrams. If unsure about any
  model string, consult the claude-api skill — do not use stale IDs.

## Product decisions already made (build the spec around these)
1. Scan target: STATIC IaC primary, LIVE AWS optional. Default scans IaC files in
   the repo with no cloud creds; when AWS creds are present, an optional live pass
   verifies findings against the deployed account.
2. Compliance: configurable. Security best-practice findings by default; a
   `--compliance 800-53` mode adds NIST 800-53 control IDs + FedRAMP baseline
   mapping to each finding. (Note where this overlaps a separate `compliance-review`
   plugin idea and recommend how they should relate.)
3. Output: findings + remediation IaC. Severity-ranked report AND generated
   corrected/remediation IaC (infrabot's strongest feature). Consider an opt-in
   `--fix` that applies remediation to the working tree.

## Do this, in order
1. Read `~/dev/infrabot` end to end (README, src, agent prompts, finding taxonomy,
   remediation logic, package.json). Produce a "salvage inventory": what to port
   (agent prompts, finding schema, remediation logic), discard (CLI plumbing),
   rebuild.
2. Skim the reference plugins for packaging/UX conventions.
3. INTERVIEW John on the open questions you surface — ask, don't assume. At minimum:
   exact IaC formats for the MVP, command name + invocation UX, how live-mode creds
   are handled, and whether it must emit machine-readable output (JSON/SARIF) for CI.
4. Write the spec to `~/dev/iac-security-scan/SPEC.md`.

## The spec must cover
- Overview, goals, and differentiation (compliance mapping + remediation IaC +
  pairing with iac-diagram-generator) vs. built-in `/security-review` and generic
  scanners (tfsec/checkov/etc.).
- Scope in/out; IaC formats for MVP vs later.
- The two scan modes (static primary, live-AWS optional) and how they interact.
- Findings schema: fields, severity model, rule IDs, optional 800-53/FedRAMP mapping.
- `--compliance 800-53` behavior.
- Remediation IaC generation: format, how presented (diff vs separate file), safety,
  optional `--fix`.
- Plugin components + invocation UX: command name/args, which agents/skills/hooks,
  `${CLAUDE_PLUGIN_ROOT}` usage.
- Model usage: which model does what (current IDs); optional GPT-5.6 cross-check.
- Credentials & security for live mode: never persist/exfiltrate creds; read-only.
- Output for humans AND CI (report + JSON/SARIF?).
- Packaging & release: repo name, plugin.json, catalog entry, install path(s),
  testing approach.
- Phasing: a concrete MVP (suggest static scan + findings + remediation on Terraform)
  and follow-on phases (live verification, 800-53 mode, more formats).
- Open questions & risks.

Deliverable: `~/dev/iac-security-scan/SPEC.md`. No implementation code this session.
```

---

## Decisions already locked (2026-07-13)

| Decision | Choice |
|---|---|
| Scan target | Static IaC primary; live AWS optional when creds present |
| Compliance | Configurable — security findings by default, `--compliance 800-53` adds control IDs + FedRAMP baseline |
| Output | Findings report **+ generated remediation IaC**; consider opt-in `--fix` |
| Old form factor | Discard the CLI; salvage agent prompts / finding schema / remediation logic |
