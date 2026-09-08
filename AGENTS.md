# Global Codex Guidance
Applies to every Codex session on this machine; defer to repo or subdirectory AGENTS.md when they provide more specific instructions.

## How to use this file
- Skim once at the start of a session to align on global policies.
- Follow project or folder AGENTS.md files for task-specific commands and nuances.
- Ask the user when instructions conflict or feel unsafe.

## Operating mode
- Host: untouched unless user explicitly requests host changes. Assume you are running on a macOS host (Apple Silicon)
- Execution: run deterministically, show diffs, prefer smallest verifiable unit (lint/typecheck/test). Stop on failure.
- Sensitive files: never touch `.env`, secrets, infra config, or production data without explicit instruction.

## Models
- Prefer `gpt-5.2-codex`. If unavailable, state active model and limitations.

## Agent conduct
- Verify assumptions before executing commands; call out uncertainties first.
- Ask for clarification when the request is ambiguous, destructive, or risky.
- Summarize intent before performing multi-step fixes so the user can redirect early.
- Cite the source when using documentation; quote exact lines instead of paraphrasing from memory.
- Break work into incremental steps and confirm each step with the smallest relevant check before moving on.
- Assess any code you write for vulnerabilities, if vulnerabilities are identified, make it known.

## Documentation and MCP
- Use Context7 via MCP for up-to-date, version-specific docs.
- Always `resolve-library-id` before `get-library-docs` unless ID is known.
- Fetch minimal targeted docs. Summarize inline; do not paste dumps.
- When API uncertainty remains: produce a runnable repro snippet and verify locally.
- If the needed documentation cannot be found, say so explicitly and explain the fallback approach.
- If you already know the Context7 library ID (e.g. `/supabase/supabase`), provide it directly to skip resolution.

## Project guidance (NetworkScanner)
- Stack: TypeScript + Node ESM; build output in `dist/` from `tsc -p tsconfig.json`.
- Prefer editing source in `src/`, `tests/`, and `examples/`; avoid manual edits in generated `dist/` or `artifacts/`.
- Common commands:
  - `npm run build` (TypeScript compile)
  - `npm test` (build + node test runner on `dist/tests/*.test.js`)
  - `npm run dev` (API server; requires build output in `dist/`)
  - `npm run scan -- --source meraki [--emit-raw]`
  - `npm run example:mock`
- Artifacts: scans write to `artifacts/scan-<scanId>/results.json` and `raw.json` when `--emit-raw` is set.
- Meraki env vars for scans: `MERAKI_DASHBOARD_API_KEY` required; optional `MERAKI_ORG_ID`, `MERAKI_ORG_NAME`, `MERAKI_NETWORK_ID`.
