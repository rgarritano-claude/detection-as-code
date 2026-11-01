# CLAUDE.md: repo conventions

Detection-as-code portfolio for a Cloud Security Architect. Audience: recruiters
and hiring managers, so keep content professional, accurate, and readable.

## Hard rules

- **Never invent** employers, clients, metrics, or real incidents. Anything
  scenario-based is a **lab simulation** and must say so.
- Sample data uses only placeholders: AWS account `123456789012`, RFC 5737 IPs
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), AWS example key
  `AKIAIOSFODNN7EXAMPLE`, and `lab-` prefixed user names.
- Sigma is the source of truth. **Never hand-edit** `detections/splunk/*.spl`;
  change the Sigma rule or a pipeline and run `make convert`.
- Do not include AI model identifiers in commits, PRs, or files.

## Adding a detection

1. Rule: `detections/sigma/<platform>/<logsource>/<snake_case_name>.yml`
   - New UUIDv4 `id`, `status: experimental` until validated on real telemetry
   - `description` states the logic **and** any scope limits or known gaps
   - `tags`: ATT&CK tactic(s) (`attack.persistence`) plus technique (`attack.t1098.001`)
   - `falsepositives`, `level`, `references` (ATT&CK + vendor docs) are required
   - Prefer explicit `selection and not filter_a and not filter_b` when a filter
     uses `|fieldref`; the Splunk backend can't OR fieldref comparisons
2. SPL: `make convert` writes `detections/splunk/<same path>.spl`. Commit it.
3. Samples: `tests/data/<rule file stem>/true_positive/*.json` and `benign/*.json`.
   Each file is `{"_meta": {"synthetic": true, "note": "...", "description": "..."}, "event": {...}}`.
   At least one TP and one benign. Benign samples should cover each filter branch.
4. `make all` must pass. Tests are generic and pick up new rules automatically;
   add evaluator support in `scripts/sigma_eval.py` (with a unit test) if a rule
   uses a modifier it doesn't handle, rather than skipping the test.

## Tooling

- Python 3.11, versions pinned in `requirements.txt`. Upgrade deliberately and
  review the resulting SPL diff.
- `make lint` / `make convert` / `make convert-check` / `make test` / `make all`.
- CI (`.github/workflows/ci.yml`) runs lint, convert-check, and test on push and PR.
- Log-source specifics (sourcetypes, field mappings) live in
  `scripts/pipelines/*.yml`, not in rules.

## Git

- Small, logical commits with descriptive messages.
- Work on feature branches; PRs target `main`.
