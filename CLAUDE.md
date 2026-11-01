# CLAUDE.md: repo conventions

Detection-as-code portfolio for a Cloud Security Architect. Audience: recruiters
and hiring managers, so keep content professional, accurate, and readable.

## Hard rules

- **Never invent** employers, clients, metrics, or real incidents. Anything
  scenario-based is a **lab simulation** and must say so.
- Sample data uses only placeholders: AWS account `123456789012`, RFC 5737 IPs
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), AWS example key
  `AKIAIOSFODNN7EXAMPLE`, `lab-` prefixed user names, and RFC 2606 domains
  (`example.com`, `example.net`).
- README files contain no author/bio section.
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

## Adding a SOAR playbook

1. Layout: `soar/playbooks/<name>/<name>.py` + `soar/playbooks/<name>/README.md`,
   and add a row to `soar/playbooks/README.md`.
2. Standard Splunk SOAR structure: `import phantom.rules as phantom`,
   `on_start(container)`, `on_finish(container, summary)`, block functions with
   the SOAR callback signature (`action=None, success=None, container=None,
   results=None, handle=None, ..., **kwargs`), `phantom.act(..., name=, callback=)`,
   and `phantom.collect2()` for datapaths.
3. Parallel actions must join through a function guarded by
   `phantom.completed(action_names=[...])` and a run-data flag so the next block
   runs exactly once.
4. Keep decision logic in **pure functions** (no `phantom` calls) so it can be
   unit-tested directly. Fail safe: errors and missing data go to a human, never
   to auto-close.
5. Configuration (asset names, result datapaths, thresholds) sits in a
   CONFIGURATION block at the top. Use generic action names ("url reputation")
   and `lab_` asset names. **No credentials, API keys, or real hostnames.**
6. Python 3.9 syntax only (tests enforce this).
7. README needs a Mermaid ```` ```mermaid ```` flow diagram, the decision table,
   configuration, SOAR import steps, and the words "lab simulation" (tests enforce
   the diagram and the label).
8. Tests: `tests/test_soar_<name>.py` using the offline mock at
   `tests/mocks/phantom/rules.py` (`phantom_mock.reset(container, responders)`).
   Cover every outcome branch plus failure/edge cases. Fixture containers go in
   `tests/data/soar/<name>/` with `_meta.synthetic: true`. Extend the mock
   (with the real API's signature) if a playbook needs another `phantom` call.
   `tests/test_soar_playbooks.py` applies structure gates to every playbook
   automatically.

## Tooling

- Python 3.11, versions pinned in `requirements.txt`. Upgrade deliberately and
  review the resulting SPL diff.
- `make lint` / `make convert` / `make convert-check` / `make test` / `make all`.
- CI (`.github/workflows/ci.yml`) runs lint, convert-check, and pytest (detections
  and SOAR playbooks) on push and PR. New tests under `tests/` run automatically.
- Log-source specifics (sourcetypes, field mappings) live in
  `scripts/pipelines/*.yml`, not in rules.

## Git

- Small, logical commits with descriptive messages.
- Work on feature branches; PRs target `main`.
