# Detection-as-Code

[![CI](https://github.com/rgarritano-claude/detection-as-code/actions/workflows/ci.yml/badge.svg)](https://github.com/rgarritano-claude/detection-as-code/actions/workflows/ci.yml)

Cloud threat detections written once in [Sigma](https://sigmahq.io), compiled to
Splunk SPL, and gated by automated tests in CI, the same way application code
is built, reviewed, and shipped.

Each detection in this repo ships with:

- a **Sigma rule** with MITRE ATT&CK mapping, documented false positives, and references
- **generated Splunk SPL**, rebuilt from the Sigma source and checked for drift in CI
- **synthetic sample events** (true-positive and benign) that prove the logic fires when it should and stays quiet when it shouldn't

> All sample data, scenarios, and write-ups are **lab simulations**. Account IDs,
> user names, and IPs are synthetic placeholders (AWS documentation account
> `123456789012`, RFC 5737 documentation IP ranges). Nothing here describes a real
> organization or incident.

## Detections

| Detection | Platform | ATT&CK | Level | Sigma | SPL |
|---|---|---|---|---|---|
| AWS IAM access key created for a different user | AWS CloudTrail | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Additional Cloud Credentials | Medium | [rule](detections/sigma/aws/cloudtrail/aws_iam_create_access_key_for_other_user.yml) | [spl](detections/splunk/aws/cloudtrail/aws_iam_create_access_key_for_other_user.spl) |

### Spotlight: access key created for another IAM user

An identity with `iam:CreateAccessKey` on other users can mint long-lived
credentials for a more privileged account. Those keys survive a password reset
and session revocation of the original foothold, which makes this a well-known
persistence and privilege-escalation path.

The rule flags successful `CreateAccessKey` calls where the target
`requestParameters.userName` differs from the calling IAM user. Self-service key
creation and denied attempts are excluded. Generated SPL:

```spl
sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com" eventName="CreateAccessKey" userIdentity.type="IAMUser" requestParameters.userName=* NOT errorCode=*
| where NOT 'requestParameters.userName'='userIdentity.userName'
| table eventTime,userIdentity.arn,userIdentity.userName,requestParameters.userName,responseElements.accessKey.accessKeyId,sourceIPAddress,userAgent,recipientAccountId
```

**Known gap:** callers using assumed roles or federation have no
`userIdentity.userName` to compare against, so this rule scopes to IAM-user
callers. A companion rule for role-initiated key creation is on the roadmap.

## Repository structure

| Path | Purpose |
|---|---|
| `detections/sigma/` | Sigma rules, the single source of truth, organized by `<platform>/<log source>/` |
| `detections/splunk/` | SPL generated from Sigma by `scripts/convert.py`; never hand-edited |
| `scripts/convert.py` | Sigma to SPL conversion (pySigma + Splunk backend); `--check` mode detects drift |
| `scripts/pipelines/` | pySigma processing pipelines (e.g. CloudTrail sourcetype scoping) |
| `scripts/sigma_eval.py` | Lightweight evaluator that runs a Sigma rule against JSON events for unit tests |
| `tests/data/<rule>/` | Synthetic `true_positive/` and `benign/` sample events per rule |
| `tests/` | pytest suite: parsing, metadata, conversion, and TP/benign matching for every rule |
| `soar/playbooks/` | Splunk SOAR response playbooks (Phase 2, placeholder) |
| `docs/incidents/` | Lab-simulation incident write-ups (Phase 3, placeholder) |
| `.github/workflows/ci.yml` | CI: yamllint, conversion drift check, and pytest on every push and PR |

## How to run

Requires Python 3.11 and `make`.

```bash
python3.11 -m venv .venv && source .venv/bin/activate
```

```bash
make install
```

| Command | What it does |
|---|---|
| `make lint` | `yamllint --strict` across rules, pipelines, and workflows |
| `make convert` | Regenerate SPL in `detections/splunk/` from every Sigma rule |
| `make convert-check` | Fail if committed SPL doesn't match a fresh conversion |
| `make test` | Run the pytest suite |
| `make all` | Everything CI runs (`lint`, `convert-check`, `test`) |

### Quality gates (enforced for every rule)

1. Parses cleanly with pySigma.
2. Has an ATT&CK technique tag, level, description, false positives, and references.
3. Converts to SPL, and the committed `.spl` matches the conversion byte for byte.
4. Fires on every `true_positive/` sample and on no `benign/` sample.
5. Every sample is labeled `"_meta": {"synthetic": true}`.

## Roadmap

- **Phase 1 (this release):** scaffold, CI, and one end-to-end CloudTrail detection.
- **Phase 2:** Splunk SOAR playbook for the access-key detection (enrich, approval-gated key deactivation, case notes).
- **Phase 3:** Kubernetes detection and a lab-simulation incident write-up.

## License

[MIT](LICENSE)
