# Detection-as-Code

[![CI](https://github.com/rgarritano-claude/detection-as-code/actions/workflows/ci.yml/badge.svg)](https://github.com/rgarritano-claude/detection-as-code/actions/workflows/ci.yml)

Cloud threat detections written once in [Sigma](https://sigmahq.io), compiled to
Splunk SPL, and paired with Splunk SOAR response playbooks. Detections and
playbooks are gated by automated tests in CI, the same way application code is
built, reviewed, and shipped.

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
| AWS IAM access key created by an assumed-role or federated caller | AWS CloudTrail | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Additional Cloud Credentials | Medium | [rule](detections/sigma/aws/cloudtrail/aws_iam_create_access_key_by_role_or_federated_caller.yml) | [spl](detections/splunk/aws/cloudtrail/aws_iam_create_access_key_by_role_or_federated_caller.spl) |

### Spotlight: IAM access-key persistence (T1098.001)

An identity that can call `iam:CreateAccessKey` on other users can mint
long-lived credentials for a more privileged account. Those keys survive a
password reset or session revocation of the original foothold, which makes this
a well-known persistence and privilege-escalation path. Two companion rules
split coverage by caller type:

| Caller (`userIdentity.type`) | Rule | Logic |
|---|---|---|
| `IAMUser` | Access key created for a different user | Target `requestParameters.userName` differs from the caller's `userIdentity.userName` |
| `AssumedRole`, `FederatedUser` | Access key created by an assumed-role or federated caller | Any successful key creation (roles and federated sessions can't own access keys, so every key goes to an IAM user) |

Both rules exclude failed calls (`errorCode` present). Generated SPL for the
IAM-user rule:

```spl
sourcetype="aws:cloudtrail" eventSource="iam.amazonaws.com" eventName="CreateAccessKey" userIdentity.type="IAMUser" requestParameters.userName=* NOT errorCode=*
| where NOT 'requestParameters.userName'='userIdentity.userName'
| table eventTime,userIdentity.arn,userIdentity.userName,requestParameters.userName,responseElements.accessKey.accessKeyId,sourceIPAddress,userAgent,recipientAccountId
```

**Remaining scope note:** callers using the root user (`userIdentity.type=Root`)
are not covered by either rule. Root activity belongs in a dedicated root-usage
detection, which isn't in this repo yet. Expect tuning for infrastructure-as-code
and identity-automation roles, which are listed in each rule's `falsepositives`.

## SOAR playbooks

| Playbook | Trigger | Outcomes | Docs |
|---|---|---|---|
| Phishing triage | User-reported email container | **Malicious:** quarantine, block sender, ticket · **Suspicious:** analyst review · **Clean:** auto-close | [README + flow diagram](soar/playbooks/phishing_triage/README.md) |

The phishing playbook extracts URLs, domains, sender, and attachment hashes,
runs generic reputation actions in parallel, and joins on a single decision.
Automatic containment requires two or more engines to agree. Failed lookups and
text-only (BEC-style) emails go to an analyst, never to auto-close. The decision
logic is unit-tested offline against a mock of the SOAR `phantom` API.

## Repository structure

| Path | Purpose |
|---|---|
| `detections/sigma/` | Sigma rules, the single source of truth, organized by `<platform>/<log source>/` |
| `detections/splunk/` | SPL generated from Sigma by `scripts/convert.py`; never hand-edited |
| `scripts/convert.py` | Sigma to SPL conversion (pySigma + Splunk backend); `--check` mode detects drift |
| `scripts/pipelines/` | pySigma processing pipelines (e.g. CloudTrail sourcetype scoping) |
| `scripts/sigma_eval.py` | Lightweight evaluator that runs a Sigma rule against JSON events for unit tests |
| `tests/data/<rule>/` | Synthetic `true_positive/` and `benign/` sample events per rule |
| `tests/data/soar/<playbook>/` | Synthetic SOAR containers for playbook tests |
| `tests/mocks/phantom/` | Offline mock of the Splunk SOAR `phantom.rules` API |
| `tests/` | pytest suite: rule gates (parse, metadata, conversion, TP/benign) and playbook gates (structure, decision paths) |
| `soar/playbooks/<name>/` | Splunk SOAR playbooks (Python) with a README, Mermaid flow, and import steps |
| `docs/incidents/` | Lab-simulation incident write-ups (Phase 3, placeholder) |
| `.github/workflows/ci.yml` | CI: yamllint, conversion drift check, and pytest (detections + playbooks) on every push and PR |

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
| `make test` | Run the pytest suite (detections and SOAR playbooks) |
| `make all` | Everything CI runs (`lint`, `convert-check`, `test`) |

### Quality gates: detections (enforced for every rule)

1. Parses cleanly with pySigma.
2. Has an ATT&CK technique tag, level, description, false positives, and references.
3. Converts to SPL, and the committed `.spl` matches the conversion byte for byte.
4. Fires on every `true_positive/` sample and on no `benign/` sample.
5. Every sample is labeled `"_meta": {"synthetic": true}`.

### Quality gates: SOAR playbooks (enforced for every playbook)

1. Layout is `soar/playbooks/<name>/<name>.py` plus a README with a Mermaid diagram and a lab-simulation label.
2. Parses as Python 3.9 and defines `on_start` and `on_finish`.
3. No hard-coded credential markers.
4. Playbook-specific tests cover every outcome branch and the failure paths.

## Roadmap

- **Phase 1 (done):** scaffold, CI, and an end-to-end CloudTrail detection.
- **Phase 2 (this release):** companion CloudTrail detection for role and federated callers, plus a Splunk SOAR phishing-triage playbook with offline tests.
- **Next:** SOAR response playbook for the IAM access-key detections, a root-user activity detection, a Kubernetes detection, and a lab-simulation incident write-up.

## License

[MIT](LICENSE)
