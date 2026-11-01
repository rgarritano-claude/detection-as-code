# Detection-as-Code

[![CI](https://github.com/rgarritano-claude/detection-as-code/actions/workflows/ci.yml/badge.svg)](https://github.com/rgarritano-claude/detection-as-code/actions/workflows/ci.yml)

Cloud and Kubernetes threat detections written once in [Sigma](https://sigmahq.io),
compiled to Splunk SPL, paired with Splunk SOAR response playbooks, and exercised
end to end in a lab-simulation incident write-up. Detections and playbooks are
gated by automated tests in CI, the same way application code is built, reviewed,
and shipped.

**At a glance:** 5 detections (AWS CloudTrail, Kubernetes audit) · 1 SOAR playbook · 1 incident write-up, all validated in CI.

Each detection in this repo ships with:

- a **Sigma rule** with MITRE ATT&CK mapping, documented false positives, and references
- **generated Splunk SPL**, rebuilt from the Sigma source and checked for drift in CI
- **synthetic sample events** (true-positive and benign) that prove the logic fires when it should and stays quiet when it shouldn't

> All sample data, scenarios, and write-ups are **lab simulations**. Account IDs,
> user names, IPs, and domains are synthetic placeholders (AWS documentation account
> `123456789012`, RFC 5737 documentation IP ranges, RFC 2606 domains). Nothing here
> describes a real organization or incident.

## Detections

| Detection | Platform | ATT&CK | Level | Sigma | SPL |
|---|---|---|---|---|---|
| AWS IAM access key created for a different user | AWS CloudTrail | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Additional Cloud Credentials | Medium | [rule](detections/sigma/aws/cloudtrail/aws_iam_create_access_key_for_other_user.yml) | [spl](detections/splunk/aws/cloudtrail/aws_iam_create_access_key_for_other_user.spl) |
| AWS IAM access key created by an assumed-role or federated caller | AWS CloudTrail | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Additional Cloud Credentials | Medium | [rule](detections/sigma/aws/cloudtrail/aws_iam_create_access_key_by_role_or_federated_caller.yml) | [spl](detections/splunk/aws/cloudtrail/aws_iam_create_access_key_by_role_or_federated_caller.spl) |
| Kubernetes ClusterRoleBinding grants cluster-admin to a non-system subject | Kubernetes audit | [T1098.006](https://attack.mitre.org/techniques/T1098/006/) Additional Container Cluster Roles | High | [rule](detections/sigma/kubernetes/audit/k8s_cluster_admin_binding_to_non_system_subject.yml) | [spl](detections/splunk/kubernetes/audit/k8s_cluster_admin_binding_to_non_system_subject.spl) |
| Kubernetes privileged pod or hostPath mount created outside kube-system | Kubernetes audit | [T1610](https://attack.mitre.org/techniques/T1610/) Deploy Container, [T1611](https://attack.mitre.org/techniques/T1611/) Escape to Host | High | [rule](detections/sigma/kubernetes/audit/k8s_privileged_pod_or_hostpath_outside_kube_system.yml) | [spl](detections/splunk/kubernetes/audit/k8s_privileged_pod_or_hostpath_outside_kube_system.spl) |
| Kubernetes exec into a pod in kube-system | Kubernetes audit | [T1609](https://attack.mitre.org/techniques/T1609/) Container Administration Command | Medium | [rule](detections/sigma/kubernetes/audit/k8s_exec_into_kube_system_pod.yml) | [spl](detections/splunk/kubernetes/audit/k8s_exec_into_kube_system_pod.spl) |

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

### Spotlight: Kubernetes audit coverage

Three rules on API server audit logs cover the escalation, deployment, and
hands-on-keyboard stages of a cluster compromise:

| Stage | Rule | Key logic |
|---|---|---|
| Privilege escalation | cluster-admin binding to a non-system subject | `create`/`update` of a ClusterRoleBinding with `roleRef.name=cluster-admin`; excludes `system:` subjects and kube-system service accounts |
| Node access | Privileged pod or hostPath outside kube-system | Pod create with any `privileged: true` container or init container, or any `hostPath` volume |
| Interactive access | Exec into kube-system | `pods/exec` in kube-system over both SPDY (`create`) and WebSocket (`get`) streaming |

The rules need an audit policy that logs RBAC and pod writes at `Request` level or
higher. The recommended policy is in the
[incident write-up](docs/incidents/2026-lab-k8s-service-account-compromise.md#audit-policy).
Each rule's `description` lists its remaining gaps (e.g. `patch` requests,
ephemeral containers, `pods/attach`).

## SOAR playbooks

| Playbook | Trigger | Outcomes | Docs |
|---|---|---|---|
| Phishing triage | User-reported email container | **Malicious:** quarantine, block sender, ticket · **Suspicious:** analyst review · **Clean:** auto-close | [README + flow diagram](soar/playbooks/phishing_triage/README.md) |

The phishing playbook extracts URLs, domains, sender, and attachment hashes,
runs generic reputation actions in parallel, and joins on a single decision.
Automatic containment requires two or more engines to agree. Failed lookups and
text-only (BEC-style) emails go to an analyst, never to auto-close. The decision
logic is unit-tested offline against a mock of the SOAR `phantom` API.

## Incident write-ups

| Write-up | Scenario | Detections exercised |
|---|---|---|
| [Kubernetes service account compromise to cryptominer](docs/incidents/2026-lab-k8s-service-account-compromise.md) *(lab simulation)* | Exposed workload → stolen SA token → cluster-admin binding → privileged pod → cryptominer | All 3 Kubernetes rules |

The write-up includes a synthetic UTC timeline, how each detection matched (linked
to the committed sample events), triage SPL, containment through recovery, the
detection gaps it surfaced, RBAC/PSA/NetworkPolicy/audit-policy hardening, an
ATT&CK mapping table, and a Mermaid attack-flow diagram.

## Repository structure

| Path | Purpose |
|---|---|
| `detections/sigma/` | Sigma rules, the single source of truth, organized by `<platform>/<log source>/` |
| `detections/splunk/` | SPL generated from Sigma by `scripts/convert.py`; never hand-edited |
| `scripts/convert.py` | Sigma to SPL conversion (pySigma + Splunk backend); `--check` mode detects drift |
| `scripts/pipelines/` | pySigma processing pipelines: sourcetype scoping and field mappings per log source (CloudTrail, Kubernetes audit) |
| `scripts/sigma_eval.py` | Lightweight evaluator that runs a Sigma rule against JSON events (including arrays) for unit tests |
| `tests/data/<rule>/` | Synthetic `true_positive/` and `benign/` sample events per rule |
| `tests/data/soar/<playbook>/` | Synthetic SOAR containers for playbook tests |
| `tests/mocks/phantom/` | Offline mock of the Splunk SOAR `phantom.rules` API |
| `tests/` | pytest suite: rule gates (parse, metadata, conversion, TP/benign) and playbook gates (structure, decision paths) |
| `soar/playbooks/<name>/` | Splunk SOAR playbooks (Python) with a README, Mermaid flow, and import steps |
| `docs/incidents/` | Lab-simulation incident write-ups |
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
3. Converts to SPL scoped to a sourcetype, and the committed `.spl` matches the conversion byte for byte.
4. Fires on every `true_positive/` sample and on no `benign/` sample.
5. Every sample is labeled `"_meta": {"synthetic": true}`.

### Quality gates: SOAR playbooks (enforced for every playbook)

1. Layout is `soar/playbooks/<name>/<name>.py` plus a README with a Mermaid diagram and a lab-simulation label.
2. Parses as Python 3.9 and defines `on_start` and `on_finish`.
3. No hard-coded credential markers.
4. Playbook-specific tests cover every outcome branch and the failure paths.

## Roadmap

- **Phase 1 (done):** scaffold, CI, and an end-to-end CloudTrail detection.
- **Phase 2 (done):** companion CloudTrail detection for role and federated callers, plus a Splunk SOAR phishing-triage playbook with offline tests.
- **Phase 3 (done):** three Kubernetes audit detections and a Splunk pipeline for the audit sourcetype, a lab-simulation incident write-up, and CI on Node 24 action versions.
- **Next candidates:**
  - Detections for the gaps the incident surfaced: service-account token used from outside the cluster, cluster-wide secret enumeration, and denied-then-allowed escalation.
  - A root-user activity detection for CloudTrail.
  - A SOAR response playbook for the IAM access-key detections.

## License

[MIT](LICENSE)
