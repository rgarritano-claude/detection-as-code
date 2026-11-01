# SOAR Playbooks

Splunk SOAR playbooks, each in `soar/playbooks/<name>/` with the playbook
(`<name>.py`) and a README that has a Mermaid flow diagram and import steps.

| Playbook | Trigger | Outcomes |
|---|---|---|
| [phishing_triage](phishing_triage/) | User-reported email container | Malicious: quarantine, block sender, ticket · Suspicious: analyst review · Clean: auto-close |

**Planned:** a response playbook for the IAM access-key detections in
[`detections/`](../../detections). It would enrich caller and target, then deactivate
the new key after approval, then write case notes.

All playbooks are built and tested offline against **lab simulations** using the
`phantom` mock in [`tests/mocks/`](../../tests/mocks). They do not describe
production deployments or real incidents.
