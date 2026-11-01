# Incident Write-ups

Incident-style write-ups that walk the repo's detections from alert through
triage, containment, eradication, recovery, and lessons learned.

**Every write-up here is a lab simulation.** Account IDs, user names, IP
addresses, domains, and timelines are synthetic: the AWS documentation
placeholder account `123456789012`, RFC 5737 documentation IP ranges, and
RFC 2606 domains. None of them describes a real organization, employer, client,
or incident.

| Write-up | Platform | Scenario | Detections exercised |
|---|---|---|---|
| [Kubernetes service account compromise to cryptominer](2026-lab-k8s-service-account-compromise.md) | Kubernetes | Exposed workload → stolen SA token → cluster-admin binding → privileged pod → cryptominer | 3 Kubernetes audit rules |

Each write-up links to the synthetic audit events (in `tests/data/`) that the
detections are tested against, so the "how it fired" sections can be checked by
running `make test`.
