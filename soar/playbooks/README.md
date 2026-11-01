# SOAR Playbooks

> **Status: placeholder (Phase 2).**

This directory will hold Splunk SOAR playbooks that respond to the detections in
[`detections/`](../../detections). The first planned playbook is a response to
`AWS IAM Access Key Created for a Different User`:

1. Enrich: look up the caller and target IAM users, attached policies, and key age.
2. Contain (approval-gated): deactivate the newly created access key.
3. Notify: open a case with the CloudTrail evidence and the analyst decision.

All playbook content in this repo is built and exercised against **lab
simulations only**, not production environments or real incidents.
