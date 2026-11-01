"""
Phishing Triage: Splunk SOAR playbook (lab build)

Triage for a user-reported phishing email container.

  1. Extract indicators from the container's artifacts: URLs, domains, sender,
     recipient, Message-ID, and attachment hashes.
  2. Run generic reputation actions in parallel ("url reputation",
     "domain reputation", "file reputation").
  3. Join, then classify the email as malicious, suspicious, or clean.
  4. Route:
       malicious  -> quarantine message, block sender, open ticket
       suspicious -> assign to an analyst for manual review
       clean      -> add a note and auto-close the container

Built and tested against lab simulations only. Asset names and reputation result
datapaths are configuration (see CONFIGURATION below) and must be mapped to the
apps installed on your SOAR instance. No credentials live in this file; SOAR
stores them on the asset.

Syntax is restricted to Python 3.9 for compatibility across Splunk SOAR
playbook runtime versions (enforced by tests/test_soar_playbooks.py).
"""

import json
from urllib.parse import urlparse

import phantom.rules as phantom

##############################################################################
# CONFIGURATION
##############################################################################

# SOAR asset names. Create these assets (or rename to match yours) under
# Apps -> <app> -> Configure New Asset.
ASSETS = {
    "url_reputation": "lab_threat_intel",
    "domain_reputation": "lab_threat_intel",
    "file_reputation": "lab_threat_intel",
    "email": "lab_mail_server",
    "ticketing": "lab_ticketing",
}

# Where each reputation action reports detection counts. Reputation apps
# differ, so point these at the summary fields your app actually returns.
MALICIOUS_COUNT_PATH = "action_result.summary.malicious"
SUSPICIOUS_COUNT_PATH = "action_result.summary.suspicious"

# Engines that must flag an indicator malicious before automatic containment.
# Anything weaker (1 engine, "suspicious" hits, failed lookups) goes to a human.
MALICIOUS_THRESHOLD = 2

# Role that owns emails needing manual review.
ANALYST_ROLE = "Tier 1 Analyst"

# Reputation action definitions: run-data key, SOAR action, parameter name.
REPUTATION_ACTIONS = [
    {"name": "url_reputation_1", "action": "url reputation", "indicator": "urls",
     "param": "url", "asset": "url_reputation"},
    {"name": "domain_reputation_1", "action": "domain reputation", "indicator": "domains",
     "param": "domain", "asset": "domain_reputation"},
    {"name": "file_reputation_1", "action": "file reputation", "indicator": "file_hashes",
     "param": "hash", "asset": "file_reputation"},
]

# CEF fields populated by SOAR email ingestion / the email parser.
ARTIFACT_DATAPATHS = {
    "urls": ["artifact:*.cef.requestURL"],
    "domains": ["artifact:*.cef.destinationDnsDomain"],
    "senders": ["artifact:*.cef.fromEmail"],
    "recipients": ["artifact:*.cef.toEmail"],
    "message_ids": ["artifact:*.cef.emailHeaders.Message-ID"],
    "file_hashes": ["artifact:*.cef.fileHashSha256", "artifact:*.cef.fileHash"],
}

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"


##############################################################################
# Pure helpers (no SOAR side effects, unit-tested directly)
##############################################################################

def _unique(values):
    """Order-preserving de-duplication that drops empty values."""
    seen = set()
    out = []
    for value in values:
        if value is None:
            continue
        value = str(value).strip()
        key = value.lower()
        if value and key not in seen:
            seen.add(key)
            out.append(value)
    return out


def _domain_of_email(address):
    if address and "@" in address:
        return address.rsplit("@", 1)[1].strip().lower()
    return None


def _host_of_url(url):
    try:
        host = urlparse(url if "://" in url else "http://" + url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def build_indicators(raw):
    """Normalize raw artifact values into the indicator set used by the playbook.

    Domains include those parsed from URLs and the sender's domain, so the
    sender infrastructure gets a reputation check even without links.
    """
    urls = _unique(raw.get("urls", []))
    senders = _unique(raw.get("senders", []))
    derived_domains = [_host_of_url(u) for u in urls] + [_domain_of_email(s) for s in senders]
    return {
        "urls": urls,
        "domains": _unique([d.lower() for d in raw.get("domains", []) if d] + derived_domains),
        "sender": senders[0] if senders else None,
        "recipient": (_unique(raw.get("recipients", [])) or [None])[0],
        "message_id": (_unique(raw.get("message_ids", [])) or [None])[0],
        "file_hashes": _unique([h.lower() for h in raw.get("file_hashes", []) if h]),
    }


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def classify(indicators, reputation_results):
    """Return (verdict, reasons) for an email.

    reputation_results: list of dicts with keys
        type, value, status ("success"/"failed"), malicious, suspicious

    Rules, in order:
      1. any indicator flagged malicious by >= MALICIOUS_THRESHOLD engines -> malicious
      2. no URLs and no attachments (e.g. a text-only / BEC-style lure)   -> suspicious
         (a clean sender domain alone is not enough to auto-close)
      3. any malicious/suspicious hit below threshold, or a failed lookup -> suspicious
      4. otherwise                                                       -> clean
    """
    malicious, suspicious = [], []
    for result in reputation_results:
        label = "{} {}".format(result["type"], result["value"])
        mal = _as_int(result.get("malicious"))
        sus = _as_int(result.get("suspicious"))
        if result.get("status") != "success" or mal is None:
            suspicious.append("{}: reputation lookup failed or returned no score".format(label))
        elif mal >= MALICIOUS_THRESHOLD:
            malicious.append("{}: flagged malicious by {} engines".format(label, mal))
        elif mal > 0 or (sus or 0) > 0:
            suspicious.append("{}: {} malicious / {} suspicious detections (below threshold {})".format(
                label, mal, sus or 0, MALICIOUS_THRESHOLD))

    if malicious:
        return VERDICT_MALICIOUS, malicious + suspicious
    if not indicators.get("urls") and not indicators.get("file_hashes"):
        return VERDICT_SUSPICIOUS, suspicious + [
            "No URLs or attachments to assess (possible text-only/BEC lure); manual review required."]
    if suspicious:
        return VERDICT_SUSPICIOUS, suspicious
    return VERDICT_CLEAN, ["All {} reputation lookups returned no detections.".format(len(reputation_results))]


def _save(key, value):
    phantom.save_run_data(key=key, value=json.dumps(value), auto=True)


def _load(key, default=None):
    raw = phantom.get_run_data(key=key)
    return json.loads(raw) if raw else default


##############################################################################
# Playbook entry point
##############################################################################

def on_start(container):
    phantom.debug("on_start() called")
    extract_indicators(container=container)
    return


##############################################################################
# Block: extract indicators
##############################################################################

def extract_indicators(action=None, success=None, container=None, results=None, handle=None,
                       filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_indicators() called")

    raw = {}
    for key, datapaths in ARTIFACT_DATAPATHS.items():
        values = []
        for datapath in datapaths:
            rows = phantom.collect2(container=container, datapath=[datapath])
            values.extend(row[0] for row in rows if row and row[0])
        raw[key] = values

    indicators = build_indicators(raw)
    _save("indicators", indicators)
    phantom.debug("indicators: {}".format(indicators))

    launched = [a["name"] for a in REPUTATION_ACTIONS if indicators[a["indicator"]]]
    _save("launched_reputation_actions", launched)

    if not launched:
        decide_verdict(container=container)
        return

    for definition in REPUTATION_ACTIONS:
        if definition["name"] in launched:
            run_reputation(container=container, definition=definition, indicators=indicators)
    return


##############################################################################
# Block: reputation lookups (run in parallel, joined below)
##############################################################################

def run_reputation(container=None, definition=None, indicators=None, **kwargs):
    phantom.debug("{}() called".format(definition["name"]))
    parameters = [{definition["param"]: value} for value in indicators[definition["indicator"]]]
    phantom.act(
        definition["action"],
        parameters=parameters,
        name=definition["name"],
        assets=[ASSETS[definition["asset"]]],
        callback=join_decide_verdict,
    )
    return


def join_decide_verdict(action=None, success=None, container=None, results=None, handle=None,
                        filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_decide_verdict() called")

    # Guard so the decision runs exactly once, after every launched lookup.
    if phantom.get_run_data(key="join_decide_verdict_called"):
        return

    launched = _load("launched_reputation_actions", [])
    if phantom.completed(action_names=launched):
        phantom.save_run_data(key="join_decide_verdict_called", value="decide_verdict", auto=True)
        decide_verdict(container=container)
    return


##############################################################################
# Block: decision
##############################################################################

def _collect_reputation_results(container):
    launched = set(_load("launched_reputation_actions", []))
    results = []
    for definition in REPUTATION_ACTIONS:
        name = definition["name"]
        if name not in launched:
            continue
        rows = phantom.collect2(
            container=container,
            datapath=[
                "{}:action_result.parameter.{}".format(name, definition["param"]),
                "{}:action_result.status".format(name),
                "{}:{}".format(name, MALICIOUS_COUNT_PATH),
                "{}:{}".format(name, SUSPICIOUS_COUNT_PATH),
            ],
        )
        for value, status, mal, sus in rows:
            results.append({"type": definition["param"], "value": value, "status": status,
                            "malicious": mal, "suspicious": sus})
    return results


def decide_verdict(action=None, success=None, container=None, results=None, handle=None,
                   filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decide_verdict() called")

    indicators = _load("indicators", {})
    verdict, reasons = classify(indicators, _collect_reputation_results(container))
    _save("verdict", {"verdict": verdict, "reasons": reasons})

    phantom.add_note(
        container=container,
        note_type="general",
        title="Phishing triage verdict: {}".format(verdict.upper()),
        content="\n".join("- " + r for r in reasons),
        note_format="markdown",
    )

    if verdict == VERDICT_MALICIOUS:
        contain_malicious(container=container)
    elif verdict == VERDICT_SUSPICIOUS:
        assign_to_analyst(container=container)
    else:
        close_clean(container=container)
    return


##############################################################################
# Branch: malicious -> quarantine, block sender, ticket
##############################################################################

def contain_malicious(action=None, success=None, container=None, results=None, handle=None,
                      filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("contain_malicious() called")
    phantom.set_severity(container=container, severity="high")

    indicators = _load("indicators", {})
    reasons = _load("verdict", {}).get("reasons", [])
    planned, skipped = [], []

    if indicators.get("message_id") and indicators.get("recipient"):
        planned.append(("quarantine email", "quarantine_email_1", ASSETS["email"],
                        [{"id": indicators["message_id"], "email": indicators["recipient"]}]))
    else:
        skipped.append("quarantine email (Message-ID or recipient missing; quarantine manually)")

    if indicators.get("sender"):
        planned.append(("block sender", "block_sender_1", ASSETS["email"],
                        [{"email": indicators["sender"]}]))
    else:
        skipped.append("block sender (no sender address extracted)")

    planned.append(("create ticket", "create_ticket_1", ASSETS["ticketing"], [{
        "title": "Malicious phishing email reported (SOAR container {})".format(container["id"]),
        "description": "Sender: {}\nRecipient: {}\n\nVerdict reasons:\n{}".format(
            indicators.get("sender"), indicators.get("recipient"),
            "\n".join("- " + r for r in reasons)),
        "severity": "high",
    }]))

    _save("containment_actions", [name for _, name, _, _ in planned])
    _save("containment_skipped", skipped)

    for action_name, name, asset, parameters in planned:
        phantom.act(action_name, parameters=parameters, name=name, assets=[asset],
                    callback=join_containment_summary)
    return


def join_containment_summary(action=None, success=None, container=None, results=None, handle=None,
                             filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_containment_summary() called")
    if phantom.get_run_data(key="join_containment_summary_called"):
        return

    names = _load("containment_actions", [])
    if not phantom.completed(action_names=names):
        return
    phantom.save_run_data(key="join_containment_summary_called", value="containment_summary", auto=True)

    lines = []
    for name in names:
        statuses = [row[0] for row in phantom.collect2(
            container=container, datapath=["{}:action_result.status".format(name)])]
        lines.append("- {}: {}".format(name, ", ".join(s or "unknown" for s in statuses) or "no result"))
    for item in _load("containment_skipped", []):
        lines.append("- SKIPPED {}".format(item))

    phantom.add_note(container=container, note_type="general", title="Containment actions",
                     content="\n".join(lines), note_format="markdown")
    phantom.set_status(container=container, status="open")
    return


##############################################################################
# Branch: suspicious -> analyst review
##############################################################################

def assign_to_analyst(action=None, success=None, container=None, results=None, handle=None,
                      filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("assign_to_analyst() called")
    phantom.set_severity(container=container, severity="medium")
    phantom.set_owner(container=container, role=ANALYST_ROLE)
    phantom.set_status(container=container, status="open")
    return


##############################################################################
# Branch: clean -> auto-close
##############################################################################

def close_clean(action=None, success=None, container=None, results=None, handle=None,
                filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_clean() called")
    phantom.set_severity(container=container, severity="low")
    phantom.add_note(
        container=container,
        note_type="general",
        title="Auto-closed: no malicious indicators",
        content="Closed by phishing_triage playbook. All reputation lookups were clean. "
                "Reopen if the reporter supplies new context.",
        note_format="markdown",
    )
    phantom.set_status(container=container, status="closed")
    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")
    phantom.debug("verdict: {}".format(phantom.get_run_data(key="verdict")))
    return
