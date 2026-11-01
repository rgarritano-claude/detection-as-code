"""Offline mock of the Splunk SOAR ``phantom.rules`` API, for unit tests only.

It implements the subset of the API used by playbooks in soar/playbooks/:
act, collect2, completed, save_run_data, get_run_data, add_note, set_status,
set_severity, set_owner, debug, error.

Behavior:
  * ``act`` runs **synchronously**: it looks up a responder for the action type,
    stores the action results under the action's ``name``, then invokes the
    callback. A real SOAR instance runs actions asynchronously, which is why
    playbooks use join functions guarded by ``completed``; the mock exercises
    that same join logic.
  * Every side effect is recorded on ``STATE`` so tests can assert on what the
    playbook did.

Call ``reset(container, responders)`` before each test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

Responder = Callable[[dict], dict]


@dataclass
class _State:
    container: dict = field(default_factory=dict)
    responders: dict[str, Responder] = field(default_factory=dict)
    acts: list[dict] = field(default_factory=list)
    action_results: dict[str, list[dict]] = field(default_factory=dict)
    run_data: dict[str, str] = field(default_factory=dict)
    notes: list[dict] = field(default_factory=list)
    status: str | None = None
    severity: str | None = None
    owner: dict | None = None
    log: list[str] = field(default_factory=list)

    def act_names(self) -> list[str]:
        return [a["action"] for a in self.acts]


STATE = _State()


def reset(container: dict, responders: dict[str, Responder] | None = None) -> _State:
    global STATE
    STATE = _State(container=container, responders=dict(responders or {}))
    return STATE


def _default_responder(parameter: dict) -> dict:
    return {"status": "success", "summary": {}, "data": [], "message": "mock success"}


def _resolve(obj: Any, path: list[str]) -> Any:
    for part in path:
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


# --- actions -------------------------------------------------------------------


def act(action, parameters=None, assets=None, callback=None, name=None, tags=None,
        reviewer=None, handle=None, **kwargs):
    name = name or action.replace(" ", "_") + "_1"
    responder = STATE.responders.get(action, _default_responder)
    results = []
    for parameter in parameters or [{}]:
        result = {"status": "success", "summary": {}, "data": [], "message": ""}
        result.update(responder(parameter))
        result["parameter"] = dict(parameter)
        results.append(result)

    STATE.acts.append({"action": action, "name": name, "parameters": parameters or [],
                       "assets": assets or []})
    STATE.action_results[name] = results

    if callback:
        callback(
            action={"name": name, "action": action},
            success=all(r["status"] == "success" for r in results),
            container=STATE.container,
            results=[{"action_results": results}],
            handle=handle,
        )
    return True


def completed(action_names=None, playbook_names=None, custom_function_names=None, trace=False):
    return all(n in STATE.action_results for n in (action_names or []))


# --- data access ----------------------------------------------------------------


def collect2(container=None, datapath=None, action_results=None, scope="new", filter_artifacts=None,
             trace=False, **kwargs):
    """Resolve datapaths against container artifacts or recorded action results.

    Supported forms (all datapaths in one call must share a source):
      artifact:*.<path>                  e.g. artifact:*.cef.requestURL
      <action name>:action_result.<path> e.g. url_reputation_1:action_result.summary.malicious
    """
    datapath = datapath or []
    if not datapath:
        return []
    sources = {dp.split(":", 1)[0] for dp in datapath}
    if len(sources) != 1:
        raise ValueError(f"mock collect2 needs one source per call, got {sources}")
    source = sources.pop()

    if source == "artifact":
        paths = [dp.split(":", 1)[1].removeprefix("*.").split(".") for dp in datapath]
        records = STATE.container.get("artifacts", [])
    else:
        paths = [dp.split(":", 1)[1].removeprefix("action_result.").split(".") for dp in datapath]
        records = STATE.action_results.get(source, [])
    return [[_resolve(rec, p) for p in paths] for rec in records]


def save_run_data(value=None, key=None, auto=True):
    STATE.run_data[key] = value


def get_run_data(key=None, **kwargs):
    return STATE.run_data.get(key)


# --- container mutations -------------------------------------------------------------


def add_note(container=None, note_type="general", title="", content="", note_format="markdown", **kwargs):
    STATE.notes.append({"title": title, "content": content, "note_type": note_type})
    return True, "mock note added", len(STATE.notes)


def set_status(container=None, status=None, trace=False):
    STATE.status = status
    return True, "mock status set"


def set_severity(container=None, severity=None, trace=False):
    STATE.severity = severity
    return True, "mock severity set"


def set_owner(container=None, user=None, role=None, trace=False):
    STATE.owner = {"user": user, "role": role}
    return True, "mock owner set"


# --- logging --------------------------------------------------------------------


def debug(message, *args, **kwargs):
    STATE.log.append(str(message))


def error(message, *args, **kwargs):
    STATE.log.append("ERROR: " + str(message))
