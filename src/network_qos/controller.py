"""network-qos-controller: reconciles the NetworkQosPolicy (policy.yaml) onto
its three targets.

  router    VyOS QoS (CAKE per WAN), DSCP reset/marking rules, through the
            VyOS HTTPS API. Every change is one commit-confirm commit that is
            confirmed only after the router still answers the API, keeps at
            least as many established BGP sessions and every WLB-active WAN;
            otherwise VyOS reverts it (commit-confirm action reload) and that
            exact configuration is not retried until it changes.
  nodes     renders ConfigMap network-qos/network-qos-node-config, the node
            agents' only input (classes, member addresses, per-node mode), and
            collects every agent's applied state and counters.
  switches  QNAP QSS QoS (DSCP mode, DSCP -> queue) over the QSS REST API, when
            enabled and credentialed; otherwise reports why not and whether
            each switch answers.

Status of each target, with observed generation, applied hash and last
error, is written to the policy's status. Prometheus metrics for router tins
are served on :9818.
"""

import asyncio
import base64
import ipaddress
import json
import logging
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import kopf
import requests
import urllib3
from kubernetes import client, config

from . import render
from . import vyos as vyos_target
from .vyos import VyOS

GROUP, VERSION, PLURAL = "network.appmana.com", "v1alpha1", "networkqospolicies"
NAMESPACE = os.environ.get("NAMESPACE", "network-qos")
NODE_CONFIG = "network-qos-node-config"
AGENT_PORT = int(os.environ.get("AGENT_PORT", "9817"))
SETTLE_SECONDS = int(os.environ.get("SETTLE_SECONDS", "20"))
COUNTER_STATUS_SECONDS = 300
log = logging.getLogger("network-qos")
metrics = {"router": ""}
last_counter_write = {"router": 0.0, "nodes": 0.0}
# The router's and switches' API certificates are self-signed; the existing
# VyOS controllers talk to the router the same way.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Metrics(BaseHTTPRequestHandler):
    def do_GET(self):
        body = "".join(metrics.values()).encode() if self.path == "/metrics" else b""
        self.send_response(200 if self.path == "/metrics" else 404)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@kopf.on.startup()
async def configure(settings: kopf.OperatorSettings, **_):
    settings.posting.level = logging.WARNING
    settings.persistence.finalizer = "network-qos.appmana.com/controller-finalizer"
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    server = HTTPServer(("0.0.0.0", int(os.environ.get("METRICS_PORT", "9818"))), Metrics)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def fresh(name: str) -> tuple[dict, dict, int]:
    """The policy's spec, status and generation as the API server has them
    now. kopf's cached body can go stale (it stopped updating after an API
    server restart on a running cluster), and every decision here (what to
    render, what was applied, what was reverted) must use the stored object."""
    obj = client.CustomObjectsApi().get_cluster_custom_object(GROUP, VERSION, PLURAL, name)
    return obj.get("spec") or {}, obj.get("status") or {}, obj["metadata"]["generation"]


def secret_value(ref: dict) -> str | None:
    try:
        secret = client.CoreV1Api().read_namespaced_secret(ref["name"], ref["namespace"])
    except client.ApiException as error:
        if error.status == 404:
            return None
        raise
    raw = (secret.data or {}).get(ref["key"])
    return base64.b64decode(raw).decode() if raw else None


# ------------------------------------------------------------- cluster ----


def nodes():
    return client.CoreV1Api().list_node().items


def node_addresses(items) -> list[str]:
    return [a.address for n in items for a in (n.status.addresses or []) if a.type == "InternalIP"]


def pod_ipv6_pools() -> list[str]:
    pools = client.CustomObjectsApi().list_cluster_custom_object("crd.projectcalico.org", "v1", "ippools")["items"]
    return [p["spec"]["cidr"] for p in pools
            if ipaddress.ip_network(p["spec"]["cidr"]).version == 6 and not p["spec"].get("disabled")]


def service_addresses(namespace: str, name: str) -> list[str]:
    svc = client.CoreV1Api().read_namespaced_service(name, namespace)
    # kubernetes client 36 names it cluster_ips (older clients: cluster_i_ps).
    ips = getattr(svc.spec, "cluster_ips", None) or getattr(svc.spec, "cluster_i_ps", None) or []
    return [ip for ip in ips if ip and ip != "None"]


def resolve_members(class_spec: dict, node_ips: set[str]) -> list[str]:
    core = client.CoreV1Api()
    match = class_spec.get("match", {})
    pods = []
    for term in match.get("pods", []):
        selector = render.label_selector(term.get("podSelector"))
        if term.get("namespaceSelector") is not None:
            ns_selector = render.label_selector(term["namespaceSelector"])
            names = [n.metadata.name for n in core.list_namespace(label_selector=ns_selector).items]
            items = [p for ns in names for p in core.list_namespaced_pod(ns, label_selector=selector).items]
        else:
            items = core.list_pod_for_all_namespaces(label_selector=selector).items
        pods += [{"ips": [i.ip for i in (getattr(p.status, "pod_ips", None) or getattr(p.status, "pod_i_ps", None) or [])],
                  "phase": p.status.phase,
                  "hostNetwork": bool(p.spec.host_network)} for p in items]
    endpoints = []
    discovery = client.DiscoveryV1Api()
    for ref in match.get("services", []):
        endpoints += service_addresses(ref["namespace"], ref["name"])
        slices = discovery.list_namespaced_endpoint_slice(ref["namespace"], label_selector=f"kubernetes.io/service-name={ref['name']}")
        endpoints += [a for s in slices.items for e in (s.endpoints or []) for a in (e.addresses or [])]
    return render.class_members(pods, endpoints, match.get("cidrs", []), node_ips)


def render_node_config(spec: dict) -> dict:
    items = nodes()
    node_ips = set(node_addresses(items))
    members = {c["name"]: resolve_members(c, node_ips) for c in spec.get("classes", [])}
    selector = spec.get("nodes", {}).get("enforceNodeSelector")
    enforce = [n.metadata.name for n in items
               if (n.metadata.labels or {}).get("kubernetes.io/os") == "linux"
               and render.selector_matches(selector, n.metadata.labels or {})]
    return render.node_config(spec, members, enforce)


def write_node_config(body: dict) -> bool:
    core = client.CoreV1Api()
    data = {"config.json": json.dumps(body, sort_keys=True, indent=1)}
    try:
        current = core.read_namespaced_config_map(NODE_CONFIG, NAMESPACE)
        if (current.data or {}).get("config.json") == data["config.json"]:
            return False
        core.patch_namespaced_config_map(NODE_CONFIG, NAMESPACE, {"data": data})
    except client.ApiException as error:
        if error.status != 404:
            raise
        core.create_namespaced_config_map(NAMESPACE, {"metadata": {"name": NODE_CONFIG}, "data": data})
    return True


@kopf.timer(GROUP, VERSION, PLURAL, id="nodes", interval=15, initial_delay=5)
async def reconcile_nodes(name, patch, logger, **_):
    spec, status, generation = await asyncio.to_thread(fresh, name)
    target = dict(status.get("nodes") or {})
    try:
        body = await asyncio.to_thread(render_node_config, spec)
        if await asyncio.to_thread(write_node_config, body):
            logger.info(f"node config {body['hash']} mode={body['mode']} enforce={len(body['enforceNodes'])}")
        update = {"observedGeneration": generation, "renderedHash": body["hash"], "mode": body["mode"],
                  "enforceNodes": body["enforceNodes"], "memberCounts": {k: len(v) for k, v in body["members"].items()},
                  "lastError": ""}
    except (render.RenderError, client.ApiException) as error:
        update = {"observedGeneration": generation, "lastError": str(error)[:500]}
        logger.warning(f"node config not rendered: {error}")
    # Keys this target no longer writes (the agent rollup moved to
    # status.agents) are removed: None deletes in a merge patch.
    for stale in ("agents", "classTotals", "summary"):
        if stale in target:
            update[stale] = None
    if any(target.get(k) != v for k, v in update.items()):
        patch.status["nodes"] = update


def rendered_hash() -> str | None:
    try:
        cm = client.CoreV1Api().read_namespaced_config_map(NODE_CONFIG, NAMESPACE)
    except client.ApiException:
        return None
    return json.loads((cm.data or {}).get("config.json", "{}")).get("hash")


def agent_states() -> list[dict]:
    pods = client.CoreV1Api().list_namespaced_pod(NAMESPACE, label_selector="app=network-qos-agent").items
    states = []
    for pod in pods:
        if pod.status.phase != "Running" or not pod.status.host_ip:
            continue
        try:
            state = requests.get(f"http://{pod.status.host_ip}:{AGENT_PORT}/status", timeout=5).json()
        except (requests.RequestException, ValueError) as error:
            state = {"error": f"status unreadable: {error}"}
        state["node"] = pod.spec.node_name
        states.append(state)
    return sorted(states, key=lambda s: s["node"])


@kopf.timer(GROUP, VERSION, PLURAL, id="agents", interval=60, initial_delay=30)
async def collect_agents(name, patch, **_):
    states = await asyncio.to_thread(agent_states)
    _, status, _ = await asyncio.to_thread(fresh, name)
    # What the agents must have applied is what the ConfigMap holds now.
    rendered = await asyncio.to_thread(rendered_hash)
    current = status.get("agents") or {}
    applied = sum(1 for s in states if s.get("appliedHash") == rendered and not s.get("error"))
    modes = {}
    for s in states:
        modes[s.get("mode", "?")] = modes.get(s.get("mode", "?"), 0) + 1
    summary = f"{applied}/{len(states)} applied " + ",".join(f"{k}={v}" for k, v in sorted(modes.items()))
    # No nulls: a JSON merge patch would read them as deletions.
    agents = [{k: s[k] for k in ("node", "mode", "appliedHash", "interface", "linkMbit", "error") if s.get(k) is not None}
              for s in states]
    changed = current.get("summary") != summary or current.get("nodes") != agents
    now = time.monotonic()
    if changed or now - last_counter_write["nodes"] > COUNTER_STATUS_SECONDS:
        totals = {}
        for s in states:
            for cls, counters in (s.get("classes") or {}).items():
                acc = totals.setdefault(cls, {"bytes": 0, "packets": 0, "drops": 0, "markedPackets": 0})
                for key in acc:
                    acc[key] += int(counters.get(key, 0))
        patch.status["agents"] = {"summary": summary, "nodes": agents, "classTotals": totals}
        last_counter_write["nodes"] = now


# -------------------------------------------------------------- router ----


def router_inputs(spec: dict):
    router_spec = render.RouterSpec.from_spec(spec["router"])
    classes = render.classes_of(spec)
    sources = {}
    for c in spec.get("classes", []):
        if c.get("router", {}).get("markSources"):
            sources[c["name"]] = [a for ref in c.get("match", {}).get("services", [])
                                  for a in service_addresses(ref["namespace"], ref["name"])]
    trusted = node_addresses(nodes())
    if not trusted:
        raise render.RenderError("no node addresses: refusing to wash every node's DSCP")
    if spec["router"].get("trustedSources", {}).get("podIPv6Pools"):
        trusted += pod_ipv6_pools()
    return router_spec, render.render_router(router_spec, classes, trusted, sources)


def router_metrics(counters: dict) -> str:
    lines = []
    for target, tins in counters.items():
        interface, direction = target.split("-", 1)
        for tin, values in tins.items():
            labels = f'interface="{interface}",direction="{direction}",tin="{tin}"'
            for key, metric in (("pkts", "packets"), ("bytes", "bytes"), ("drops", "drops"), ("marks", "ecn_marks")):
                if key in values:
                    lines.append(f"appmana_qos_router_tin_{metric}_total{{{labels}}} {values[key]}")
    return "\n".join(lines) + ("\n" if lines else "")


@kopf.timer(GROUP, VERSION, PLURAL, id="router", interval=60, initial_delay=15)
async def reconcile_router(name, patch, logger, **_):
    spec, status, generation = await asyncio.to_thread(fresh, name)
    target = dict(status.get("router") or {})
    out = {"observedGeneration": generation, "mode": spec["router"].get("mode", "Observe")}
    try:
        router_spec, desired = await asyncio.to_thread(router_inputs, spec)
    except (render.RenderError, client.ApiException) as error:
        out.update({"phase": "Invalid", "lastError": str(error)[:500]})
        patch.status["router"] = out
        logger.warning(f"router config not rendered: {error}")
        return
    digest = render.config_hash(desired)
    out["desiredHash"] = digest
    try:
        key = await asyncio.to_thread(secret_value, spec["router"]["credentialsSecretRef"])
        router = VyOS(spec["router"]["endpoint"], key or "")
        owned = await asyncio.to_thread(vyos_target.live_owned, router, router_spec)
    except (requests.RequestException, RuntimeError, client.ApiException) as error:
        # Nothing was written; the router keeps what it has.
        out.update({"phase": "Unreachable", "lastError": str(error)[:500]})
        patch.status["router"] = {**target, **out}
        return
    ops = render.router_ops(desired, owned)
    out["pendingOps"] = len(ops)
    if not ops:
        out.update({"phase": "InSync", "appliedHash": digest, "lastError": ""})
    elif out["mode"] != "Enforce":
        out.update({"phase": "Drift", "lastError": "",
                    "pending": [f"{op['op']} {' '.join(op['path'])}" for op in ops[:40]]})
    elif target.get("revertedHash") == digest:
        out.update({"phase": "Reverted"})
    else:
        minutes = int(spec["router"].get("commitConfirmMinutes", 1))
        out.update(await asyncio.to_thread(vyos_target.apply, router, ops, digest, minutes, SETTLE_SECONDS, logger.warning))
    if out.get("phase") != "Drift":
        out["pending"] = []
    counters = await asyncio.to_thread(vyos_target.counters, router, router_spec)
    metrics["router"] = router_metrics(counters)
    now = time.monotonic()
    phase_changed = any(target.get(k) != v for k, v in out.items())
    if phase_changed or now - last_counter_write["router"] > COUNTER_STATUS_SECONDS:
        out["tins"] = counters
        last_counter_write["router"] = now
        patch.status["router"] = {**target, **out}


# ------------------------------------------------------------ switches ----


class QSS:
    """QNAP QSS REST API v3 (the switches' web UI backend): Bearer token from
    POST /users/login with a base64 password; QoS under /qos/mode and
    /qos/dscp (PUT {idx, data})."""

    def __init__(self, address: str, timeout: int = 10):
        self.base, self.timeout, self.token = f"https://{address}/api/v3", timeout, None

    def request(self, method: str, path: str, body=None) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        resp = requests.request(method, self.base + path, json=body, headers=headers, verify=False, timeout=self.timeout)
        return resp.json()

    def login(self, password: str) -> None:
        body = self.request("POST", "/users/login",
                            {"username": "admin", "password": base64.b64encode(password.encode()).decode(), "rememberme": False})
        if body.get("error_code") != 200:
            raise PermissionError(body.get("error_message") or "login refused")
        self.token = body["result"]["AccessToken"] if isinstance(body.get("result"), dict) else body.get("result")


def switch_state(spec: dict) -> dict:
    switches = spec.get("switches") or {}
    desired = render.render_switch(render.classes_of(spec), int(switches.get("defaultQueue", 0)))
    devices = []
    password = None
    if switches.get("enabled"):
        password = secret_value(switches["credentialsSecretRef"])
    for device in switches.get("devices", []):
        qss = QSS(device["address"])
        state = {"name": device["name"], "address": device["address"]}
        try:
            probe = qss.request("GET", "/qos/mode")
            state["reachable"] = True
            state["authorised"] = probe.get("error_code") == 200
            if switches.get("enabled") and password:
                qss.login(password)
                mode = qss.request("GET", "/qos/mode").get("result")
                dscp = qss.request("GET", "/qos/dscp").get("result")
                state.update({"authorised": True, "liveMode": mode, "liveDscp": dscp})
                if switches.get("mode") == "Enforce":
                    # The QSS UI writes these exact shapes (index.bundle.js,
                    # firmware on these units); verified once credentials exist.
                    if (mode or {}).get("mode") != desired["mode"]:
                        qss.request("PUT", "/qos/mode", {"mode": desired["mode"]})
                    for value, queue in desired["dscpQueues"].items():
                        qss.request("PUT", "/qos/dscp", {"idx": value, "data": queue})
                    state["applied"] = True
        except PermissionError as error:
            state.update({"authorised": False, "error": str(error)})
        except (requests.RequestException, ValueError) as error:
            state.update({"reachable": False, "error": str(error)[:200]})
        devices.append(state)
    if not switches.get("enabled"):
        phase, reason = "Disabled", switches.get("disabledReason", "")
    elif not password:
        phase, reason = "Unauthorised", f"Secret {switches['credentialsSecretRef']['namespace']}/{switches['credentialsSecretRef']['name']} missing"
    else:
        phase = "Applied" if all(d.get("applied") for d in devices) else ("Observed" if all(d.get("authorised") for d in devices) else "Degraded")
        reason = ""
    return {"phase": phase, "reason": reason, "desired": desired, "devices": devices}


@kopf.timer(GROUP, VERSION, PLURAL, id="switches", interval=300, initial_delay=20)
async def reconcile_switches(name, patch, **_):
    spec, status, generation = await asyncio.to_thread(fresh, name)
    state = await asyncio.to_thread(switch_state, spec)
    state["observedGeneration"] = generation
    if (status.get("switches") or {}) != state:
        patch.status["switches"] = state
