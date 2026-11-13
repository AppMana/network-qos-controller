"""network-qos node agent: DaemonSet on Linux nodes, hostNetwork, NET_ADMIN.

Its only input is ConfigMap network-qos/network-qos-node-config, which
network-qos-controller renders from the NetworkQosPolicy. From it and two
local facts (the LAN interface toward the gateway, and that interface's
negotiated speed) it applies, by the mode the config gives this node:

  Observe  nothing (removes its own table and qdisc if present)
  Mark     the nftables table inet appmana_qos (DSCP marking)
  Enforce  the table, and the HTB class tree on the LAN interface

It keeps no state outside the kernel objects it owns, so a freshly booted
node or a new kernel converges on the first pass. The nftables table is
replaced in one transaction and never touches other tables (Calico's and
kube-proxy's live in their own). A tc failure is fail-open: the agent deletes
its root qdisc and the kernel's default qdisc returns.
"""

import json
import logging
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from kubernetes import client, config

from . import render

NODE = os.environ.get("NODE_NAME", "")
NAMESPACE = os.environ.get("NAMESPACE", "network-qos")
CONFIG = os.environ.get("NODE_CONFIG", "network-qos-node-config")
INTERVAL = int(os.environ.get("INTERVAL_SECONDS", "15"))
TABLE = "inet appmana_qos"
# Hash of the queue tree last applied, on tmpfs: it lives exactly as long as
# the qdisc it describes, so an agent restart does not swap a live qdisc and
# a reboot starts clean.
TC_HASH = Path(os.environ.get("RUN_DIR", "/run/appmana-qos")) / "tc.hash"
log = logging.getLogger("network-qos-agent")
state: dict = {"node": NODE, "mode": None, "appliedHash": None, "error": None}
applied: dict = {}


def run(*argv, stdin: str | None = None) -> str:
    result = subprocess.run(argv, input=stdin, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:3])}: {result.stderr.strip()[:300]}")
    return result.stdout


def lan_interface(gateway: str) -> str:
    return json.loads(run("ip", "-j", "route", "get", gateway))[0]["dev"]


def link_mbit(interface: str) -> int:
    node = client.CoreV1Api().read_node(NODE)
    override = (node.metadata.annotations or {}).get("network.appmana.com/lan-mbit")
    if override:
        return int(override)
    try:
        return int(Path(f"/sys/class/net/{interface}/speed").read_text().strip())
    except (OSError, ValueError):
        return -1


def our_root(interface: str) -> bool:
    qdiscs = json.loads(run("tc", "-j", "qdisc", "show", "dev", interface))
    return any(q.get("root") and q.get("kind") == "htb" and q.get("handle") == "1:" for q in qdiscs)


def apply_nft(text: str):
    # Declare-then-delete makes the replacement one transaction whether or
    # not the table exists; no other table is touched.
    run("nft", "-f", "-", stdin=f"table {TABLE} {{}}\ndelete table {TABLE}\n" + text)


def remove_nft():
    run("nft", "-f", "-", stdin=f"table {TABLE} {{}}\ndelete table {TABLE}\n")


def apply_tc(interface: str, lines: list[str]):
    if our_root(interface):
        # Filters are added, not replaced; start the tree from a clean root.
        run("tc", "qdisc", "del", "dev", interface, "root")
    try:
        run("tc", "-batch", "-", stdin="\n".join(lines) + "\n")
    except RuntimeError:
        if our_root(interface):
            run("tc", "qdisc", "del", "dev", interface, "root")
        raise


def remove_tc(interface: str):
    if our_root(interface):
        run("tc", "qdisc", "del", "dev", interface, "root")


def counters(classes: list[render.TrafficClass], interface: str) -> dict:
    out: dict = {}
    try:
        table = json.loads(run("nft", "-j", "list", "table", *TABLE.split()))
        for item in table.get("nftables", []):
            rule = item.get("rule")
            if not rule or not rule.get("comment"):
                continue
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    acc = out.setdefault(rule["comment"], {})
                    acc["markedPackets"] = acc.get("markedPackets", 0) + expr["counter"]["packets"]
                    acc["markedBytes"] = acc.get("markedBytes", 0) + expr["counter"]["bytes"]
    except RuntimeError:
        pass
    if our_root(interface):
        for cls in json.loads(run("tc", "-s", "-j", "class", "show", "dev", interface)):
            name = render.class_of_minor(classes, cls.get("handle", ""))
            if not name:
                continue
            stats = cls.get("stats", {})
            acc = out.setdefault(name, {})
            acc.update({"bytes": stats.get("bytes", 0), "packets": stats.get("packets", 0),
                        "drops": stats.get("drops", 0), "overlimits": stats.get("overlimits", 0)})
    return out


def metrics_text() -> str:
    labels = f'node="{NODE}"'
    lines = [f'appmana_qos_agent_info{{{labels},mode="{state.get("mode")}",hash="{state.get("appliedHash")}"}} 1',
             f"appmana_qos_agent_error{{{labels}}} {1 if state.get('error') else 0}"]
    for cls, values in (state.get("classes") or {}).items():
        cl = f'{labels},class="{cls}"'
        for key, metric in (("bytes", "class_bytes_total"), ("packets", "class_packets_total"),
                            ("drops", "class_drops_total"), ("overlimits", "class_overlimits_total"),
                            ("markedPackets", "marked_packets_total"), ("markedBytes", "marked_bytes_total")):
            if key in values:
                lines.append(f"appmana_qos_{metric}{{{cl}}} {values[key]}")
    return "\n".join(lines) + "\n"


def reconcile_once():
    cm = client.CoreV1Api().read_namespaced_config_map(CONFIG, NAMESPACE)
    cfg = json.loads(cm.data["config.json"])
    classes = [render.TrafficClass.from_json(c) for c in cfg["classes"]]
    mode = render.node_mode(cfg, NODE)
    interface = lan_interface(cfg["lanGateway"])
    nft = render.render_node_nft(classes, interface, cfg["members"], cfg["podInterfacePrefix"])
    speed = link_mbit(interface)
    error = None
    tc = []
    if mode == "Enforce":
        profile = render.NodeProfile(mode, cfg["rootPercent"], cfg["minDefaultPercent"])
        try:
            tc = render.render_node_tc(profile, classes, interface, speed)
        except render.RenderError as exc:
            error = str(exc)
    # Membership churn changes only the nftables sets; the qdisc tree is
    # rebuilt only when its own lines change, since a swap drops queued packets.
    nft_key = None if mode == "Observe" else (interface, nft)
    tc_key = (interface, tuple(tc))
    if nft_key != applied.get("nft"):
        if nft_key is None:
            remove_nft()
        else:
            apply_nft(nft)
        applied["nft"] = nft_key
    tc_hash = render.digest([interface] + tc)
    if "tc" not in applied and tc and our_root(interface) and TC_HASH.exists() and TC_HASH.read_text() == tc_hash:
        applied["tc"] = tc_key  # this tree is already live (agent restart)
    if tc_key != applied.get("tc") or (tc and not our_root(interface)):
        if tc:
            apply_tc(interface, tc)
            TC_HASH.parent.mkdir(parents=True, exist_ok=True)
            TC_HASH.write_text(tc_hash)
            log.info("queue tree applied on %s at %s Mbit/s", interface, speed)
        else:
            remove_tc(interface)
            TC_HASH.unlink(missing_ok=True)
        applied["tc"] = tc_key
    if state.get("appliedHash") != cfg["hash"] or state.get("mode") != mode:
        log.info("config %s applied: mode=%s interface=%s speed=%s", cfg["hash"], mode, interface, speed)
    state.update({"mode": mode, "appliedHash": cfg["hash"], "interface": interface, "linkMbit": speed,
                  "error": error, "classes": counters(classes, interface)})


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            body, kind = metrics_text().encode(), "text/plain; version=0.0.4"
        elif self.path == "/status":
            body, kind = json.dumps(state).encode(), "application/json"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not NODE:
        raise SystemExit("NODE_NAME is required (the downward API spec.nodeName)")
    config.load_incluster_config()
    server = HTTPServer(("0.0.0.0", int(os.environ.get("AGENT_PORT", "9817"))), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    while True:
        try:
            reconcile_once()
        except (render.RenderError, client.ApiException, RuntimeError, OSError, KeyError, ValueError) as error:
            # Keep what is applied: a render or API error must not strip a
            # working policy, and a tc failure already fell back to default.
            state["error"] = str(error)[:500]
            log.error("reconcile failed: %s", error)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
