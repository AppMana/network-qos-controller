"""The router target: reads, diffs and applies the controller-owned VyOS
subtrees through the VyOS HTTPS API. No Kubernetes dependency, so the router
lab runs this exact code inside a lab router.

Apply is one commit-confirm commit. It is confirmed (and saved) only if,
after SETTLE seconds, the API still answers (LAN path), the number of
established BGP sessions did not fall, and every WAN WLB had active is still
active (its health checks are pings over that WAN). Otherwise nothing more
is sent and VyOS reverts by itself (`commit-confirm action reload`).
"""

import json
import re
import time

import requests

from . import render


class VyOS:
    def __init__(self, endpoint: str, key: str, timeout: int = 60):
        self.endpoint, self.key, self.timeout = endpoint.rstrip("/"), key, timeout

    def call(self, path: str, data) -> dict:
        resp = requests.post(f"{self.endpoint}/{path}", data={"data": json.dumps(data), "key": self.key},
                             verify=False, timeout=self.timeout)
        body = resp.json()
        if not body.get("success"):
            raise RuntimeError(f"VyOS {path}: {body.get('error')}")
        return body

    def show_config(self, path) -> dict:
        """The subtree under path, as its children.

        Two shapes of the API are normalised (both measured in the router
        lab): a path with nothing under it is reported as an error
        ("Configuration under specified path is empty"), and a tag node or
        leaf path comes back wrapped in its own name
        ({"network-group": {...}}, {"redirect": "ifb0"}), while a plain node
        path (["qos"]) comes back as its children."""
        try:
            data = self.call("retrieve", {"op": "showConfig", "path": list(path)}).get("data") or {}
        except RuntimeError as error:
            if "specified path is empty" in str(error):
                return {}
            raise
        if isinstance(data, dict) and len(data) == 1 and path and path[-1] in data:
            return data[path[-1]]
        return data

    def show(self, words) -> str:
        return self.call("show", {"op": "show", "path": list(words)}).get("data") or ""


def established_bgp_sessions(summary: str) -> int:
    count = 0
    for line in summary.splitlines():
        fields = line.split()
        if len(fields) >= 10 and fields[1] in ("4", "6") and re.match(r"^\*?[0-9a-fA-F.:]+$", fields[0]):
            if fields[9].isdigit():
                count += 1
    return count


def active_wans(text: str) -> set[str]:
    active, current = set(), None
    for line in text.splitlines():
        if line.startswith("Interface:"):
            current = line.split(":", 1)[1].strip()
        elif line.startswith("Status:") and current and line.split(":", 1)[1].strip() == "active":
            active.add(current)
    return active


def health(router: VyOS) -> dict:
    return {"bgp": established_bgp_sessions(router.show(["bgp", "summary"])),
            "wans": sorted(active_wans(router.show(["wan-load-balance"])))}


def healthy_after(before: dict, after: dict) -> bool:
    return after["bgp"] >= before["bgp"] and set(before["wans"]) <= set(after["wans"])


def live_owned(router: VyOS, router_spec: render.RouterSpec) -> dict:
    live = {root: router.show_config(root) for root in render.router_owned_roots(router_spec)}
    for kind in ("network-group", "ipv6-network-group", "address-group", "ipv6-address-group"):
        live[("firewall", "group", kind)] = router.show_config(("firewall", "group", kind))
    for route in ("route", "route6"):
        live[("policy", route)] = router.show_config(("policy", route))
    return render.owned_from_live(router_spec, live)


def apply(router: VyOS, ops: list[dict], digest: str, minutes: int, settle: int, log=print) -> dict:
    try:
        before = health(router)
        router.call("configure", {"commands": ops, "confirm_time": minutes})
    except (requests.RequestException, RuntimeError) as error:
        # A rejected commit changes nothing: VyOS validates the whole tree.
        log(f"router commit failed: {error}")
        return {"phase": "Failed", "lastError": str(error)[:500], "revertedHash": digest}
    time.sleep(settle)
    try:
        after = health(router)
    except (requests.RequestException, RuntimeError) as error:
        log(f"router unreachable after commit; VyOS reverts in {minutes} min: {error}")
        return {"phase": "Reverted", "revertedHash": digest, "lastError": f"unreachable after commit: {error}"[:500]}
    if not healthy_after(before, after):
        log(f"router health regressed {before} -> {after}; left unconfirmed, VyOS reverts in {minutes} min")
        return {"phase": "Reverted", "revertedHash": digest, "lastError": f"health before {before} after {after}"}
    router.call("config-file", {"op": "confirm"})
    router.call("config-file", {"op": "save"})
    log(f"router applied {digest}: {len(ops)} ops, health {before} -> {after}")
    return {"phase": "Applied", "appliedHash": digest, "lastError": "", "revertedHash": "",
            "lastApplied": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "health": after}


def counters(router: VyOS, router_spec: render.RouterSpec) -> dict:
    out = {}
    targets = [(router_spec.lan_interface, "download")] + [(w.interface, "upload") for w in router_spec.wans]
    for iface, direction in targets:
        try:
            tins = render.parse_cake_tins(router.show(["qos", "cake", "interface", iface]))
        except (requests.RequestException, RuntimeError):
            continue
        if tins:
            out[f"{iface}-{direction}"] = tins
    return out
