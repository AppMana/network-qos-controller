"""Pure rendering for network-qos. No Kubernetes, router, switch or kernel
access happens here: controller.py and node_agent.py collect inputs, call
these functions and apply the results.

Everything is derived from one NetworkQosPolicy spec (policy.yaml).

DSCP is the only classification carrier between hosts, the router and the
switches. VyOS WAN load balancing owns the packet mark and the conntrack mark
(it compares `ct mark` against whole values and copies it into `meta mark`
for every LAN packet), so nothing here sets either mark on the router.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field

DSCP_NAMES = {
    "CS0": 0, "CS1": 8, "AF11": 10, "AF12": 12, "AF13": 14, "CS2": 16, "AF21": 18,
    "AF22": 20, "AF23": 22, "CS3": 24, "AF31": 26, "AF32": 28, "AF33": 30, "CS4": 32,
    "AF41": 34, "AF42": 36, "AF43": 38, "CS5": 40, "VA": 44, "EF": 46, "CS6": 48, "CS7": 56,
}

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
RATE_RE = re.compile(r"^(\d+)(kbit|mbit|gbit)$")
ROUTER_PREFIX = "QOS-"
LAN_POLICY = "QOS-LAN-IN"
LAN_POLICY6 = "QOS-LAN6-IN"
TRUSTED_V4 = "QOS-TRUSTED-V4"
TRUSTED_V6 = "QOS-TRUSTED-V6"
# Leaves that take no value; a set-path ending in one of these has no value.
VALUELESS = {"flow-isolation-nat"}
DEFAULT_MINOR = 0x99


class RenderError(ValueError):
    """The declared policy cannot be rendered; nothing is applied."""


def dscp_value(value) -> int:
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.upper() in DSCP_NAMES:
        number = DSCP_NAMES[value.upper()]
    elif isinstance(value, str) and value.isdigit():
        number = int(value)
    else:
        raise RenderError(f"invalid DSCP {value!r}")
    if not 0 <= number <= 63:
        raise RenderError(f"DSCP {number} outside 0-63")
    return number


def rate_kbit(rate: str) -> int:
    match = RATE_RE.match(rate)
    if not match:
        raise RenderError(f"invalid rate {rate!r}; use <n>kbit, <n>mbit or <n>gbit")
    number, unit = int(match.group(1)), match.group(2)
    return number * {"kbit": 1, "mbit": 1000, "gbit": 1000000}[unit]


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class TrafficClass:
    name: str
    dscp: int
    rank: int
    guarantee_percent: int
    queue: str
    router_mark_sources: bool
    switch_queue: int | None = None
    ports: tuple = ()  # ((protocol, port), ...): IANA-registered protocol ports only

    @staticmethod
    def from_spec(spec: dict) -> "TrafficClass":
        name = spec["name"]
        if not NAME_RE.match(name):
            raise RenderError(f"class name {name!r} must match {NAME_RE.pattern}")
        node = spec.get("node", {})
        queue = node.get("queue", "fq_codel")
        if queue not in ("fq_codel", "pfifo"):
            raise RenderError(f"{name}: queue {queue!r} is not fq_codel or pfifo")
        guarantee = int(node.get("guaranteePercent", 0))
        if not 0 <= guarantee <= 90:
            raise RenderError(f"{name}: guaranteePercent {guarantee} outside 0-90")
        switch_queue = spec.get("switch", {}).get("queue")
        if switch_queue is not None and not 0 <= int(switch_queue) <= 7:
            raise RenderError(f"{name}: switch queue {switch_queue} outside 0-7")
        ports = []
        for item in spec.get("match", {}).get("ports", []):
            protocol, port = item["protocol"].lower(), int(item["port"])
            if protocol not in ("udp", "tcp") or not 0 < port < 65536:
                raise RenderError(f"{name}: invalid port match {item!r}")
            ports.append((protocol, port))
        return TrafficClass(
            name=name, dscp=dscp_value(spec["dscp"]), rank=int(spec["rank"]),
            guarantee_percent=guarantee, queue=queue,
            router_mark_sources=bool(spec.get("router", {}).get("markSources", False)),
            switch_queue=None if switch_queue is None else int(switch_queue),
            ports=tuple(sorted(ports)),
        )

    def to_json(self) -> dict:
        data = asdict(self)
        data["ports"] = [list(p) for p in self.ports]
        return data

    @staticmethod
    def from_json(data: dict) -> "TrafficClass":
        data = dict(data)
        data["ports"] = tuple(tuple(p) for p in data.get("ports", []))
        return TrafficClass(**data)


def classes_of(policy_spec: dict) -> list[TrafficClass]:
    return ordered([TrafficClass.from_spec(c) for c in policy_spec.get("classes", [])])


def ordered(classes: list[TrafficClass]) -> list[TrafficClass]:
    seen_rank, seen_dscp, seen_name = {}, {}, set()
    for cls in classes:
        if cls.name in seen_name:
            raise RenderError(f"class {cls.name} declared twice")
        if cls.rank in seen_rank:
            raise RenderError(f"{cls.name} and {seen_rank[cls.rank]} share rank {cls.rank}")
        if cls.dscp in seen_dscp:
            raise RenderError(f"{cls.name} and {seen_dscp[cls.dscp]} share DSCP {cls.dscp}")
        if cls.dscp == 0:
            raise RenderError(f"{cls.name}: DSCP 0 is the unclassified default")
        seen_name.add(cls.name)
        seen_rank[cls.rank], seen_dscp[cls.dscp] = cls.name, cls.name
    return sorted(classes, key=lambda c: c.rank)


def split_families(addresses) -> tuple[list[str], list[str]]:
    v4, v6 = set(), set()
    for raw in addresses:
        net = ipaddress.ip_network(raw, strict=False)
        (v4 if net.version == 4 else v6).add(net)
    return [str(n) for n in sorted(v4)], [str(n) for n in sorted(v6)]


def label_selector(selector: dict | None) -> str:
    """metav1.LabelSelector -> the label selector string list calls take."""
    if not selector:
        return ""
    parts = [f"{k}={v}" for k, v in sorted((selector.get("matchLabels") or {}).items())]
    for expr in selector.get("matchExpressions") or []:
        key, op, values = expr["key"], expr["operator"], sorted(expr.get("values") or [])
        if op == "In":
            parts.append(f"{key} in ({','.join(values)})")
        elif op == "NotIn":
            parts.append(f"{key} notin ({','.join(values)})")
        elif op == "Exists":
            parts.append(key)
        elif op == "DoesNotExist":
            parts.append(f"!{key}")
        else:
            raise RenderError(f"unknown selector operator {op!r}")
    return ",".join(parts)


def selector_matches(selector: dict | None, labels: dict) -> bool:
    """metav1.LabelSelector semantics; an empty selector matches everything."""
    if selector is None:
        return False
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False
    for expr in selector.get("matchExpressions") or []:
        key, op, values = expr["key"], expr["operator"], expr.get("values") or []
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and key in labels and labels[key] in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def class_members(pods: list[dict], endpoint_addresses: list[str], cidrs: list[str], node_ips: set[str]) -> list[str]:
    """Addresses that put a packet in a class: IPs of selected pods (not
    hostNetwork, whose IP is the node's), Service VIPs and endpoint
    addresses that are not node IPs, and declared CIDRs."""
    out = set()
    for pod in pods:
        if pod.get("hostNetwork") or pod.get("phase") not in ("Running", "Pending"):
            continue
        out.update(ip for ip in pod.get("ips", []) if ip and ip not in node_ips)
    out.update(ip for ip in endpoint_addresses if ip and ip not in node_ips)
    v4, v6 = split_families(list(out) + list(cidrs))
    return v4 + v6


# ---------------------------------------------------------------- router ----


@dataclass
class Wan:
    interface: str
    upload_kbit: int


@dataclass
class RouterSpec:
    lan_interface: str
    download_kbit: int
    wans: list[Wan]
    trusted_extra: list[str] = field(default_factory=list)

    @staticmethod
    def from_spec(spec: dict) -> "RouterSpec":
        wans = []
        for item in spec["wan"]:
            if not re.match(r"^(eth|wlan)\d+$", item["interface"]):
                raise RenderError(f"invalid WAN {item!r}")
            wans.append(Wan(item["interface"], rate_kbit(item["uploadRate"])))
        if not wans:
            raise RenderError("at least one WAN interface is required")
        if spec["lanInterface"] in {w.interface for w in wans}:
            raise RenderError("the LAN interface cannot be a WAN interface")
        return RouterSpec(spec["lanInterface"], rate_kbit(spec["downloadRate"]), wans,
                          list(spec.get("trustedSources", {}).get("cidrs", [])))


def router_owned_roots(spec: RouterSpec) -> list[tuple[str, ...]]:
    """Fixed config subtrees the controller owns outright. QOS-* firewall
    groups and policies found on the router are owned too (owned_from_live).

    Never anything under `interfaces`: a change to a WAN interface node
    (even `redirect`) re-runs its interface script, which restarts its DHCP
    clients, releases the lease and renumbers the IPv6 delegation. Whatever
    manages the rest of the router (interfaces, WAN load balancing, NAT, BGP,
    the firewall) keeps owning it."""
    return [("qos",)]


def render_router(spec: RouterSpec, classes: list[TrafficClass], trusted: list[str],
                  class_sources: dict[str, list[str]]) -> list[tuple[str, ...]]:
    """VyOS set-paths (tuples of words, value last).

    trusted: node addresses (from Node objects) plus any pod pools; the router
    keeps their DSCP and resets everyone else's. class_sources: per class with
    router.markSources, the Service VIPs whose LAN-ingress packets (replies of
    DNAT'd inbound flows, which leave the cluster unmarked) get its DSCP."""
    out: list[tuple[str, ...]] = []
    ranked = ordered(classes)
    if not trusted:
        # An empty node list means the Node read failed, not a cluster without
        # nodes; rendering would wash every node's DSCP.
        raise RenderError("no node addresses: refusing to wash every node's DSCP")
    trusted_v4, trusted_v6 = split_families(list(trusted) + spec.trusted_extra)
    for net in trusted_v4:
        out.append(("firewall", "group", "network-group", TRUSTED_V4, "network", net))
    for net in trusted_v6:
        out.append(("firewall", "group", "ipv6-network-group", TRUSTED_V6, "network", net))

    rule = 10
    for cls in ranked:
        if not cls.router_mark_sources:
            continue
        v4, v6 = split_families(class_sources.get(cls.name, []))
        group = f"{ROUTER_PREFIX}{cls.name.upper()}"
        for family, nets, kind, policy in (("V4", v4, "network-group", LAN_POLICY),
                                           ("V6", v6, "ipv6-network-group", LAN_POLICY6)):
            if not nets:
                continue
            for net in nets:
                out.append(("firewall", "group", kind, f"{group}-{family}", "network", net))
            route = "route" if family == "V4" else "route6"
            out.append(("policy", route, policy, "rule", str(rule), "source", "group", "network-group", f"{group}-{family}"))
            out.append(("policy", route, policy, "rule", str(rule), "set", "dscp", str(cls.dscp)))
            out.append(("policy", route, policy, "rule", str(rule), "action", "return"))
        rule += 10
    out.append(("policy", "route", LAN_POLICY, "interface", spec.lan_interface))
    out.append(("policy", "route", LAN_POLICY, "rule", "900", "source", "group", "network-group", TRUSTED_V4))
    out.append(("policy", "route", LAN_POLICY, "rule", "900", "action", "return"))
    out.append(("policy", "route", LAN_POLICY, "rule", "910", "set", "dscp", "0"))
    out.append(("policy", "route6", LAN_POLICY6, "interface", spec.lan_interface))
    if trusted_v6:
        out.append(("policy", "route6", LAN_POLICY6, "rule", "900", "source", "group", "network-group", TRUSTED_V6))
        out.append(("policy", "route6", LAN_POLICY6, "rule", "900", "action", "return"))
    out.append(("policy", "route6", LAN_POLICY6, "rule", "910", "set", "dscp", "0"))

    # Downloads are shaped where they leave the router toward the LAN: the
    # LAN interface's egress, post-NAT (real LAN destinations, so host
    # fairness needs no conntrack lookup) and after the policy routes above.
    # No ingress redirect, so no IFB and no WAN interface change.
    out.append(("qos", "policy", "cake", "QOS-LAN-DOWN", "bandwidth", f"{spec.download_kbit}kbit"))
    out.append(("qos", "policy", "cake", "QOS-LAN-DOWN", "flow-isolation", "dual-dst-host"))
    out.append(("qos", "interface", spec.lan_interface, "egress", "QOS-LAN-DOWN"))
    for wan in spec.wans:
        up = f"{ROUTER_PREFIX}{wan.interface.upper()}-UP"
        # nat: CAKE looks up conntrack for the pre-masquerade source, so LAN
        # hosts stay distinct behind the one public address.
        out.append(("qos", "policy", "cake", up, "bandwidth", f"{wan.upload_kbit}kbit"))
        out.append(("qos", "policy", "cake", up, "flow-isolation", "dual-src-host"))
        out.append(("qos", "policy", "cake", up, "flow-isolation-nat"))
        out.append(("qos", "interface", wan.interface, "egress", up))
    return sorted(set(out))


def set_command(path: tuple[str, ...]) -> str:
    """The `set` line VyOS prints in `show configuration commands`."""
    if path[-1] in VALUELESS:
        return "set " + " ".join(path)
    return "set " + " ".join(path[:-1]) + f" '{path[-1]}'"


def flatten(tree, prefix: tuple[str, ...] = ()) -> set[tuple[str, ...]]:
    """showConfig JSON -> set-paths. Valueless leaves ({}) keep their path."""
    paths: set[tuple[str, ...]] = set()
    if isinstance(tree, dict):
        if not tree and prefix:
            paths.add(prefix)
        for key, value in tree.items():
            paths |= flatten(value, prefix + (key,))
    elif isinstance(tree, list):
        for value in tree:
            paths.add(prefix + (str(value),))
    else:
        paths.add(prefix + (str(tree),))
    return paths


def owned_from_live(spec: RouterSpec, live: dict[tuple[str, ...], dict]) -> dict[tuple[str, ...], set]:
    """Map each owned root to its live set-paths. `live` maps a queried path
    to its showConfig JSON."""
    owned: dict[tuple[str, ...], set] = {}
    for root in router_owned_roots(spec):
        tree = live.get(root)
        owned[root] = flatten(tree, root) if tree not in (None, {}, "") else set()
    for kind in ("network-group", "ipv6-network-group", "address-group", "ipv6-address-group"):
        for name, tree in (live.get(("firewall", "group", kind)) or {}).items():
            if name.startswith(ROUTER_PREFIX):
                root = ("firewall", "group", kind, name)
                owned[root] = flatten(tree, root)
    for route in ("route", "route6"):
        for name, tree in (live.get(("policy", route)) or {}).items():
            if name.startswith(ROUTER_PREFIX):
                root = ("policy", route, name)
                owned[root] = flatten(tree, root)
    return owned


def root_of(path: tuple[str, ...]) -> tuple[str, ...]:
    if path[0] == "qos":
        return ("qos",)
    if path[:2] == ("firewall", "group") and path[3].startswith(ROUTER_PREFIX):
        return path[:4]
    if path[0] == "policy" and path[1] in ("route", "route6") and path[2].startswith(ROUTER_PREFIX):
        return path[:3]
    raise RenderError(f"rendered path {path} is outside the owned subtrees")


def router_ops(desired: list[tuple[str, ...]], live_owned: dict[tuple[str, ...], set]) -> list[dict]:
    """VyOS API ops that make every owned subtree equal to the desired one.
    A changed subtree is deleted and set again; unchanged subtrees produce no
    ops, so an in-sync router produces []. All ops go in one /configure
    request, which VyOS commits as one commit."""
    by_root: dict[tuple[str, ...], set] = {}
    for path in desired:
        by_root.setdefault(root_of(path), set()).add(path)
    ops: list[dict] = []
    for root in sorted(set(by_root) | set(live_owned)):
        want, have = by_root.get(root, set()), live_owned.get(root, set())
        if want == have:
            continue
        if have:
            ops.append({"op": "delete", "path": list(root)})
        for path in sorted(want):
            ops.append({"op": "set", "path": list(path)})
    return [op for op in ops if op["op"] == "delete"] + [op for op in ops if op["op"] == "set"]


def config_hash(paths) -> str:
    return hashlib.sha256("\n".join(sorted(set_command(p) for p in paths)).encode()).hexdigest()[:16]


def parse_cake_tins(text: str) -> dict[str, dict[str, int]]:
    """Per-tin counters from `tc -s qdisc show` output of a CAKE qdisc
    (what VyOS `show qos cake interface X` prints)."""
    lines = text.splitlines()
    header = None
    tins: dict[str, dict[str, int]] = {}
    for line in lines:
        if re.match(r"^\s+(Bulk|Tin 0)\s", line) or re.match(r"^\s+Bulk\s+Best Effort", line):
            header = re.split(r"\s{2,}", line.strip())
            tins = {name: {} for name in header}
            continue
        if header:
            parts = line.split()
            if len(parts) == len(header) + 1 and parts[0] in ("pkts", "bytes", "drops", "marks", "ack_drop", "way_inds"):
                for name, value in zip(header, parts[1:]):
                    if value.isdigit():
                        tins[name][parts[0]] = int(value)
    return tins


# ------------------------------------------------------------------ node ----


@dataclass(frozen=True)
class NodeProfile:
    mode: str  # Observe | Mark | Enforce
    root_percent: int
    min_default_percent: int

    @staticmethod
    def from_spec(spec: dict) -> "NodeProfile":
        mode = spec.get("mode", "Observe")
        if mode not in ("Observe", "Mark", "Enforce"):
            raise RenderError(f"node mode {mode!r} is not Observe, Mark or Enforce")
        root = int(spec.get("rootPercent", 97))
        if not 50 <= root <= 99:
            raise RenderError(f"rootPercent {root} outside 50-99")
        return NodeProfile(mode, root, int(spec.get("minDefaultPercent", 5)))


def node_config(policy_spec: dict, members: dict[str, list[str]], enforce_nodes: list[str]) -> dict:
    """The rendered node configuration: the node agent's only input."""
    nodes = policy_spec.get("nodes", {})
    profile = NodeProfile.from_spec(nodes)
    classes = classes_of(policy_spec)
    # Validate the queueing tree now, against the slowest link in service,
    # so a bad share fails in the controller rather than on 24 nodes.
    render_node_tc(profile, classes, "lo", 1000)
    body = {
        "mode": profile.mode,
        "rootPercent": profile.root_percent,
        "minDefaultPercent": profile.min_default_percent,
        "enforceNodes": sorted(enforce_nodes) if profile.mode == "Enforce" else [],
        "podInterfacePrefix": nodes.get("podInterfacePrefix", "cali"),
        "lanGateway": _required(nodes, "lanGateway"),
        "classes": [c.to_json() for c in classes],
        "members": {c.name: members.get(c.name, []) for c in classes},
    }
    body["hash"] = digest(body)
    return body


def _required(section: dict, key: str):
    if not section.get(key):
        raise RenderError(f"nodes.{key} is required")
    return section[key]


def node_mode(config: dict, node: str) -> str:
    """Queueing applies only on nodes the policy's enforceNodeSelector picked;
    every other node marks."""
    if config["mode"] == "Enforce" and node not in config["enforceNodes"]:
        return "Mark"
    return config["mode"]


def render_node_nft(classes: list[TrafficClass], interface: str, members: dict[str, list[str]],
                    pod_interface_prefix: str = "cali") -> str:
    """nftables table that sets DSCP on packets leaving the LAN interface.

    Classes are checked highest rank first; the first match wins. A packet is
    in a class when its source or destination is a member, so both directions
    of a flow are marked by whichever end runs this table. Pod-originated
    packets no class matches have their DSCP reset: a pod cannot claim a class
    with its own socket option. Host processes keep theirs (BIRD marks BGP
    CS6). Every rule counts, for the per-class counters."""
    if not re.match(r"^[A-Za-z0-9_.-]+$", interface) or not re.match(r"^[A-Za-z0-9_-]+$", pod_interface_prefix):
        raise RenderError(f"invalid interface {interface!r}")
    lines = ["table inet appmana_qos {"]
    ranked = ordered(classes)
    for cls in ranked:
        v4, v6 = split_families(members.get(cls.name, []))
        set_name = cls.name.replace("-", "_")
        for family, nets, kind in (("v4", v4, "ipv4_addr"), ("v6", v6, "ipv6_addr")):
            lines.append(f"  set {set_name}_{family} {{")
            lines.append(f"    type {kind}")
            lines.append("    flags interval")
            if nets:
                lines.append("    elements = { " + ", ".join(nets) + " }")
            lines.append("  }")
    lines.append("  chain postrouting {")
    lines.append("    type filter hook postrouting priority mangle + 10; policy accept;")
    lines.append(f'    oifname != "{interface}" accept')
    for cls in ranked:
        set_name = cls.name.replace("-", "_")
        comment = f'comment "{cls.name}"'
        for protocol, port in cls.ports:
            for direction in ("dport", "sport"):
                if protocol == "udp" and direction == "sport":
                    continue  # RoCEv2 source ports are per-QP hashes
                lines.append(f"    meta nfproto ipv4 {protocol} {direction} {port} counter ip dscp set {cls.dscp} accept {comment}")
                lines.append(f"    meta nfproto ipv6 {protocol} {direction} {port} counter ip6 dscp set {cls.dscp} accept {comment}")
        for direction in ("saddr", "daddr"):
            lines.append(f"    ip {direction} @{set_name}_v4 counter ip dscp set {cls.dscp} accept {comment}")
            lines.append(f"    ip6 {direction} @{set_name}_v6 counter ip6 dscp set {cls.dscp} accept {comment}")
    lines.append(f'    iifname "{pod_interface_prefix}*" ip dscp != 0 counter ip dscp set 0 comment "pod-wash"')
    lines.append(f'    iifname "{pod_interface_prefix}*" ip6 dscp != 0 counter ip6 dscp set 0 comment "pod-wash"')
    lines.append('    counter comment "default"')
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def class_minor(index: int) -> int:
    return 0x10 * (index + 1)


def render_node_tc(profile: NodeProfile, classes: list[TrafficClass], interface: str, link_mbit: int) -> list[str]:
    """`tc -batch` lines: an HTB root at rootPercent of the negotiated link
    speed, one class per TrafficClass (guaranteePercent of the root, ceiling
    the root, HTB priority by rank), a default class with the remainder, and
    DSCP -> class flower filters for IPv4 and IPv6."""
    if link_mbit <= 0:
        raise RenderError(f"{interface}: unknown link speed")
    ranked = ordered(classes)
    root = link_mbit * profile.root_percent // 100
    guaranteed = sum(c.guarantee_percent for c in ranked)
    if 100 - guaranteed < profile.min_default_percent:
        raise RenderError(f"guarantees sum to {guaranteed}%; the default class needs {profile.min_default_percent}%")
    # HTB's computed bursts are a few KB, far below one GSO segment at
    # multi-gigabit rates, which caps classes below their rate (lab finding).
    burst = "burst 256k cburst 256k"
    lines = [f"qdisc replace dev {interface} root handle 1: htb default {DEFAULT_MINOR:x} r2q 2000",
             f"class replace dev {interface} parent 1: classid 1:1 htb rate {root}mbit ceil {root}mbit {burst}"]
    for index, cls in enumerate(ranked):
        minor = class_minor(index)
        rate = max(1, root * cls.guarantee_percent // 100)
        lines.append(f"class replace dev {interface} parent 1:1 classid 1:{minor:x} htb rate {rate}mbit ceil {root}mbit {burst} prio {min(index, 7)}")
        leaf = "pfifo limit 3000" if cls.queue == "pfifo" else "fq_codel"
        lines.append(f"qdisc replace dev {interface} parent 1:{minor:x} handle {minor:x}: {leaf}")
    default_rate = root * (100 - guaranteed) // 100
    lines.append(f"class replace dev {interface} parent 1:1 classid 1:{DEFAULT_MINOR:x} htb rate {default_rate}mbit ceil {root}mbit {burst} prio 7")
    lines.append(f"qdisc replace dev {interface} parent 1:{DEFAULT_MINOR:x} handle {DEFAULT_MINOR:x}: fq_codel")
    for index, cls in enumerate(ranked):
        tos = f"0x{cls.dscp << 2:02x}/0xfc"
        # tc ties one filter priority to one protocol.
        lines.append(f"filter add dev {interface} parent 1: protocol ip prio {index + 1} flower ip_tos {tos} classid 1:{class_minor(index):x}")
        lines.append(f"filter add dev {interface} parent 1: protocol ipv6 prio {index + 101} flower ip_tos {tos} classid 1:{class_minor(index):x}")
    return lines


def class_of_minor(classes: list[TrafficClass], handle: str) -> str | None:
    """`1:20` -> class name (or "default")."""
    if not handle.startswith("1:"):
        return None
    minor = int(handle.split(":")[1] or "0", 16)
    if minor == DEFAULT_MINOR:
        return "default"
    for index, cls in enumerate(ordered(classes)):
        if class_minor(index) == minor:
            return cls.name
    return None


# --------------------------------------------------------------- switches ----


def render_switch(classes: list[TrafficClass], default_queue: int) -> dict:
    """Desired QNAP QSS QoS: DSCP-based mode and the queue each class DSCP
    maps to. DSCP values no class claims are left as the switch has them."""
    dscp = {str(c.dscp): c.switch_queue for c in ordered(classes) if c.switch_queue is not None}
    return {"mode": "dscp", "defaultQueue": default_queue, "dscpQueues": dscp}
