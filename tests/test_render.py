import copy
import importlib.util
import sys
from pathlib import Path
from unittest import TestCase, main

import yaml

HERE = Path(__file__).parent
from network_qos import render

POLICY = yaml.safe_load((HERE.parent / "examples" / "policy.yaml").read_text())["spec"]


def site_classes():
    return render.classes_of(POLICY)


def site_router():
    return render.RouterSpec.from_spec(POLICY["router"])


def site_profile(mode="Enforce"):
    return render.NodeProfile.from_spec({**POLICY["nodes"], "mode": mode})


def unflatten(paths):
    """set-paths -> the JSON shape VyOS /retrieve showConfig returns."""
    tree = {}
    for path in sorted(paths):
        node = tree
        if path[-1] in render.VALUELESS:
            for word in path[:-1]:
                node = node.setdefault(word, {})
            node[path[-1]] = {}
            continue
        for word in path[:-2]:
            node = node.setdefault(word, {})
        key, value = path[-2], path[-1]
        existing = node.get(key)
        if isinstance(existing, dict):
            continue
        if existing is None:
            node[key] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            node[key] = [existing, value]
    return tree


def live_for(spec, paths, extra=None):
    tree = unflatten(paths)
    for key, value in (extra or {}).items():
        node = tree
        for word in key[:-1]:
            node = node.setdefault(word, {})
        node[key[-1]] = value
    live = {}
    for root in render.router_owned_roots(spec):
        node = tree
        for word in root:
            node = node.get(word, {}) if isinstance(node, dict) else {}
        live[root] = node
    for kind in ("network-group", "ipv6-network-group", "address-group", "ipv6-address-group"):
        live[("firewall", "group", kind)] = tree.get("firewall", {}).get("group", {}).get(kind, {})
    for route in ("route", "route6"):
        live[("policy", route)] = tree.get("policy", {}).get(route, {})
    return live


TRUSTED = ["192.0.2.2", "192.0.2.9", "2001:db8:0:1::/64"]
SOURCES = {"realtime": ["203.0.113.65"], "web": ["203.0.113.99"]}


class PolicyTests(TestCase):
    def test_site_classes_are_consistent(self):
        classes = site_classes()
        self.assertEqual([c.name for c in classes], ["network-control", "rdma", "realtime", "web", "storage"])
        self.assertEqual([c.dscp for c in classes], [48, 26, 46, 34, 18])
        self.assertEqual(classes[1].ports, (("udp", 4791),))
        self.assertEqual(sum(c.guarantee_percent for c in classes), 94)

    def test_modes_are_valid_and_switches_stay_disabled(self):
        self.assertIn(POLICY["router"]["mode"], ("Observe", "Enforce"))
        self.assertIn(POLICY["nodes"]["mode"], ("Observe", "Mark", "Enforce"))
        self.assertFalse(POLICY["switches"]["enabled"])
        self.assertIn("credentials", POLICY["switches"]["disabledReason"])

    def test_duplicates_are_rejected(self):
        bad = copy.deepcopy(POLICY)
        bad["classes"].append({**bad["classes"][1], "name": "rdma2", "rank": 9})
        with self.assertRaisesRegex(render.RenderError, "share DSCP 26"):
            render.classes_of(bad)
        bad = copy.deepcopy(POLICY)
        bad["classes"].append({**bad["classes"][1], "name": "x", "dscp": 30})
        with self.assertRaisesRegex(render.RenderError, "share rank"):
            render.classes_of(bad)


class RouterRenderTests(TestCase):
    def setUp(self):
        self.spec = site_router()
        self.desired = render.render_router(self.spec, site_classes(), TRUSTED, SOURCES)
        self.lines = {render.set_command(p) for p in self.desired}

    def test_wan_shaping_is_cake_with_host_fairness_through_nat(self):
        for line in [
            "set qos policy cake QOS-LAN-DOWN bandwidth '900000kbit'",
            "set qos policy cake QOS-LAN-DOWN flow-isolation 'dual-dst-host'",
            "set qos interface eth2 egress 'QOS-LAN-DOWN'",
            "set qos policy cake QOS-ETH0-UP bandwidth '900000kbit'",
            "set qos policy cake QOS-ETH0-UP flow-isolation 'dual-src-host'",
            "set qos policy cake QOS-ETH0-UP flow-isolation-nat",
            "set qos interface eth0 egress 'QOS-ETH0-UP'",
        ]:
            self.assertIn(line, self.lines)
        self.assertFalse(any("wlan0" in line for line in self.lines))

    def test_never_touches_interfaces(self):
        # A change under a WAN interface node restarts its DHCP clients and
        # renumbered production on 2026-11-13.
        self.assertFalse(any(p[0] == "interfaces" for p in self.desired))
        self.assertEqual(render.router_owned_roots(self.spec), [("qos",)])
        with self.assertRaises(render.RenderError):
            render.root_of(("interfaces", "ethernet", "eth0", "redirect", "ifb0"))

    def test_untrusted_lan_dscp_is_washed_after_trusted_return(self):
        for line in ["set policy route QOS-LAN-IN interface 'eth2'",
                     "set policy route QOS-LAN-IN rule 900 source group network-group 'QOS-TRUSTED-V4'",
                     "set policy route QOS-LAN-IN rule 900 action 'return'",
                     "set policy route QOS-LAN-IN rule 910 set dscp '0'",
                     "set policy route6 QOS-LAN6-IN rule 910 set dscp '0'",
                     "set firewall group network-group QOS-TRUSTED-V4 network '192.0.2.9/32'",
                     "set firewall group network-group QOS-TRUSTED-V4 network '198.51.100.0/24'",
                     "set firewall group ipv6-network-group QOS-TRUSTED-V6 network '2001:db8:0:1::/64'"]:
            self.assertIn(line, self.lines)

    def test_dnat_reply_sources_get_their_class_and_stop(self):
        for line in ["set firewall group network-group QOS-REALTIME-V4 network '203.0.113.65/32'",
                     "set policy route QOS-LAN-IN rule 10 source group network-group 'QOS-REALTIME-V4'",
                     "set policy route QOS-LAN-IN rule 10 set dscp '46'",
                     "set policy route QOS-LAN-IN rule 10 action 'return'",
                     "set policy route QOS-LAN-IN rule 20 set dscp '34'"]:
            self.assertIn(line, self.lines)
        self.assertFalse(any("QOS-STORAGE" in line for line in self.lines))

    def test_router_never_sets_marks_that_wan_load_balancing_owns(self):
        self.assertFalse(any("mark" in word for p in self.desired for word in p[:-1]))

    def test_no_node_addresses_refuses_to_render(self):
        with self.assertRaisesRegex(render.RenderError, "no node addresses"):
            render.render_router(self.spec, site_classes(), [], SOURCES)

    def test_in_sync_router_produces_no_ops(self):
        live = render.owned_from_live(self.spec, live_for(self.spec, self.desired))
        self.assertEqual(render.router_ops(self.desired, live), [])

    def test_production_today_is_replaced_in_one_change(self):
        production = {("qos",): {"interface": {"eth0": {"egress": "UPLOAD-SHAPER"}},
                                 "policy": {"shaper": {"UPLOAD-SHAPER": {"bandwidth": "1gbit", "default": {"bandwidth": "95%", "queue-type": "fq-codel"}}}}},
                      ("firewall", "group", "network-group"): {"OTHER-NETS": {"network": ["198.51.100.0/24", "203.0.113.0/24"]}}}
        ops = render.router_ops(self.desired, render.owned_from_live(self.spec, production))
        self.assertEqual(ops[0], {"op": "delete", "path": ["qos"]})
        self.assertEqual(sum(1 for op in ops if op["op"] == "delete"), 1)
        self.assertFalse(any("OTHER-NETS" in op["path"] for op in ops))
        self.assertEqual({render.set_command(tuple(op["path"])) for op in ops if op["op"] == "set"}, self.lines)

    def test_rate_change_rewrites_only_qos(self):
        live = render.owned_from_live(self.spec, live_for(self.spec, self.desired))
        spec = site_router()
        spec.download_kbit = 920000
        ops = render.router_ops(render.render_router(spec, site_classes(), TRUSTED, SOURCES), live)
        self.assertEqual([op for op in ops if op["op"] == "delete"], [{"op": "delete", "path": ["qos"]}])
        self.assertTrue(all(op["path"][0] == "qos" for op in ops))

    def test_stale_owned_group_is_deleted_and_foreign_groups_kept(self):
        extra = {("firewall", "group", "network-group", "QOS-OLD-V4"): {"network": "192.0.2.250/32"},
                 ("firewall", "group", "network-group", "OTHER-NETS"): {"network": "198.51.100.0/24"}}
        live = render.owned_from_live(self.spec, live_for(self.spec, self.desired, extra))
        self.assertEqual(render.router_ops(self.desired, live),
                         [{"op": "delete", "path": ["firewall", "group", "network-group", "QOS-OLD-V4"]}])

    def test_new_node_touches_only_the_trusted_group(self):
        live = render.owned_from_live(self.spec, live_for(self.spec, self.desired))
        ops = render.router_ops(render.render_router(self.spec, site_classes(), TRUSTED + ["192.0.2.68"], SOURCES), live)
        self.assertTrue(all(op["path"][:4] == ["firewall", "group", "network-group", "QOS-TRUSTED-V4"] for op in ops))

    def test_cake_tin_parsing(self):
        text = """qdisc cake 8004: root refcnt 2 bandwidth 276Mbit diffserv3 dual-dsthost nat nowash
 Sent 123 bytes 4 pkt (dropped 2, overlimits 0 requeues 0)
                   Bulk  Best Effort        Voice
  thresh      17250Kbit      276Mbit       69Mbit
  pkts                0      1026920         2004
  bytes               0   1458000000      2004000
  drops               0          113            0
  marks               0            5            0
"""
        tins = render.parse_cake_tins(text)
        self.assertEqual(tins["Best Effort"], {"pkts": 1026920, "bytes": 1458000000, "drops": 113, "marks": 5})
        self.assertEqual(tins["Voice"]["pkts"], 2004)


class NodeTests(TestCase):
    def test_node_config_is_the_agents_whole_input(self):
        members = {"storage": ["198.51.100.19/32"]}
        cfg = render.node_config({**POLICY, "nodes": {**POLICY["nodes"], "mode": "Enforce"}}, members, ["node-a"])
        self.assertEqual(cfg["enforceNodes"], ["node-a"])
        self.assertEqual(cfg["members"]["storage"], ["198.51.100.19/32"])
        self.assertEqual(cfg["members"]["rdma"], [])
        self.assertEqual(render.node_mode(cfg, "node-a"), "Enforce")
        self.assertEqual(render.node_mode(cfg, "node-b"), "Mark")
        classes = [render.TrafficClass.from_json(c) for c in cfg["classes"]]
        self.assertEqual(classes, site_classes())
        observe = render.node_config({**POLICY, "nodes": {**POLICY["nodes"], "mode": "Observe"}}, members, ["node-a"])
        self.assertEqual(observe["enforceNodes"], [])
        self.assertEqual(render.node_mode(observe, "node-a"), "Observe")
        self.assertNotEqual(observe["hash"], cfg["hash"])

    def test_enforce_selector_semantics(self):
        selector = POLICY["nodes"]["enforceNodeSelector"]
        self.assertFalse(render.selector_matches(selector, {"kubernetes.io/hostname": "node-a"}))
        wider = {"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": ["node-a", "node-c"]}]}
        self.assertTrue(render.selector_matches(wider, {"kubernetes.io/hostname": "node-c"}))
        self.assertTrue(render.selector_matches({}, {"a": "b"}))
        self.assertFalse(render.selector_matches(None, {"a": "b"}))
        self.assertFalse(render.selector_matches({"matchExpressions": [{"key": "x", "operator": "DoesNotExist"}]}, {"x": "1"}))

    def test_htb_tree_on_a_2500_mbit_link(self):
        lines = render.render_node_tc(site_profile(), site_classes(), "enp110s0", 2500)
        self.assertEqual(lines[0], "qdisc replace dev enp110s0 root handle 1: htb default 99 r2q 2000")
        for line in ["class replace dev enp110s0 parent 1: classid 1:1 htb rate 2425mbit ceil 2425mbit burst 256k cburst 256k",
                     "class replace dev enp110s0 parent 1:1 classid 1:10 htb rate 48mbit ceil 2425mbit burst 256k cburst 256k prio 0",
                     "class replace dev enp110s0 parent 1:1 classid 1:20 htb rate 1600mbit ceil 2425mbit burst 256k cburst 256k prio 1",
                     "qdisc replace dev enp110s0 parent 1:20 handle 20: pfifo limit 3000",
                     "class replace dev enp110s0 parent 1:1 classid 1:50 htb rate 436mbit ceil 2425mbit burst 256k cburst 256k prio 4",
                     "class replace dev enp110s0 parent 1:1 classid 1:99 htb rate 145mbit ceil 2425mbit burst 256k cburst 256k prio 7",
                     "filter add dev enp110s0 parent 1: protocol ip prio 2 flower ip_tos 0x68/0xfc classid 1:20",
                     "filter add dev enp110s0 parent 1: protocol ipv6 prio 102 flower ip_tos 0x68/0xfc classid 1:20"]:
            self.assertIn(line, lines)
        prios = [(line.split()[7], line.split()[9]) for line in lines if line.startswith("filter")]
        self.assertEqual(len(prios), len(set(prios)))

    def test_rates_follow_the_negotiated_speed(self):
        lines = render.render_node_tc(site_profile(), site_classes(), "eno1", 1000)
        self.assertIn("class replace dev eno1 parent 1:1 classid 1:20 htb rate 640mbit ceil 970mbit burst 256k cburst 256k prio 1", lines)

    def test_class_of_minor(self):
        self.assertEqual(render.class_of_minor(site_classes(), "1:20"), "rdma")
        self.assertEqual(render.class_of_minor(site_classes(), "1:99"), "default")
        self.assertIsNone(render.class_of_minor(site_classes(), "1:1"))

    def test_overcommitted_guarantees_are_rejected_by_the_controller(self):
        bad = copy.deepcopy(POLICY)
        bad["classes"].append({"name": "bulk", "dscp": "CS1", "rank": 9, "node": {"guaranteePercent": 30}})
        with self.assertRaisesRegex(render.RenderError, "default class needs"):
            render.node_config(bad, {}, [])

    def test_unknown_speed_is_rejected(self):
        with self.assertRaisesRegex(render.RenderError, "unknown link speed"):
            render.render_node_tc(site_profile(), site_classes(), "eno1", -1)

    def test_nft_marks_by_registered_port_and_membership_and_washes_pods(self):
        members = {"storage": ["198.51.100.19/32", "192.0.2.73/32", "2001:db8:ffff::1/128"], "web": ["203.0.113.99/32"]}
        text = render.render_node_nft(site_classes(), "enp110s0", members)
        self.assertIn('oifname != "enp110s0" accept', text)
        self.assertIn('meta nfproto ipv4 udp dport 4791 counter ip dscp set 26 accept comment "rdma"', text)
        self.assertNotIn("udp sport 4791", text)
        self.assertIn('meta nfproto ipv4 tcp sport 2379 counter ip dscp set 48 accept comment "network-control"', text)
        self.assertIn("elements = { 192.0.2.73/32, 198.51.100.19/32 }", text)
        self.assertIn('ip daddr @storage_v4 counter ip dscp set 18 accept comment "storage"', text)
        self.assertIn('ip6 saddr @storage_v6 counter ip6 dscp set 18 accept comment "storage"', text)
        self.assertLess(text.index("dport 4791"), text.index("@storage_v4"))
        self.assertIn('iifname "cali*" ip dscp != 0 counter ip dscp set 0 comment "pod-wash"', text)

    def test_nft_rejects_odd_interface_names(self):
        with self.assertRaises(render.RenderError):
            render.render_node_nft(site_classes(), 'eth0" accept; drop', {})


class MembershipAndSwitchTests(TestCase):
    def test_label_selector_strings(self):
        self.assertEqual(render.label_selector({"matchLabels": {"b": "2", "a": "1"},
                                                "matchExpressions": [{"key": "c", "operator": "In", "values": ["y", "x"]},
                                                                     {"key": "cnpg.io/cluster", "operator": "Exists"}]}),
                         "a=1,b=2,c in (x,y),cnpg.io/cluster")

    def test_members_skip_host_network_pods_and_node_endpoints(self):
        pods = [{"ips": ["198.51.100.19", "2001:db8:0:1::12"], "phase": "Running"},
                {"ips": ["192.0.2.20"], "phase": "Running", "hostNetwork": True},
                {"ips": ["198.51.100.1"], "phase": "Succeeded"}]
        members = render.class_members(pods, ["203.0.113.99", "192.0.2.7"], ["192.0.2.73/32"], {"192.0.2.7", "192.0.2.20"})
        self.assertEqual(members, ["192.0.2.73/32", "198.51.100.19/32", "203.0.113.99/32", "2001:db8:0:1::12/128"])

    def test_switch_render(self):
        desired = render.render_switch(site_classes(), 0)
        self.assertEqual(desired, {"mode": "dscp", "defaultQueue": 0,
                                   "dscpQueues": {"48": 7, "26": 7, "46": 6, "34": 5, "18": 3}})


if __name__ == "__main__":
    main()
