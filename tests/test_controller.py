import types
from pathlib import Path
from unittest import TestCase, main, mock

import yaml

HERE = Path(__file__).parent
from network_qos import controller

POLICY = yaml.safe_load((HERE.parent / "examples" / "policy.yaml").read_text())["spec"]

# The shapes VyOS prints for `show bgp summary` and `show wan-load-balance`.
BGP = """
Neighbor                           V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
192.0.2.2                           4      65414    147146    138079   147920    0    0 3d00h33m           57       34 N/A
*192.0.2.3                          4      65414     11326    108129   147920    0    0 6d05h07m            1       34 N/A
192.0.2.41                          4      65414    162128    151682   147920    0    0 2d22h53m           57       34 N/A
192.0.2.68                          4      65414         0         0        0    0    0    never       Active        0 N/A
2001:db8::1ac0:4dff:fe89:5194 4      65414     10          9        0    0    0 00:10:00            3        2 N/A
"""
WLB = """Interface: eth0
Status: active
Last Status Change: 2026-11-13 00:01:48

Interface: wlan0
Status: failed
"""


class HealthTests(TestCase):
    def test_established_sessions(self):
        self.assertEqual(controller.vyos_target.established_bgp_sessions(BGP), 4)

    def test_active_wans(self):
        self.assertEqual(controller.vyos_target.active_wans(WLB), {"eth0"})

    def test_health_gate(self):
        before = {"bgp": 30, "wans": ["eth0", "wlan0"]}
        self.assertTrue(controller.vyos_target.healthy_after(before, {"bgp": 30, "wans": ["eth0", "wlan0"]}))
        self.assertFalse(controller.vyos_target.healthy_after(before, {"bgp": 29, "wans": ["eth0", "wlan0"]}))
        self.assertFalse(controller.vyos_target.healthy_after(before, {"bgp": 30, "wans": ["eth0"]}))


class VyOSApiTests(TestCase):
    def test_empty_path_is_an_empty_subtree_not_an_error(self):
        router = controller.VyOS("https://192.0.2.1:9090", "k")
        empty = mock.Mock()
        empty.json.return_value = {"success": False, "error": "Configuration under specified path is empty\n", "data": None}
        with mock.patch.object(controller.vyos_target.requests, "post", return_value=empty):
            self.assertEqual(router.show_config(("qos",)), {})
        broken = mock.Mock()
        broken.json.return_value = {"success": False, "error": "Invalid key", "data": None}
        with mock.patch.object(controller.vyos_target.requests, "post", return_value=broken):
            with self.assertRaisesRegex(RuntimeError, "Invalid key"):
                router.show_config(("qos",))


    def test_tag_and_leaf_paths_are_unwrapped(self):
        router = controller.VyOS("https://192.0.2.1:9090", "k")
        for path, data, want in [
                (("firewall", "group", "network-group"), {"network-group": {"QOS-TRUSTED-V4": {"network": "192.0.2.2/32"}}},
                 {"QOS-TRUSTED-V4": {"network": "192.0.2.2/32"}}),
                (("interfaces", "ethernet", "eth0", "redirect"), {"redirect": "ifb0"}, "ifb0"),
                (("qos",), {"interface": {"eth0": {"egress": "QOS-ETH0-UP"}}}, {"interface": {"eth0": {"egress": "QOS-ETH0-UP"}}})]:
            response = mock.Mock()
            response.json.return_value = {"success": True, "data": data}
            with mock.patch.object(controller.vyos_target.requests, "post", return_value=response):
                self.assertEqual(router.show_config(path), want)


class SwitchTests(TestCase):
    def test_disabled_switches_report_reason_and_reachability(self):
        response = mock.Mock()
        response.json.return_value = {"error_code": 401, "error_message": "Unauthorized", "result": None}
        with mock.patch.object(controller.requests, "request", return_value=response) as request:
            state = controller.switch_state(POLICY)
        self.assertEqual(state["phase"], "Disabled")
        self.assertIn("credentials", state["reason"])
        self.assertEqual(len(state["devices"]), 1)
        self.assertTrue(all(d["reachable"] and not d["authorised"] for d in state["devices"]))
        self.assertEqual(request.call_args.args[:2], ("GET", "https://192.0.2.23/api/v3/qos/mode"))

    def test_enabled_without_secret_is_unauthorised(self):
        policy = {**POLICY, "switches": {**POLICY["switches"], "enabled": True}}
        response = mock.Mock()
        response.json.return_value = {"error_code": 401}
        with mock.patch.object(controller, "secret_value", return_value=None), \
                mock.patch.object(controller.requests, "request", return_value=response):
            state = controller.switch_state(policy)
        self.assertEqual(state["phase"], "Unauthorised")


class ClusterReadTests(TestCase):
    def test_service_addresses_with_kubernetes_36_attribute_names(self):
        svc = types.SimpleNamespace(spec=types.SimpleNamespace(cluster_ips=["203.0.113.65", "2001:db8:ffff::41"]))
        core = mock.Mock()
        core.read_namespaced_service.return_value = svc
        with mock.patch.object(controller.client, "CoreV1Api", return_value=core):
            self.assertEqual(controller.service_addresses("media", "turn"), ["203.0.113.65", "2001:db8:ffff::41"])


class RouterMetricsTests(TestCase):
    def test_tin_metrics(self):
        text = controller.router_metrics({"eth2-download": {"Voice": {"pkts": 5, "drops": 1}}})
        self.assertIn('appmana_qos_router_tin_drops_total{interface="eth2",direction="download",tin="Voice"} 1', text)


if __name__ == "__main__":
    main()


class StoredStateTests(TestCase):
    """Decisions use the stored object, not kopf's cached body, which can go
    stale after an API server restart."""

    def test_agent_rollup_compares_against_the_rendered_configmap(self):
        import asyncio
        states = [{"node": "node-a", "mode": "Mark", "appliedHash": "h2"},
                  {"node": "node-b", "mode": "Mark", "appliedHash": "h2"}]
        patch = types.SimpleNamespace(status={})
        stale = {"agents": {"summary": "0/2 applied Mark=2", "nodes": []}, "nodes": {"renderedHash": "h1"}}
        with mock.patch.object(controller, "agent_states", return_value=states), \
                mock.patch.object(controller, "fresh", return_value=({}, stale, 3)), \
                mock.patch.object(controller, "rendered_hash", return_value="h2"):
            asyncio.run(controller.collect_agents(name="site", patch=patch))
        self.assertEqual(patch.status["agents"]["summary"], "2/2 applied Mark=2")

    def test_a_reverted_configuration_is_not_reapplied(self):
        import asyncio
        spec = {**POLICY, "router": {**POLICY["router"], "mode": "Enforce"}}
        router_spec = controller.render.RouterSpec.from_spec(spec["router"])
        desired = controller.render.render_router(router_spec, controller.render.classes_of(spec), ["192.0.2.2"], {})
        digest = controller.render.config_hash(desired)
        status = {"router": {"revertedHash": digest, "phase": "Reverted"}}
        patch = types.SimpleNamespace(status={})
        logger = mock.Mock()
        with mock.patch.object(controller, "fresh", return_value=(spec, status, 4)), \
                mock.patch.object(controller, "router_inputs", return_value=(router_spec, desired)), \
                mock.patch.object(controller, "secret_value", return_value="key"), \
                mock.patch.object(controller.vyos_target, "live_owned", return_value={}), \
                mock.patch.object(controller.vyos_target, "counters", return_value={}), \
                mock.patch.object(controller.vyos_target, "apply") as apply:
            asyncio.run(controller.reconcile_router(name="site", patch=patch, logger=logger))
        apply.assert_not_called()
        self.assertEqual(patch.status["router"]["phase"], "Reverted")
        self.assertEqual(patch.status["router"]["observedGeneration"], 4)
