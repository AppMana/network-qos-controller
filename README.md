# network-qos-controller

One `NetworkQosPolicy` resource and one [kopf](https://github.com/nolar/kopf)
controller that keep a site's traffic classes enforced on three targets:

- **the router**: VyOS QoS (CAKE with per-host fairness: downloads on the LAN
  interface's egress, uploads on each WAN interface's egress) and DSCP rules
  (keep DSCP from cluster sources, reset it from everyone else, mark replies
  of DNAT'd services), applied through the VyOS HTTPS API;
- **every Linux node**: DSCP marking in an nftables table of its own, and
  optionally an HTB tree on the LAN interface that guarantees each class a
  share of the link, applied by a DaemonSet agent;
- **managed QNAP switches**: DSCP-based QoS mode and the DSCP to queue map,
  through the switches' QSS REST API.

DSCP is the only carrier of a class between hosts, router and switches.

## Classes

A class has a DSCP value, a rank (0 is highest), a node guarantee (percent of
the node's shaped LAN rate), a switch queue, and what it matches:

- `ports`: registered protocol ports only (RoCEv2 UDP 4791, BGP, etcd);
- `pods`: `namespaceSelector`/`podSelector` pairs (`metav1.LabelSelector`);
- `services`: Service references (VIPs and endpoints);
- `cidrs`: off-cluster endpoints.

The controller resolves selectors to member addresses. A packet whose source
or destination is a member gets the class, so whichever end runs the agent
marks both directions. A pod cannot claim a class by setting its own DSCP;
the agent resets it unless a class selects the pod.

`examples/policy.yaml` is a complete policy.

## Router

The controller owns `qos`, `firewall group * QOS-*` and `policy route{,6}
QOS-*` and nothing else. It never writes under `interfaces`: on VyOS a
change to a WAN interface node re-runs that interface's script and restarts
its DHCP clients, which releases the lease and renumbers a delegated prefix.

A change is applied as one commit-confirm commit. The controller waits, then
requires that the API still answers, that no established BGP session was
lost and that every WAN load-balancing interface that was active still is.
Only then does it confirm and save; otherwise the router reverts by itself
and the controller does not retry that exact configuration until it changes.

Modes: `Observe` (report the ops it would commit in status) and `Enforce`.

## Nodes

The controller renders a ConfigMap (classes, members, which nodes queue);
it is the agent's only input. The agent adds two local facts, the interface
toward `nodes.lanGateway` and its negotiated speed (or the node annotation
`network.appmana.com/lan-mbit`), and applies by mode:

- `Observe`: nothing;
- `Mark`: table `inet appmana_qos`, a POSTROUTING chain at `mangle + 10` on
  the LAN interface, replaced in one transaction;
- `Enforce` (nodes matching `nodes.enforceNodeSelector`): additionally an HTB
  root at `rootPercent` of link speed, a class per TrafficClass at its
  guarantee, ceiling the root, priority by rank, a default class, and
  DSCP to class filters. A tc failure deletes the root so the kernel default
  qdisc returns. An agent restart does not swap a live tree.

The agent needs `hostNetwork` and the `NET_ADMIN` capability, nothing else.

## Switches

QNAP QSS REST API v3: `POST /api/v3/users/login`, `/api/v3/qos/mode`,
`/api/v3/qos/dscp`. Disabled until a credentials Secret exists; status reports
each switch's reachability and authorisation either way.

## Status and metrics

`kubectl get nqos site -o yaml` shows each target's phase, observed
generation, desired and applied hash, last error and counters. Prometheus:
`appmana_qos_class_{bytes,packets,drops,overlimits}_total{node,class}` and
`appmana_qos_marked_{packets,bytes}_total{node,class}` from agents (`:9817`),
`appmana_qos_router_tin_{packets,bytes,drops,ecn_marks}_total` from the
controller (`:9818`).

## Development

```shell
uv run --locked pytest
```

`config/` holds the CRD and a kustomize base; images are published to
`ghcr.io/appmana/network-qos-controller` for tags `v*`.
