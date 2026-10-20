# Morpheus Phase 1: flow-aware IoT SDN lab

Morpheus Phase 1 is the SDN foundation for a future moving-target-defense project. It provides an isolated virtual IoT topology, baseline forwarding, OpenFlow flow telemetry, simple legitimate traffic, a controlled reconnaissance exercise, and a deterministic detector that emits **suspicion events**. It is not a complete moving-target defense: Phase 1 does not mutate addresses, ports, switch rules, or sessions in response to detection.

## Components

- `topology.py` creates a single Open vSwitch bridge with OpenFlow 1.3 and connects it to a Ryu `RemoteController` endpoint. Hosts are Mininet namespaces with no physical interfaces attached.
- `morpheus/controller.py` installs a table-miss rule, learns source MAC addresses, floods unknown destinations, and installs learned unicast rules. Learned rules include IP/protocol/transport fields when available and expire after 60 seconds idle.
- `morpheus/monitoring.py` normalizes flow entries into `FlowObservation`, including source/destination IPs, protocol and ports, counters, duration, observation timestamp, datapath, table, priority, cookie, and stable flow ID.
- `morpheus/detection.py` consumes normalized observations. For a source, it emits one structured `suspicious` event when at least 3 distinct configured destination hosts **or** 3 distinct destination ports appear within 30 seconds. Events contain the evidence hosts/ports and reason. This is a heuristic, not proof of malicious intent. Detection has no switch or network mutation capability.
- `scripts/traffic_server.py` receives UDP updates on port 9001 and answers TCP requests on port 9000.
- `scripts/traffic_generator.py` sends periodic UDP sensor updates and, by default, a TCP request every fifth update. It accepts only configured sensor source labels and the configured server destination. Minimum update interval is 0.05 seconds; default is 2 seconds.
- `scripts/reconnaissance.py` performs opt-in TCP connect probes. Hostnames and exact configured lab IPs are allowlisted; hostnames map directly to configured IPs without DNS before a connection is attempted. The minimum inter-attempt delay is 0.25 seconds and connection timeout is capped at 5 seconds.

## Verified lab configuration

The source of truth is `morpheus/lab_config.py`. All addresses are unique and are configured on one `/24` subnet; every host is linked to `s1`.

| Role | Hostnames | Addresses |
|---|---|---|
| Sensors | `sensor1`–`sensor8` | `10.0.0.1`–`10.0.0.8` |
| Actuators | `actuator1`, `actuator2` | `10.0.0.21`, `10.0.0.22` |
| Server | `server` | `10.0.0.100` |
| Virtual attacker | `attacker` | `10.0.0.200` |
| OVS switch | `s1` | No host IP |
| Ryu controller | `c0` remote endpoint | `127.0.0.1:6653` by default |

The topology has 12 hosts, one OVS switch, and 12 host-to-switch links. `s1` is configured with `protocols=OpenFlow13` and `failMode=secure`. The Ryu process runs outside the Mininet topology; the default loopback endpoint is for this same machine. An alternate literal controller IP and port can be supplied to `topology.py`.

## Environment and interpreters

At the last audit, this environment had:

- Project `.venv`: Python 3.9.22 (`python3` resolves here in the interactive shell).
- `/usr/bin/python3`: Python 3.10.12, with Mininet 2.3.0 and Ryu 4.34 available.
- `/home/rai/.local/bin/ryu-manager`, whose shebang uses `/usr/bin/python3`.
- Open vSwitch 2.17.12; `ovs-ofctl` advertises OpenFlow 1.3 support.

Use the explicit interpreter paths below to avoid the venv/system mismatch. No extra Python packages are declared or installed by this repository. The project source and scripts are compatible with both interpreters listed above.

## Offline validation

From the repository root, the rootless suite does not open sockets or require Mininet/Ryu:

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q morpheus scripts topology.py tests
```

Topology validation without launching Mininet uses the installed system interpreter:

```sh
/usr/bin/python3 - <<'PY'
from topology import MorpheusIoTTopology
from morpheus.lab_config import HOSTS

topo = MorpheusIoTTopology()
print("hosts:", len(topo.hosts()), topo.hosts())
print("switches:", len(topo.switches()), topo.switches())
print("links:", len(topo.links()), len(HOSTS))
print("switch options:", topo.nodeInfo("s1"))
PY
```

This only constructs a topology description; it does not create namespaces, interfaces, or OVS state.

## Live integration procedure (requires operator approval)

These commands have **not** been run as part of the offline validation. Starting Mininet creates network namespaces/veth links and changes OVS runtime state. Do not run this procedure until you are ready to approve that live lab startup. The commands do not attach a physical interface or target outside the virtual topology.

### Terminal 1: Ryu controller

From `/home/rai/morpheus`, run as the normal user:

```sh
/home/rai/.local/bin/ryu-manager morpheus/controller.py
```

Expected: Ryu loads `MorpheusBaselineController` and remains running. A switch connection log should appear after the topology starts. This listener uses TCP port 6653 and does not require root.

### Terminal 2: Mininet topology

From `/home/rai/morpheus`, start with root and the system Mininet interpreter:

```sh
sudo /usr/bin/python3 topology.py
```

Expected: Mininet starts hosts `sensor1`–`sensor8`, `actuator1`, `actuator2`, `server`, and `attacker`, then presents the `mininet>` prompt. The controller endpoint is `127.0.0.1:6653`. Startup errors should unwind through `net.stop()`; if cleanup itself fails, its error is logged.

### Check switch/controller and connectivity

At `mininet>` run:

```text
sh ovs-vsctl get-controller s1
sh ovs-vsctl get Bridge s1 protocols
sh ovs-ofctl -O OpenFlow13 show s1
pingall
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Expected: the controller is `tcp:127.0.0.1:6653`, protocols include `OpenFlow13`, the switch responds to `show`, and `pingall` reports no dropped host pairs. Initially the flow dump should include the priority-0 table-miss rule. After traffic and MAC learning, it should also contain priority-1 learned rules with 60-second idle timeout. If ping fails, first check Terminal 1 for the switch-connected message and inspect the controller endpoint/protocol output before starting traffic.

### Check flow monitoring

Wait for a 10-second statistics interval or generate traffic as below. Terminal 1 should show `FLOW_STATS_REQUEST` and `FLOW_STATS_REPLY` records, followed by `FLOW_OBSERVATION` JSON entries for observed flows. The normalized entry contains counters, duration, timestamp, datapath ID, and flow ID. An empty reply is logged with zero entries and does not crash the app. Requests are not overlapped; an unreturned request expires after three poll intervals and is logged before retry.

### Start legitimate traffic explicitly

At `mininet>` start the server and a sensor generator in the background:

```text
server /usr/bin/python3 /home/rai/morpheus/scripts/traffic_server.py &
sensor1 /usr/bin/python3 /home/rai/morpheus/scripts/traffic_generator.py --source 10.0.0.1 --server 10.0.0.100 --interval 2 --duration 60 --tcp-every 5 &
```

Expected: the server reports both listeners, sensor output reports UDP updates and periodic TCP `ACK` responses, and the server logs received messages. Repeat with another sensor IP to model another legitimate source. The generator stops at the requested duration; `--duration 0` runs until stopped.

The Mininet CLI does not provide shell `jobs`/`kill %N` commands. Stop a long-running background server or generator in its own host namespace with:

```text
server pkill -f '[t]raffic_server.py'
sensor1 pkill -f '[t]raffic_generator.py'
```

Finite generators exit on their own. If a background command reports an address bind error, stop the matching process and check for a duplicate server process before retrying.

### Run one controlled reconnaissance exercise

Reconnaissance is **never automatic**. At `mininet>`, use the virtual attacker and a small target set:

```text
attacker /usr/bin/python3 /home/rai/morpheus/scripts/reconnaissance.py --targets 10.0.0.1 10.0.0.2 10.0.0.3 --ports 22 80 9000 --delay 1 --timeout 0.5
```

Mininet CLI rewrites arguments matching its node names to IP addresses, so the example uses the configured IPs. The script accepts only a configured hostname or its exact lab IP, normalizes both to a host, maps hostnames directly from the static address table without DNS, then connects to that pinned IP. Expected: it logs `(hostname, configured IP)` targets and one `open` or `closed_or_filtered` outcome per target/port. It probes TCP only and waits at least one second here (never less than 0.25 seconds). Arbitrary addresses and unconfigured names are rejected.

After the next statistics reply, Terminal 1 should show a JSON `DETECTION_EVENT` with `decision: "suspicious"`, source IP, reason, distinct host/port counts, and the evidence destination lists. The default threshold is 3 hosts or 3 ports in 30 seconds. Background sensor-to-server traffic is a single destination and ordinarily does not meet this fan-out rule. A detector event is suspicious evidence only, not a confirmed attacker attribution.

### Shut down cleanly

At `mininet>`, stop any remaining lab processes with the host-namespace `pkill` commands above and exit:

```text
exit
```

The topology's `finally` block calls `net.stop()` on normal exit and exceptions. Then stop Ryu with Ctrl-C in Terminal 1. If topology startup or cleanup fails, inspect the printed error and OVS state before retrying; do not use broad cleanup commands that affect other Mininet labs.

## Troubleshooting and limits

- **Ryu command not found:** use `/home/rai/.local/bin/ryu-manager`; do not activate `.venv` for the controller.
- **Mininet import errors:** run topology with `sudo /usr/bin/python3`, not the project Python 3.9 venv.
- **No switch connection:** verify the controller is listening in Terminal 1, then check `get-controller` and `OpenFlow13` output in Mininet.
- **No flow observations:** generate host traffic, wait one poll period, and inspect the flow dump. The table-miss can count packets without IP fields; detector decisions require source/destination information and relevant fields from learned rules.
- **No detection event:** the heuristic needs three distinct configured destination hosts or three destination ports within 30 seconds. Verify the attacker command targets the intended virtual hosts and that OpenFlow observations include those destinations. Do not lower thresholds just to force an event.
- **Recon target mismatch:** recon fails closed. Use one of the configured IPs from the table in the Mininet CLI (it substitutes hostnames in command arguments) or a configured hostname when calling the script directly inside a host.
- Flow stats are cumulative switch counters, not proof of intent. The detector deduplicates flow identities and does not threshold packet volume, so counter resets do not increase fan-out. Switch flow entries expire after 60 seconds idle; the monitor retains only a bounded recent window.

## Deferred to Phase 2

Dynamic IP or port mutation, virtual address mapping/translation, ARP rewriting, mutation-response OVS rules, coordinated mutation, cooldown/grace periods for real changes, session preservation, timer-based MTD, and baseline-versus-MTD experiments are explicitly out of scope. No research performance claims or conclusions are made here.
