"""Ryu OpenFlow 1.3 learning switch with periodic flow observations.

Run with the Ryu installation: ryu-manager morpheus/controller.py
The forwarding app delegates telemetry conversion to ``monitoring``; detection
is intentionally kept separate and is not allowed to alter network state.
"""

import json
import logging
import time
from dataclasses import asdict
from datetime import datetime, timezone

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, ipv6, packet
from ryu.lib.packet import tcp, udp, sctp
from ryu.ofproto import ofproto_v1_3

from morpheus.monitoring import observation_from_openflow, observation_to_dict
from morpheus.detection import DetectionConfig, FlowDetector
from morpheus.lab_config import (HOSTS, DETECTION_WINDOW_SECONDS,
                                 MINIMUM_DISTINCT_HOSTS, MINIMUM_DISTINCT_PORTS,
                                 STATS_INTERVAL_SECONDS as FLOW_STATS_INTERVAL_SECONDS,
                                 MAXIMUM_SOURCES,
                                 MAXIMUM_FLOWS_PER_SOURCE)

LOG = logging.getLogger("morpheus.controller")


class MorpheusBaselineController(app_manager.RyuApp):
    """Basic MAC learning and bounded-period flow statistics polling."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    STATS_INTERVAL_SECONDS = FLOW_STATS_INTERVAL_SECONDS

    def __init__(self, *args, **kwargs):
        super(MorpheusBaselineController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self._pending_stats = {}
        self.detector = FlowDetector(DetectionConfig(
            observation_window_seconds=DETECTION_WINDOW_SECONDS,
            minimum_distinct_hosts=MINIMUM_DISTINCT_HOSTS,
            minimum_distinct_ports=MINIMUM_DISTINCT_PORTS,
            designated_hosts=frozenset(HOSTS.values()),
            maximum_sources=MAXIMUM_SOURCES,
            maximum_flows_per_source=MAXIMUM_FLOWS_PER_SOURCE,
        ))
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self._pending_stats.pop(datapath.id, None)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        LOG.info("Switch %016x connected; OpenFlow 1.3 table-miss installed", datapath.id)

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = {"datapath": datapath, "priority": priority, "match": match,
                  "instructions": instructions}
        if priority > 0:
            kwargs["idle_timeout"] = 60
        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match.get("in_port")
        if in_port is None:
            LOG.warning("Ignoring PacketIn without an ingress port from %016x", datapath.id)
            return
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == 0x88cc:  # ignore non-Ethernet and LLDP
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Install a learned unicast rule. Unknown destinations are flooded and
        # learned when their reply arrives; the table miss handles first packets.
        if out_port != ofproto.OFPP_FLOOD:
            match_fields = {"in_port": in_port, "eth_src": eth.src, "eth_dst": eth.dst}
            ip4 = pkt.get_protocol(ipv4.ipv4)
            ip6 = pkt.get_protocol(ipv6.ipv6)
            if ip4 is not None:
                match_fields.update(ipv4_src=ip4.src, ipv4_dst=ip4.dst, ip_proto=ip4.proto)
            elif ip6 is not None:
                match_fields.update(ipv6_src=ip6.src, ipv6_dst=ip6.dst, ip_proto=ip6.nxt)
            transport = pkt.get_protocol(tcp.tcp)
            if transport is not None:
                match_fields.update(tcp_src=transport.src_port, tcp_dst=transport.dst_port)
            else:
                transport = pkt.get_protocol(udp.udp)
                if transport is not None:
                    match_fields.update(udp_src=transport.src_port, udp_dst=transport.dst_port)
                else:
                    transport = pkt.get_protocol(sctp.sctp)
                    if transport is not None:
                        match_fields.update(sctp_src=transport.src_port, sctp_dst=transport.dst_port)
            match = parser.OFPMatch(**match_fields)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            self._add_flow(datapath, 1, match, actions)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self._pending_stats.pop(datapath.id, None)
            self.mac_to_port.pop(datapath.id, None)
            LOG.info("Switch %016x disconnected", datapath.id)

    def _monitor(self):
        """Poll each live datapath without overlapping outstanding requests."""
        interval = self.STATS_INTERVAL_SECONDS
        stale_after = interval * 3
        while True:
            now = time.monotonic()
            for datapath in list(self.datapaths.values()):
                pending = self._pending_stats.get(datapath.id)
                if pending is not None and now - pending[1] < stale_after:
                    continue
                if pending is not None:
                    LOG.warning("Flow-statistics request timed out for %016x xid=%s",
                                datapath.id, pending[0])
                    self._pending_stats.pop(datapath.id, None)
                try:
                    request = datapath.ofproto_parser.OFPFlowStatsRequest(datapath)
                    datapath.send_msg(request)
                    self._pending_stats[datapath.id] = (request.xid, now)
                    LOG.info("FLOW_STATS_REQUEST dpid=%016x xid=%s",
                              datapath.id, request.xid)
                except Exception:
                    LOG.exception("Could not request flow statistics from %016x", datapath.id)
            hub.sleep(interval)

    def close(self):
        """Stop the periodic green thread before Ryu releases this app."""
        monitor_thread = getattr(self, "monitor_thread", None)
        if monitor_thread is not None:
            hub.kill(monitor_thread)
        self._pending_stats.clear()
        super(MorpheusBaselineController, self).close()

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        pending = self._pending_stats.get(datapath.id)
        if pending is None or ev.msg.xid != pending[0]:
            LOG.debug("Ignoring unmatched flow-statistics reply from %016x xid=%s",
                      datapath.id, ev.msg.xid)
            return
        more_replies = bool(ev.msg.flags & datapath.ofproto.OFPMPF_REPLY_MORE)
        if not more_replies:
            self._pending_stats.pop(datapath.id, None)

        body = ev.msg.body or []
        LOG.info("FLOW_STATS_REPLY dpid=%016x xid=%s entries=%d more=%s",
                  datapath.id, ev.msg.xid, len(body), more_replies)
        observed_at = datetime.now(timezone.utc).isoformat()
        for stat in body:
            try:
                observation = observation_from_openflow(
                    stat, observed_at, datapath_id=datapath.id)
                LOG.info("FLOW_OBSERVATION %s", json.dumps(observation_to_dict(observation),
                                                            sort_keys=True))
                event = self.detector.observe(observation, time.monotonic())
                if event is not None:
                    LOG.warning("DETECTION_EVENT %s", json.dumps(asdict(event), sort_keys=True))
            except Exception:
                LOG.warning("Skipping malformed flow-statistics entry from %016x",
                            datapath.id, exc_info=True)
