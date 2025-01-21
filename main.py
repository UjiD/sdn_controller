from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

class SimpleSDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSDNController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # Stores MAC-to-port mappings
        self.packet_count = {}  # {host_ip: packet_count}
        self.port_count = {}    # {port_no: packet_count}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handles initial connection with a switch."""
        datapath = ev.msg.datapath
        self._install_table_miss_flow(datapath)

    def _install_table_miss_flow(self, datapath):
        """Install a table-miss flow entry to handle unmatched packets."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Match all packets
        match = parser.OFPMatch()
        # Send unmatched packets to the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        # Create a flow mod message
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_mod = parser.OFPFlowMod(
            datapath=datapath, priority=0, match=match, instructions=inst
        )
        # Send the flow mod message to the switch
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handles packets that are sent to the controller."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth is None:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # Update MAC to port mapping
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Traffic Monitoring: Count packets per host and per port
        if ip_pkt:
            src_ip = ip_pkt.src
            self.packet_count[src_ip] = self.packet_count.get(src_ip, 0) + 1
        self.port_count[in_port] = self.port_count.get(in_port, 0) + 1

        # Handle traffic within the same subnet
        if ip_pkt and self._same_subnet(ip_pkt.src, ip_pkt.dst, "10.0.0.0/24"):
            if dst_mac in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst_mac]
                actions = [parser.OFPActionOutput(out_port)]
            else:
                # If the destination MAC is unknown, flood the packet
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        else:
            # Drop packets for different subnets
            self.logger.info("Dropping packet from %s to %s (different subnets)", ip_pkt.src, ip_pkt.dst)
            return

        # Send packet out
        data = None if msg.buffer_id == ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

    def _same_subnet(self, ip1, ip2, subnet):
        """Check if two IP addresses are in the same subnet."""
        import ipaddress
        net = ipaddress.ip_network(subnet, strict=False)
        return ipaddress.ip_address(ip1) in net and ipaddress.ip_address(ip2) in net
