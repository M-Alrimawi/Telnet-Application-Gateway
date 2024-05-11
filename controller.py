import logging
import secrets
from typing import List
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
# from ryu.lib.packet import packet
# from ryu.lib.packet.ethernet import ethernet
# from ryu.lib.packet.tcp import tcp
from ryu.lib.dpid import dpid_to_str


class TCPSession():
    def __init__(self, server_ip, client_ip, client_port, fin_count=None):
        self.server_ip = server_ip
        self.client_ip = client_ip
        self.client_port = client_port
        self.fin_count = fin_count

    def __eq__(self, other):
        if isinstance(other, TCPSession):
            return (self.server_ip == other.server_ip and
                    self.client_ip == other.client_ip and
                    self.client_port == other.client_port)
        return False


class Controller(RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger(__name__)
        self.mac_port_map = {}
        self.whitelist: List[str] = ['Admin', 'User', "user1"]
        self.prompted_users: List[TCPSession] = []
        self.allowed_users: List[TCPSession] = []

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        '''
         This event is triggered when the switch (datapath) sends its features to the controller during the handshake process.
         Sets up the default to forward all packets to controller
        '''
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Forward all packets to controller with prio 0 (default)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.__add_flow(datapath, 0, match, actions, idle=0)
        # Forward all Telnet packets to controller with prio 2
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=23)  # TCP, TELNET
        self.__add_flow(datapath, 2, match, actions, idle=0)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_src=23)  # TCP, TELNET
        self.__add_flow(datapath, 2, match, actions, idle=0)
        self.logger.debug("🤝\thandshake taken place with datapath: {}".format(dpid_to_str(datapath.id)))

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        '''
        OpenFlow Error Handler
        '''
        error = ev.msg.datapath.ofproto.ofp_error_to_jsondict(ev.msg.type, ev.msg.code)
        self.logger.error("🆘\topenflow error received:\n\t\ttype={}\n\t\tcode={}".format(error.get("type"), error.get("code")))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        Packet In Event Handler
        '''
        datapath = ev.msg.datapath
        buffer_id = ev.msg.buffer_id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(ev.msg.data)
        in_port = ev.msg.match['in_port']
        data = ""

        # if packet is telnet client or server
        if pkt.get_protocol(tcp.tcp) and (pkt.get_protocol(tcp.tcp).dst_port == 23 or pkt.get_protocol(tcp.tcp).src_port == 23):
            eth_header = pkt.get_protocol(ethernet.ethernet)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            src_mac = eth_header.src
            dst_mac = eth_header.dst
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port


            # if FIN flag
            if (tcp_pkt.bits & tcp.TCP_FIN):
                # If packet is from a Server
                if tcp_pkt.src_port == 23:
                    session = TCPSession(server_ip=src_ip, client_ip=dst_ip, client_port=dst_port)
                # If packet is from a Client
                else:
                    session = TCPSession(server_ip=dst_ip, client_ip=src_ip, client_port=src_port)
                if session in self.allowed_users:
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=6,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                        tcp_src=src_port,
                        tcp_dst=dst_port
                    )
                    self.__delete_flow(datapath=datapath, match=match)
                    i = self.allowed_users.index(session)
                    actual_session = self.allowed_users[i]
                    actual_session.fin_count += 1
                    if actual_session.fin_count == 2:
                        self.allowed_users.remove(actual_session)
                    else:
                        self.allowed_users[i] = actual_session
                else:
                    self.logger.critical("❗️\ttelnet packet with FIN but no permissions")
                self.__route_packet(datapath=datapath, buffer_id=buffer_id, in_port=in_port, data=ev.msg.data, dst_mac=dst_mac)

            # if packet is from telnet server
            elif src_port == 23:
                # if packet has payload
                payload = pkt.protocols[-1]
                if payload != tcp_pkt:
                    data = payload.decode('utf-8', errors='ignore').strip()
                    # if server is requesting username => add to prompted_users
                    if data == 'Username:':
                        session = TCPSession(
                            server_ip=src_ip,
                            client_ip=dst_ip,
                            client_port=dst_port
                        )
                        self.prompted_users.append(session)
                self.__route_packet(datapath=datapath, buffer_id=buffer_id, in_port=in_port, data=ev.msg.data, dst_mac=dst_mac)

            # if packet is from telnet client
            elif dst_port == 23:
                session = TCPSession(server_ip=dst_ip, client_ip=src_ip, client_port=src_port, fin_count=0)
                # if telnet server has requested the client's username + a payload is being sent
                payload = pkt.protocols[-1]
                if (session in self.prompted_users) and (payload != tcp_pkt):
                    username = payload.decode('utf-8', errors='ignore').strip()
                    if username in self.whitelist:
                        self.prompted_users.remove(session)
                        self.allowed_users.append(session)

                        # FIN or (FIN,ACK) rule from client -> server = forward to controller
                        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                        match = parser.OFPMatch(
                            eth_type=0x0800,
                            ip_proto=6,
                            ipv4_src=src_ip,
                            ipv4_dst=dst_ip,
                            tcp_src=src_port,
                            tcp_dst=dst_port,
                            tcp_flags=tcp.TCP_FIN
                        )
                        self.__add_flow(datapath, 4, match, action)
                        self.logger.info("🔒\t FIN Rule 1")
                        match = parser.OFPMatch(
                            eth_type=0x0800,
                            ip_proto=6,
                            ipv4_src=src_ip,
                            ipv4_dst=dst_ip,
                            tcp_src=src_port,
                            tcp_dst=dst_port,
                            tcp_flags=(tcp.TCP_FIN | tcp.TCP_ACK)
                        )
                        self.__add_flow(datapath, 4, match, action)
                        self.logger.info("🔒\t FIN Rule 2")
                        # FIN or(FIN,ACK) rule from server -> client = forward to controller
                        match = parser.OFPMatch(
                            eth_type=0x0800,
                            ip_proto=6,
                            ipv4_src=dst_ip,
                            ipv4_dst=src_ip,
                            tcp_src=dst_port,
                            tcp_dst=src_port,
                            tcp_flags=tcp.TCP_FIN
                        )
                        self.__add_flow(datapath, 4, match, action)
                        self.logger.info("🔒\t FIN Rule 3")
                        match = parser.OFPMatch(
                            eth_type=0x0800,
                            ip_proto=6,
                            ipv4_src=dst_ip,
                            ipv4_dst=src_ip,
                            tcp_src=dst_port,
                            tcp_dst=src_port,
                            tcp_flags=(tcp.TCP_FIN | tcp.TCP_ACK)
                        )
                        self.__add_flow(datapath, 4, match, action)
                        self.logger.info("🔒\t FIN Rule 4")

                        # if port to reach dst is known => forward packet + create rules
                        out_port = self.__get_port(datapath=datapath, mac=dst_mac)
                        if out_port:

                            # forward rule from client -> server
                            action = [parser.OFPActionOutput(out_port)]
                            match = parser.OFPMatch(
                                eth_type=0x0800,
                                ip_proto=6,
                                ipv4_src=src_ip,
                                ipv4_dst=dst_ip,
                                tcp_src=src_port,
                                tcp_dst=dst_port
                            )
                            self.__add_flow(datapath, 3, match, action)
                            self.logger.info("🔒\t Forward Rule c->s")
                            # forward rule from server -> client
                            action = [parser.OFPActionOutput(in_port)]
                            match = parser.OFPMatch(
                                eth_type=0x0800,
                                ip_proto=6,
                                ipv4_src=dst_ip,
                                ipv4_dst=src_ip,
                                tcp_src=dst_port,
                                tcp_dst=src_port
                            )
                            self.__add_flow(datapath, 3, match, action)
                            self.logger.info("🔒\t Forward Rule s->c")

                            self.__forward_packet(datapath=datapath, buffer_id=buffer_id, in_port=in_port, data=ev.msg.data, out_port=out_port)

                        # port to reach dst is not known => flood packet to all ports
                        else:
                            # forward rule from client -> server
                            actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
                            match = parser.OFPMatch(
                                eth_type=0x0800,
                                ip_proto=6,
                                ipv4_src=src_ip,
                                ipv4_dst=dst_ip,
                                tcp_src=src_port,
                                tcp_dst=dst_port
                            )
                            self.__add_flow(datapath, 3, match, action)
                            self.logger.info("🔒\t Forward Rule c->s")
                            # forward rule from server -> client
                            action = [parser.OFPActionOutput(in_port)]
                            match = parser.OFPMatch(
                                eth_type=0x0800,
                                ip_proto=6,
                                ipv4_src=dst_ip,
                                ipv4_dst=src_ip,
                                tcp_src=dst_port,
                                tcp_dst=src_port
                            )
                            self.__add_flow(datapath, 3, match, action)
                            self.logger.info("🔒\t Forward Rule s->c")

                            self.__flood_packet(datapath=datapath, buffer_id=buffer_id, in_port=in_port, data=ev.msg.data)
                            self.logger.info("\ttelnet client is giving username without knowing how to reach server")

                    # if the username is not whitelisted => do NOT forward
                    else:
                        ip_pkt.total_length = 0
                        tcp_pkt.offset, tcp_pkt.csum = 0, 0
                        server_reset_pkt = packet.Packet()
                        server_reset_pkt.add_protocol(eth_header)
                        server_reset_pkt.add_protocol(ip_pkt)
                        server_reset_pkt.add_protocol(tcp_pkt)
                        nonce = secrets.token_urlsafe(len(username)-2)
                        data = f"{nonce}\r\n".encode('utf-8', errors='ignore')
                        server_reset_pkt.protocols.append(data)
                        server_reset_pkt.serialize()
                        self.__route_packet(
                            datapath=datapath,
                            buffer_id=buffer_id,
                            in_port=ofproto.OFPP_CONTROLLER,
                            data=server_reset_pkt,
                            dst_mac=dst_mac
                        )
                        # self.logger.info("❗️\tReset packet sent to {} from {}".format(dst_ip, dpid_to_str(datapath.id)))
                        # eth_header.src, eth_header.dst = dst_mac, src_mac
                        # ip_pkt.src, ip_pkt.dst = dst_ip, src_ip
                        # tcp_pkt.src_port, tcp_pkt.dst_port = dst_port, src_port
                        # client_reset_pkt = packet.Packet()
                        # client_reset_pkt.add_protocol(eth_header)
                        # client_reset_pkt.add_protocol(ip_pkt)
                        # client_reset_pkt.add_protocol(tcp_pkt)
                        # client_reset_pkt.serialize()
                        # self.__route_packet(
                        #     datapath=datapath,
                        #     buffer_id=buffer_id,
                        #     in_port=ofproto.OFPP_CONTROLLER,
                        #     data=client_reset_pkt,
                        #     dst_mac=eth_header.dst
                        # )
                        self.logger.info("❗️\tTCP packet with payload {} sent to {}".format(nonce, ip_pkt.dst))
                        self.prompted_users.remove(session)
                        self.logger.info("❗️\tuser:{} tried to access server {} without permissions".format(username, dst_ip))
                        return
                self.__route_packet(
                    datapath=datapath,
                    buffer_id=buffer_id,
                    in_port=in_port,
                    data=ev.msg.data,
                    dst_mac=dst_mac
                )
            if data == "":
                data = hex(tcp_pkt.bits)
            log_message = f"\t{src_ip} => {dst_ip} : {data}"
            self.logger.info(log_message)

        # Ethernet packet handler
        elif pkt.get_protocol(ethernet.ethernet):
            eth_header = pkt.get_protocol(ethernet.ethernet)
            src_mac = eth_header.src
            dst_mac = eth_header.dst
            data = ev.msg.data

            # if src port to mac map is not known then update mapping
            if self.__get_port(datapath=datapath, mac=src_mac) is None:
                self.__add_port(
                    datapath=datapath,
                    mac=src_mac,
                    out_port=in_port
                )

            # if port to reach dst is known => add rule + forward packet
            if self.__get_port(datapath=datapath, mac=dst_mac):
                port = self.__get_port(datapath=datapath, mac=dst_mac)
                actions = [parser.OFPActionOutput(port)]
                match = parser.OFPMatch(eth_dst=eth_header.dst)
                self.__add_flow(datapath, 1, match, actions)
                self.__forward_packet(
                    datapath=datapath,
                    buffer_id=buffer_id,
                    in_port=in_port,
                    data=data,
                    out_port=port
                )

            # if port to reach dst is not known => then flood
            else:
                self.__flood_packet(datapath=datapath, buffer_id=buffer_id, in_port=in_port, data=data)

        # Illegal packet format
        else:
            self.logger.warning("❗️\tpacket has no Ethernet header nor is it TCP\t❗️:\n {}".format(data))

        return

    def __route_packet(self, datapath, buffer_id, in_port, data, dst_mac):
        out_port = self.__get_port(datapath=datapath, mac=dst_mac)
        if out_port:
            self.__forward_packet(datapath=datapath, buffer_id=buffer_id, in_port=in_port, data=data, out_port=out_port)
        else:
            self.__flood_packet(datapath=datapath, buffer_id=buffer_id, in_port=in_port, data=data)

    def __forward_packet(self, datapath, buffer_id, in_port, data, out_port):
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        pkt_out_msg = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id, in_port=in_port, actions=actions, data=data)
        return datapath.send_msg(pkt_out_msg)

    def __flood_packet(self, datapath, buffer_id, in_port, data):
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
        pkt_out_msg = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id, in_port=in_port, actions=actions, data=data)
        return datapath.send_msg(pkt_out_msg)

    def __get_port(self, datapath, mac):
        entry = self.mac_port_map.get(dpid_to_str(datapath.id))
        if entry:
            port = entry.get(mac)
            return port
        return None

    def __add_port(self, datapath, mac, out_port):
        path_id = dpid_to_str(datapath.id)
        mac_to_port = self.mac_port_map.get(path_id, {})
        mac_to_port[mac] = out_port
        self.mac_port_map[path_id] = mac_to_port
        return

    def __delete_flow(self, datapath, match):
        '''
        Remove Flow Table Modification
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        flow_mod = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match
                )
        self.logger.info("🗑️\tflow-Mod removed")
        datapath.send_msg(flow_mod)

    def __add_flow(self, datapath, priority, match, actions, idle=60, hard=0):
        '''
        Install Flow Table Modification
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard
        )
        self.logger.info("✍️\tflow-Mod written")
        datapath.send_msg(mod)
