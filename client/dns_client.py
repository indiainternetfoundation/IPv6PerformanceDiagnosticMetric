# Processing time too much!!!

from scapy.all import UDP, IPv6, ICMPv6DestUnreach
from pdm_exthdr import *
from packet_utils import *
from struct import unpack
from socket import ntohs
from pprint import pprint
import time, threading

from NetworkAdaptar import NetworkAdaptar

def _astons(delta, scale):
    ns_time = delta
    ns_time = int(ns_time) << (scale - 8)

    ns_time *= 16*16
    ns_time /= 10000
    ns_time /= 100000
    return int(ns_time)

def send_packet(packet : Ether):
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)


class PDMHandler:
    def __init__(self, net:NetworkAdaptar, _psntp = 13):
        self._psntp = _psntp
        self.tx = []
        self.rx = []
        self.dns_query = {}
        self._has_setup_ = False
        self.adaptar = net
        self.exit_next = False

    def __setup__(self):
        if not self._has_setup_:
            print("[i] Sending DNS Query Packet along with PDM Header.")
            packet = packet_A(self._psntp)
            # hex_dump(packet.build())
            self.send(packet)
            self._has_setup_ = True

    def __call__(self, ethernet_frame):
        print(f"[i] {'[ TX ]' if ethernet_frame in self.tx else '[ RX ]'} {ethernet_frame.summary()}")
        if ICMPv6DestUnreach in ethernet_frame:
            return
        # if DNS in ethernet_frame:
        # else:
            # return
        if ethernet_frame not in self.tx:
            ipv6 = ethernet_frame[IPv6]
            if DNS in ipv6:
                # print(ipv6[DNS].show())
                # print(ipv6[DNS].summary())
                # print(ipv6[DNS].__repr__)
                # print(ipv6[DNS].qd)
                # print(ipv6[DNS].an)

                # txt = None
                # while txt != "exit":
                #     txt = input(">>>")
                #     print(eval(txt))

                if DNSRR in ipv6:
                    # print("Breakpoint D")
                    if ipv6[DNS].id in self.dns_query:
                        # print("Breakpoint F")
                        print(f"[i] Found DNS Response for Query Id {ipv6[DNS].id}, i.e. for domain `{ipv6[DNS].qd.qname}`")
                        self.dns_query[ipv6[DNS].id]["response"] = ipv6[DNS][DNSRR]
                        self.dns_query[ipv6[DNS].id]["rx_time"] = time.time_ns()  # Takes a lot of time
                                                                                  # before recording rx time
                        # pprint(self.dns_query[ipv6[DNS].id])
            self.rx_callback(ethernet_frame[IPv6])
        else:
            self.tx_callback(ethernet_frame[IPv6])
        pass

    def send(self, ipv6: IPv6):
        ethernet_frame = (Ether() / ipv6).build()
        self.tx.append(Ether(ethernet_frame))
        # self.tx.append(ethernet_frame)
        self.tx_callback(Ether(ethernet_frame)[IPv6])
        self.adaptar.send( ethernet_frame )

    def tx_callback(self, ipv6: IPv6):
        if DNS in ipv6 and ipv6[DNS].id not in self.dns_query:
            self.dns_query[ipv6[DNS].id] = { "query": ipv6[DNS], "response": None, "tx_time": time.time_ns(), "rx_time": None }

    def rx_callback(self, ipv6: IPv6):
        ethernet_frame = (Ether() / ipv6).build()
        self.rx.append(Ether(ethernet_frame))
        if DNS not in ipv6:
            return
        if ipv6[DNS].id not in self.dns_query:
            return
        else:
            self.dns_query[ipv6[DNS].id]
        while next_packet := analyze_and_create_next_packet(self, self.dns_query[ipv6[DNS].id], ipv6):
            # print("Sending Packet ...")
            self.send(next_packet)
            if self.exit_next:
                exit(0)




def analyze_and_create_next_packet(pdm_handler:PDMHandler, q_details: dict, ipv6: IPv6):
    rx = time.perf_counter_ns()
    if ipv6:
        if IPv6ExtHdrDestOpt in ipv6:
            exthdr_destop = ipv6[IPv6ExtHdrDestOpt]
            for option in exthdr_destop.options:
                if option.otype == 15:
                    pdm = IPv6ExtHdrPerformanceDiagnosticMetrics(option.optdata)
                    # print(pdm.__repr__())
                    print(f"[i] <IPv6ExtHdrPerformanceDiagnosticMetrics " \
                        f"\n[ ] \tscaledtlr={hex(pdm.scaledtlr)} " \
                        f"\n[ ] \tscaledtls={hex(pdm.scaledtls)} " \
                        f"\n[ ] \tpsntp={hex(pdm.psntp)} " \
                        f"\n[ ] \tpsnlr={hex(pdm.psnlr)} " \
                        f"\n[ ] \tdeltatlr={hex(pdm.deltatlr)} " \
                        f"\n[ ] \tdeltatls={hex(pdm.deltatls)} " \
                    "\n[ ] >")
                    server_latency = _astons(pdm.deltatlr, pdm.scaledtlr)
                    print(f"[i] {q_details['rx_time']=}, {q_details['tx_time']=}")
                    total_rtt = q_details['rx_time'] - q_details['tx_time']
                    print("[i] Delta Time Last Received : ", hex(server_latency))
                    print("[ ]                            ", server_latency, "ns")
                    print("[ ]                            ", server_latency/1000000000, "s")
                    print("[i] RX : ", q_details['rx_time'], "ns")
                    print("[i] TX : ", q_details['tx_time'], "ns")
                    print("[i] Round Trip Time  : ", total_rtt, "ns")
                    print("[ ]                    ", (total_rtt)/1000000000, "s")
                    print("[i] Round Trip Delay : ", total_rtt - server_latency, "ns")
                    print("[ ]                    ", (total_rtt - server_latency)/1000000000, "s")
                    tx = time.perf_counter_ns()
                    pdm_handler.exit_next = True
                    # print(packet_C(ipv6, tx - rx))
                    return packet_C(ipv6, tx - rx)


# lo = NetworkAdaptar("lo")
lo = NetworkAdaptar("enX0")
pdm_handler = PDMHandler(lo)
lo.listen(
    callback = pdm_handler,
    filter = lambda x: IPv6 in x
)
print("[ ] Listening...")
pdm_handler.__setup__()


