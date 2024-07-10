# Processing time too much!!!


from scapy.all import UDP
from pdm_exthdr import *
from packet_utils import *
from struct import unpack
from socket import ntohs
from pprint import pprint
import time, threading

def _astons(delta, scale):
    ns_time = delta
    ns_time = int(ns_time) << (scale - 8)

    ns_time *= 16*16
    ns_time /= 10000
    ns_time /= 100000
    return int(ns_time)

def threaded(func):
    def wrapped_func(*args, **kwargs):
        threaded_func = threading.Thread(target=func, args=args, kwargs=kwargs)
        return threaded_func.start()
    return wrapped_func

class NetworkAdaptar:
    ETH_P_ALL = 3
    def __init__(self, iface = "lo", mtu = 1024):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((iface, 0))
        self.listening = False
        self.mtu = mtu

    def __call__(self, ):
        pass

    @threaded
    def listen(self, callback, filter = lambda x:x):
        self.listening = True
        try:
            while self.listening:
                data = self.sock.recv(self.mtu) # buffer size is 1024 bytes
                _packet = Ether(data)
                if filter(_packet):
                    callback(_packet)
        except KeyboardInterrupt:
            self.listening = False
            sys.exit(0)

class PDMHandler:
    def __init__(self, _psntp = 13):
        self._psntp = _psntp
        self.tx = []
        self.rx = []
        self.dns_query = {}
        self._has_setup_ = False

    def __setup__(self):
        if not self._has_setup_:
            print("[i] Sending DNS Query Packet along with PDM Header.")
            packet = packet_A(self._psntp)
            # hex_dump(packet.build())
            self.send(packet)
            self._has_setup_ = True

    def __call__(self, ethernet_frame):
        print(f"[i] {'[ TX ]' if ethernet_frame in self.tx else '[ RX ]'} {ethernet_frame.summary()}")
        if ethernet_frame not in self.tx:
            ipv6 = ethernet_frame[IPv6]
            if DNS in ipv6:
                if DNSRR in ipv6:
                    if ipv6[DNS].id in self.dns_query:
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
        self.tx.append(Ether((Ether() / ipv6).build()))
        sr1(ipv6, timeout = 2, verbose=False, iface = "lo")

    def tx_callback(self, ipv6: IPv6):
        if DNS in ipv6:
            self.dns_query[ipv6[DNS].id] = { "query": ipv6[DNS], "response": None, "tx_time": time.time_ns(), "rx_time": None }

    def rx_callback(self, ipv6: IPv6):
        self.rx.append(Ether((Ether() / ipv6).build()))

        while next_packet := analyze_and_create_next_packet(self.dns_query[ipv6[DNS].id], ipv6):
            self.send(next_packet)
            pass




def analyze_and_create_next_packet(q_details: dict, ipv6: IPv6):
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
                    total_rtt = q_details['rx_time'] - q_details['tx_time']
                    print("[i] Delta Time Last Received : ", hex(server_latency))
                    print("[ ]                            ", server_latency, "ns")
                    print("[ ]                            ", server_latency/1000000000, "s")
                    print("[i] RX : ", q_details['rx_time'], "ns")
                    print("[i] TX : ", q_details['tx_time'], "ns")
                    print("[i] Round Trip Time  : ", total_rtt, "ns")
                    print("[i] Round Trip Delay : ", total_rtt - server_latency, "ns")
                    print("[ ]                    ", (total_rtt - server_latency)/1000000000, "s")
                    pass
            exit(0)
        pass
    pass


pdm_handler = PDMHandler()

lo = NetworkAdaptar("lo")
lo.listen(
    callback = pdm_handler,
    filter = lambda x: IPv6 in x
)
print("[ ] Listening...")
pdm_handler.__setup__()


