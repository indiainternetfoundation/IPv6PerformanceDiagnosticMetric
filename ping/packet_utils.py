from scapy.all import IPv6, ICMPv6EchoRequest, IPv6ExtHdrDestOpt, HBHOptUnknown, sr1, Jumbo, UDP
from pdm_exthdr import *

def packet_A(_psntp):
    _ip = IPv6()
    _ip.dst = "::1"

    _ipv6_pdm_destination_option = IPv6ExtHdrDestOpt(
        options = Destination_Options_PerformanceDiagnosticMetrics(
            otype=0x0F, optdata = IPv6ExtHdrPerformanceDiagnosticMetrics(
                scaledtlr = 0,      # Byte  : Scale of Delta Time Last Received
                scaledtls = 0,      # Byte  : Delta Time Last Sent
                psntp = _psntp,     # Short : Packet Sequence Number This Packet
                psnlr = 0,          # Short : Packet Sequence Number Last Received
                deltatlr = 0,       # Short : Delta Time Last Received
                deltatls = 0,       # Short : Delta Time Last Sent
            )
        )
    )

    _dnsq = DNS(id=121, rd=1, qd=DNSQR(qname='example.com', qtype="A"))

    return _ip / _ipv6_pdm_destination_option / UDP() / _dnsq

def packet_B(packet_A):
    pass

def packet_C(packet_B):
    pass

def packet_D(packet_C):
    pass