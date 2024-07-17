from scapy.all import IPv6, ICMPv6EchoRequest, IPv6ExtHdrDestOpt, HBHOptUnknown, sr1, Jumbo, UDP
from pdm_exthdr import *

# DST = "::1"
# SRC  =  "2406:da1a:8e8:e8f4:9959:7a8b:38d6:c1dc"
# DST = "2406:da1a:8e8:e805:6d97:b1b6:6232:ff90"
DST = "fe80::f8:39ff:fed4:34cf%enX0"

def countBits(n):
    count = 0;
    while(n):
        count+=1;
        n = int(n) >> 1;
    return count;

def _nstoas(delta_ns):
    atto_now = delta_ns
    atto_now = (atto_now * 1000000000) / (16*16)
    scale = 8
    while(countBits(atto_now) > 16):
        atto_now = int(atto_now) >> 1
        scale += 1
    return atto_now, scale

def packet_A(_psntp):
    _ip = IPv6()
    _ip.dst = DST

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

def packet_C(packet_B, delta_ns):
    _pdm = IPv6ExtHdrPerformanceDiagnosticMetrics( packet_B.options[0].optdata )
    delta, scale = _nstoas(delta_ns)
    _ip = IPv6()
    _ip.dst = DST

    _ipv6_pdm_destination_option = IPv6ExtHdrDestOpt(
        options = Destination_Options_PerformanceDiagnosticMetrics(
            otype=0x0F, optdata = IPv6ExtHdrPerformanceDiagnosticMetrics(
                scaledtlr = 0,      # Byte  : Scale of Delta Time Last Received
                scaledtls = scale,  # Byte  : Delta Time Last Sent
                psntp = _pdm.psntp + 1, # Short : Packet Sequence Number This Packet
                psnlr = _pdm.psntp, # Short : Packet Sequence Number Last Received
                deltatlr = 0,       # Short : Delta Time Last Received
                deltatls = socket.htons(delta),   # Short : Delta Time Last Sent
            )
        )
    )
    print(_ipv6_pdm_destination_option.options[0].optdata.__repr__())

    _dnsq = DNS(id=121, rd=1, qd=DNSQR(qname='example.com', qtype="A"))

    # return _ip / _ipv6_pdm_destination_option / UDP() / _dnsq
    return _ip / _ipv6_pdm_destination_option

def packet_D(packet_C):
    pass