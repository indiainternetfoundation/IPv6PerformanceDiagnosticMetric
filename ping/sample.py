from scapy.all import IPv6, ICMPv6EchoRequest, IPv6ExtHdrDestOpt, HBHOptUnknown, sr1
from pdm_exthdr import *
from struct import unpack
from socket import ntohs
import time

if __name__ == "__main__":
    _psntp = 13

    _ip = IPv6()
    _ip.dst = "::1"

    packet_1 = _ip
    packet_2 = _ip / UDP()

    hex_dump(packet_1.build())
    print()
    hex_dump(packet_2.build())
    print()
    print("P1 = ", IPv6(packet_1.build()).nh)
    print("P2 = ", IPv6(packet_2.build()).nh)