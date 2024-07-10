from scapy.all import IPv6, ICMPv6EchoRequest, IPv6ExtHdrDestOpt, HBHOptUnknown, sr1, Jumbo
from pdm_exthdr import *
from struct import unpack
from socket import ntohs
import time



if __name__ == "__main__":
    _psntp = 13

    _ip = IPv6()
    _ip.dst = "::1"
    # _ip.dst = "2001:4860:4860::8888"



    _ipv6_pdm = IPv6ExtHdrPerformanceDiagnosticMetrics(
        # scaledtlr = 0,      # Byte  : Scale of Delta Time Last Received
        # scaledtls = 0,      # Byte  : Delta Time Last Sent
        # psntp = _psntp,     # Int   : Packet Sequence Number This Packet
        # psnlr = 0,          # Int   : Packet Sequence Number Last Received
        # deltatlr = 0,       # Short : Delta Time Last Received
        # deltatls = 0,       # Short : Delta Time Last Sent


        scaledtlr = 0,      # Byte  : Scale of Delta Time Last Received
        scaledtls = 0,      # Byte  : Delta Time Last Sent
        psntp = 7,     # Int   : Packet Sequence Number This Packet
        psnlr = 0,          # Int   : Packet Sequence Number Last Received
        deltatlr = 0,       # Short : Delta Time Last Received
        deltatls = 0,       # Short : Delta Time Last Sent
    )

    _ipv6_hbh_jumbo = IPv6ExtHdrHopByHop(options=Jumbo(jumboplen=2**30))

    # _ipv6_pdm_destination_option = IPv6ExtHdrDestOpt(options = HBHOptUnknown( otype=0x0F, optlen=10,  optdata=_ipv6_pdm.build() ))
    _ipv6_pdm_destination_option = IPv6ExtHdrDestOpt(options = Destination_Options_PerformanceDiagnosticMetrics( otype=0x0F, optdata=_ipv6_pdm.build() ))


    # (otype, olen, scaledtlr, scaledtls, psntp, psnlr, deltatlr, deltatls) = unpack('>bbIIHHxx', _ipv6_pdm.build() + b"\x00\x00")
    # assert (otype, olen, scaledtlr, scaledtls, psntp, psnlr, deltatlr, deltatls) == (15, 24, 0, 0, 13, 0, 0, 0)

    # dnsq = IPv6(dst='::1') / UDP() / DNS(rd=1, qd=DNSQR(qname='example.com', qtype="A"))
    # print(sr1(dnsq, timeout = 2, verbose = False, iface = "lo"))
    _dnsq = DNS(rd=1, qd=DNSQR(qname='example.com', qtype="A"))

    response = True

    # hex_dump(_ipv6_pdm_destination_option.build())

    # packet = _ip  / IPv6ExtHdrDestOpt() / UDP() / _dnsq
    # packet = packet.build()
    # hex_dump(packet)

    # packet = _ip  / IPv6ExtHdrDestOpt(options = Destination_Options_PerformanceDiagnosticMetrics( otype=0xAB, optdata=b"\xab\xcd" )) / UDP() / _dnsq
    # packet = packet.build()
    # hex_dump(packet)

    # packet = _ip  / IPv6ExtHdrDestOpt(options = Destination_Options_PerformanceDiagnosticMetrics( otype=0xAB, optdata=b"\xab\xcd" )) / IPv6ExtHdrDestOpt(options = Destination_Options_PerformanceDiagnosticMetrics( otype=0x0F, optlen=0x10,  optdata=_ipv6_pdm.build() )) / UDP() / _dnsq
    # packet = packet.build()
    # hex_dump(packet)

    # hex_dump(Destination_Options_PerformanceDiagnosticMetrics( otype=0x0F, optlen=12,  optdata=_ipv6_pdm.build() ).build())
    # hex_dump(IPv6ExtHdrDestOpt().build())
    # hex_dump(_ipv6_pdm_destination_option.build())

    packet = _ip / _ipv6_pdm_destination_option / UDP() / _dnsq
    # packet = _ip / UDP() / _dnsq
    pkt_build_data = packet.build()
    # pkt_build_data = b"`\x00\x00\x00\x00=<@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x11\x02\x0f\x0e\x05\x06\x00\x00\x00\x07\x00\x00\x00\x08\x00\t\x00\n\x01\x02\x00\x00\x005\x005\x00%/\xcb\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01" # packet.build()
    # print(pkt_build_data)
    hex_dump(pkt_build_data)

    try:
        # _ipv6_pdm_destination_option
        # while response := sr1(_ip  / _ipv6_hbh_jumbo / IPv6ExtHdrDestOpt(options = HBHOptUnknown( otype=0x0F, optdata=_ipv6_pdm.build() + b"\x00\x00\x00\x00" )) / _echo, timeout = 2, verbose=False):
        # while response := sr1(_ip  / _ipv6_pdm_destination_option / UDP() / _dnsq, timeout = 2, verbose=False, iface = "lo"):
        # while response := sr1(_ip / IPv6ExtHdrHopByHop(options=Jumbo(jumboplen=2**30)) / UDP() / _dnsq, timeout = 2, verbose=False, iface = "lo"):
        while response := sr1(packet, timeout = 2, verbose=False, iface = "lo"):
        # while response := sr1(_ip / UDP() / _dnsq, timeout = 2, verbose=False, iface = "lo"):
            print(f"DNS {_ip.dst} ({_ip.dst}) 56 data bytes...")
            # # print("_ipv6_pdm_build is : ", " ".join([hex(b) for b in _ipv6_pdm.build()]))
            # print("_ipv6_pdm_destination_option is : ", " ".join([hex(b) for b in _ipv6_pdm_destination_option.build()]))
            if DNS in response and response[DNS].an:
                print("\tDNS Reply: ", response.summary())
            time.sleep(1)
    except KeyboardInterrupt:
        exit(0)
