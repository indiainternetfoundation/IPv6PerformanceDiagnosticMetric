from scapy.all import *
from scapy.layers import inet6
from scapy.layers.inet6 import IPv6, _IPv6ExtHdr, IPv6ExtHdrDestOpt, _OTypeField

ipv6nh = {0: "Hop-by-Hop Option Header",
          4: "IP",
          6: "TCP",
          17: "UDP",
          41: "IPv6",
          43: "Routing Header",
          44: "Fragment Header",
          47: "GRE",
          50: "ESP Header",
          51: "AH Header",
          58: "ICMPv6",
          59: "No Next Header",
          60: "Destination Option Header",
          112: "VRRP",
          132: "SCTP",
          135: "Mobility Header"}

inet6._hbhopts = {0x00: "Pad1",
            0x01: "PadN",
            0x04: "Tunnel Encapsulation Limit",
            0x05: "Router Alert",
            0x06: "Quick-Start",
            0x0f: "Performance Diagnostic Metrics",
            0xc2: "Jumbo Payload",
            0xc9: "Home Address Option"
        }



class Destination_Options_PerformanceDiagnosticMetrics(Packet):  # IPv6 Destination Options Header Option
    name = "Performance Diagnostic Metrics"
    fields_desc = [_OTypeField("otype", 0x0F, inet6._hbhopts),
                   FieldLenField("optlen", None, length_of="optdata", fmt="B"),
                   StrLenField("optdata", "", length_from=lambda pkt: pkt.optlen)]

    def alignment_delta(self, curpos):  # alignment requirement : 16n+0
        # x = 16
        # y = 0
        # delta = x * ((curpos - y + x - 1) // x) + y - curpos
        # return delta
        return 0

    def extract_padding(self, p):
        return b"", p

class IPv6ExtHdrPerformanceDiagnosticMetrics(Packet):
    name = "IPv6 Performance and Diagnostic Metrics (PDM) Destination Option"
    # RFC rfc8250
    # Linux Kernel :: Destination options header :: https://github.com/torvalds/linux/blob/32f88d65f01bf6f45476d7edbe675e44fb9e1d58/net/ipv6/exthdrs.c#L231
    '''
    PSNTP    : Packet Sequence Number This Packet       : 25
    PSNLR    : Packet Sequence Number Last Received     : -
    DELTATLR : Delta Time Last Received                 : -
    SCALEDTLR: Scale of Delta Time Last Received      : 0
    DELTATLS : Delta Time Last Sent                     : -
    SCALEDTLS: Scale of Delta Time Last Sent          : 0
    '''

    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Option Type  | Option Length |   ScaleDTLR   |   ScaleDTLS   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        PSN This Packet        |       PSN Last Received       |
    |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Delta Time Last Received   |      Delta Time Last Sent     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''

    '''
    IPv6ExtHdrDestOpt(options = IPv6ExtHdrPerformanceDiagnosticMetrics())
    '''
    fields_desc = [
        # _OTypeField("otype", 0x0F, inet6._hbhopts),
        # ByteField("optlen", 14),    # 8 Bit = 1 Byte

        # PDM Fields
        ByteField("scaledtlr", 0),  # 8 Bit = 1 Byte
        ByteField("scaledtls", 0),  # 8 Bit = 1 Byte

        # IntField("psntp", 0),       # 32 Bit = 4 Bytes
        # IntField("psnlr", 0),       # 32 Bit = 4 Bytes
        ShortField("psntp", 0),       # 32 Bit = 4 Bytes  -,  Wireshark
        ShortField("psnlr", 0),       # 32 Bit = 4 Bytes  -'  Docs Says This

        ShortField("deltatlr", 0),  # 16 Bit = 2 Bytes
        ShortField("deltatls", 0),  # 16 Bit = 2 Bytes
    ]


    def alignment_delta(self, curpos):
        # # alignment requirement : 3n+8
        # x = 3
        # y = 8
        # delta = x * ((curpos - y + x - 1) // x) + y - curpos
        # return delta

        # # alignment requirement : 2n+0
        # x = 2
        # y = 0
        # delta = x * ((curpos - y + x - 1) // x) + y - curpos
        # return delta

        # # alignment requirement : 4n+2
        # x = 4
        # y = 2
        # delta = x * ((curpos - y + x - 1) // x) + y - curpos
        # return delta

        # # alignment requirement : 8n+6
        # x = 8
        # y = 6
        # delta = x * ((curpos - y + x - 1) // x) + y - curpos
        # return delta

        return 0


    def extract_padding(self, p):
        return b"", p

def pdm_tuple(_ipv6_pdm: IPv6ExtHdrPerformanceDiagnosticMetrics):
    return (_ipv6_pdm.psntp, _ipv6_pdm.psnlr, _ipv6_pdm.deltatlr, _ipv6_pdm.scaledtlr, _ipv6_pdm.deltatls, _ipv6_pdm.scaledtls)

def hex_dump(packet):
    i = 0
    for b in packet:
        if i%16 == 0 and i > 0:
            print()
        if i%16 == 0:
            print(hex(i)[2:].rjust(8, '0'), "\t", end = "")
        print(f"{format(b, '#04x')[2:]} ", end="")
        i+=1
    print()