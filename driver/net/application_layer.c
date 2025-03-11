#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "struct.c"
#include "dump.h"
#include "application_layer.h"

#define DSTOPT_WIDTH 4;

static uint8_t protocol_identifier(struct protoid *protocol_id, struct sk_buff *skb, uint8_t debug) {
    uint32_t iphdr_offset = 0;
    uint32_t iphdr_flags = 0;
    uint16_t iphdr_fragoffset = 0;

    // Check Protocol Type
    uint16_t proto_type = ipv6_find_hdr(skb, &iphdr_offset, -1, &iphdr_fragoffset, &iphdr_flags);

    switch(proto_type){
        case IPPROTO_UDP:
            struct udphdr *udp;
            protocol_id->proto = skb_header_pointer(skb, iphdr_offset, sizeof(udp), NULL);
            udp = (struct udphdr *)protocol_id->proto;
            if(debug)
                __dump_udphdr(udp);
            if (htons(udp->source) == 53 || htons(udp->dest) == 53){
                // DNS Packet
                protocol_id->proto = protocol_id->proto + sizeof(struct udphdr);
                protocol_id->proto_type = IPPROTO_DNS;

                return 1;
            }
            return 0;
            break;
        case IPPROTO_TCP:
            break;
        default:
            return 0;
            break;
    }
    return 0;
}
static int8_t populate_protocol_id(struct protoid *protocol_id, uint8_t debug ){
    switch (protocol_id->proto_type){
        case IPPROTO_DNS:
            populate_with_dns_data(protocol_id, (struct dns_struct *)protocol_id->proto);
            return 1;
        // case IPPROTO_TCPSYN:
        // case IPPROTO_TCPACK:
        // case IPPROTO_TCPSYNACK:
        default:
            return 0;
    }
    return 0;
}
static void populate_with_dns_data(struct protoid *protocol_id, struct dns_struct *dns_header){
    protocol_id->proto_id_name = "id";
    protocol_id->proto_id_value = htons(dns_header->id);
}
