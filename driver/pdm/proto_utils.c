#include "structure.h"
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define DSTOPT_WIDTH 4;

static struct protoid {
    uint8_t     proto_type; //
    char*       proto_id_name;
    uint64_t    proto_id_value;
    unsigned char* proto;
};

enum {
    IPPROTO_DNS = 0,
    #define IPPROTO_DNS         IPPROTO_DNS
    IPPROTO_TCPSYN = 2,
    #define IPPROTO_TCPSYN      IPPROTO_TCPSYN
    IPPROTO_TCPACK = 3,
    #define IPPROTO_TCPACK      IPPROTO_TCPACK
    IPPROTO_TCPSYNACK = 4,
    #define IPPROTO_TCPSYNACK   IPPROTO_TCPSYNACK
    // IPPROTO_ICMP = 5,
    // #define IPPROTO_ICMP        IPPROTO_ICMP
};



static uint8_t protocol_identifier(struct protoid *protocol_id, struct ipv6hdr *ip6h);
static uint8_t populate_protocol_type(struct protoid *protocol_id, struct ipv6hdr *ip6h, uint8_t debug);
static int8_t populate_protocol_id(struct protoid *protocol_id );
static void populate_with_dns_data(struct protoid *protocol_id, struct dns_struct *dns_header);

static uint8_t populate_protocol_type(struct protoid *protocol_id, struct ipv6hdr *ip6h, uint8_t debug){
    unsigned char *hdr_ptr = (unsigned char *)ip6h + sizeof(struct ipv6hdr); // skb->data is usually skb + 40 is size of ipv6
    struct exthdr *ext = (struct exthdr *) hdr_ptr;
    int nh = ip6h->nexthdr;

    for (int _i = 0; _i < 100 & nh != 0x00; _i++  ){

        // Skip to the end of the destination option
        // If found Destination Option
        if(nh == 0x3c){
            // Detected Destination Header
            struct exthdr* destination_option_hdr = (struct exthdr*) hdr_ptr;
            unsigned char* option_ptr = hdr_ptr + sizeof(struct ipv6_opt_hdr);
            struct destopt_op *option;

            for (unsigned int i = 0; i < destination_option_hdr->hlen; i++){
                option = (struct destopt_op *)option_ptr;
                if(debug)
                    __dump_exthdr_opt(option);
                uint8_t PADDING = (option->optdatalen) % DSTOPT_WIDTH;
                option_ptr += sizeof(struct destopt_op) + option->optdatalen + PADDING;
            }
            if(debug)
                pr_debug("nh: %d", nh);
            hdr_ptr = option_ptr;
            ext = destination_option_hdr;
            nh = ext->nh;
        }


        // switch( ext->nh )
        // {
        //     case IPPROTO_UDP:
        //         if(debug)
        //             pr_debug("UDP Packet Found");
        //         protocol_id->proto = get_next_exthdr(hdr_ptr);
        //         struct udphdr *udp = (struct udphdr *)protocol_id->proto;
        //         if(debug)
        //             __dump_udphdr(udp);
        //         if (htons(udp->source) == 53){
        //             // DNS Packet
        //             protocol_id->proto = protocol_id->proto + sizeof(struct udphdr);
        //             protocol_id->proto_type = IPPROTO_DNS;
        //         }
        //         return 0;
        //     case IPPROTO_TCP:
        //         return -1;
        // }

        switch( nh )
        {
            case IPPROTO_UDP:
                if(debug)
                    pr_debug("UDP Packet Found");
                protocol_id->proto = hdr_ptr;
                struct udphdr *udp = (struct udphdr *)protocol_id->proto;
                if(debug)
                    __dump_udphdr(udp);
                if (htons(udp->source) == 53){
                    // DNS Packet
                    protocol_id->proto = protocol_id->proto + sizeof(struct udphdr);
                    protocol_id->proto_type = IPPROTO_DNS;
                }
                return 0;
            case IPPROTO_TCP:
                return -1;
        }

        // Go to next extension header...
        hdr_ptr = get_next_exthdr(hdr_ptr);
        ext = (struct exthdr *) hdr_ptr;
        nh = ext->nh;

    }
    return 0;
}
static int8_t populate_protocol_id(struct protoid *protocol_id ){
    switch (protocol_id->proto_type){
        case IPPROTO_DNS:
            populate_with_dns_data(protocol_id, (struct dns_struct *)protocol_id->proto);
        case IPPROTO_TCPSYN:
        case IPPROTO_TCPACK:
        case IPPROTO_TCPSYNACK:
            return -1;
    }
    return 0;
}
static void populate_with_dns_data(struct protoid *protocol_id, struct dns_struct *dns_header){
    protocol_id->proto_id_name = "id";
    protocol_id->proto_id_value = htons(dns_header->id);
}
static void __dump_protoid(struct protoid proto_id){
    pr_debug("static struct protoid {");
    pr_debug("    uint8_t     proto_type : %u;", proto_id.proto_type);
    pr_debug("    char*       proto_id_name : %s;", proto_id.proto_id_name);
    pr_debug("    uint64_t    proto_id_value : %llu;", proto_id.proto_id_value);
    pr_debug("    unsigned char* proto : %p;", proto_id.proto);
    pr_debug("};");
}