#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "struct.c"

#ifndef PROTOIDDEF
struct protoid {
    uint8_t     proto_type; //
    char*       proto_id_name;
    uint64_t    proto_id_value;
    unsigned char* proto;
};

enum {
    IPPROTO_DNS = 1,
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
#define PROTOIDDEF
#endif

static uint8_t protocol_identifier(struct protoid *protocol_id, struct sk_buff *skb, uint8_t debug);
static int8_t populate_protocol_id(struct protoid *protocol_id, uint8_t debug);
static void populate_with_dns_data(struct protoid *protocol_id, struct dns_struct *dns_header);