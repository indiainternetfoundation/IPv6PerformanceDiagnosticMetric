#include <net/ipv6.h>
#include "struct.c"
#include "dump.h"
#include "pdm.h"

static unsigned int ipv6_pdm_hdr(struct sk_buff *skb, uint64_t *pdm_ptr, int debug){
    unsigned int hdr_ptr;
    if (ipv6_find_hdr(skb, &hdr_ptr, IPPROTO_DSTOPTS, NULL, NULL) < 0)
        return 0;

    struct ipv6_opt_hdr _opthdr, *opthdr;
    opthdr = skb_header_pointer(skb, hdr_ptr, sizeof(_opthdr), &_opthdr);

    struct ipv6_opt_hdr *dstopt     = (struct ipv6_opt_hdr *) opthdr;
    struct destopt_op   *option     = (struct destopt_op *) ((uint64_t)opthdr + sizeof(struct ipv6_opt_hdr));

    if(debug)
        __dump_exthdr(IPPROTO_DSTOPTS, (uint64_t)dstopt);
    if(debug)
        __dump_exthdr_opt(option);

    if(option->opttype == 0x0f) {
        *pdm_ptr = ((uint64_t)opthdr + sizeof(struct ipv6_opt_hdr) + sizeof(struct destopt_op));
        return 1;
    }
    return 0;
}
static uint8_t pdm_packet_type(struct pdm* pdm_packet){
    // uint16_t  psntp     = ntohs(pdm_packet->psntp);
    // uint16_t  psnlr     = ntohs(pdm_packet->psnlr);
    // uint16_t  deltatlr  = ntohs(pdm_packet->deltatlr);
    // uint16_t  deltatls  = ntohs(pdm_packet->deltatls);
    uint8_t   scaledtlr = pdm_packet->scaledtlr;
    uint8_t   scaledtls = pdm_packet->scaledtls;

    if(scaledtlr)
        // Packet B
        return 1;

    if(scaledtls)
        // Packet C
        return 2;

    return 0;
}