#include <net/ipv6.h>
#include <linux/random.h>

#include "mem/kreg.c"
#include "mem/finreg.c"

#include "net/pdm.h"
#include "net/dump.h"
#include "net/struct.c"
#include "net/application_layer.h"

#include "time/timedelta.h"

#define PDM_EXTHDR_SIZE 16

static unsigned int handle_tx_pkt( void *priv, struct sk_buff *skb, const struct nf_hook_state *state)  {
    uint8_t debug = 0;

    struct protoid protocol_id;
    if(!protocol_identifier(&protocol_id, skb, debug))
        return NF_ACCEPT;

    if(!populate_protocol_id(&protocol_id, debug))
        return NF_ACCEPT;

    if(debug)
        __dump_protoid(protocol_id);

    if(is_null(kreg_fetch(protocol_id.proto_id_value, protocol_id.proto_type, debug)))
        return NF_ACCEPT;

    struct pdm_segmented_key_array pdm_element = kreg_pop(protocol_id.proto_id_value, protocol_id.proto_type, debug);
    int psntp = 0x00;
    get_random_bytes(&psntp, sizeof(psntp));
    uint64_t tlr = ktime_get_real_ns() - pdm_element.time;
    struct time _time = _nstoas(tlr);

    // 1.) Add header space of PDM
    int ipv6_payload = (skb_tail_pointer(skb) - skb->data) - sizeof(struct ipv6hdr);
    // int headroom = skb_headroom(skb);
    int tailroom = skb_tailroom(skb);

    // Ensure there's enough tailroom for the new data
    if (tailroom < PDM_EXTHDR_SIZE) {
        if (pskb_expand_head(skb, 0, PDM_EXTHDR_SIZE - tailroom, GFP_ATOMIC)) {
            pr_info("Error : Failed to expand skb\n");
            return NF_ACCEPT;
        }
    }

    // Adjust skb pointers to add data to the payload
    skb_put(skb, PDM_EXTHDR_SIZE);

    // Get the ipv6 header
    struct ipv6hdr *ip6h = ipv6_hdr(skb);

    // // // 2.) Shift ipv6hdr to udp
    unsigned long long ip6h_ptr = (unsigned long long)ip6h;

    // (1)
    //                             ,---  ipv6_payload  ---,
    // +--------------------------+-----------------------+
    // |         IPv6             |     ... data ...      |
    // +--------------------------+-----------------------+
    // |                          |
    //  `- ip6h_ptr                `- ip6h_ptr + sizeof(struct ipv6hdr)

    // (2)
    //                                     ,---  ipv6_payload  ---,
    // +--------------------------+-------+-----------------------+
    // |         IPv6             |0000000|     ... data ...      |
    // +--------------------------+-------+-----------------------+
    // |                                  |
    //  `- ip6h_ptr                        `- ip6h_ptr + sizeof(struct ipv6hdr) + PDM_EXTHDR_SIZE

    long long unsigned int *move_to = (void *)(ip6h_ptr + sizeof(struct ipv6hdr) + PDM_EXTHDR_SIZE);
    long long unsigned int *move_from = (void *)(ip6h_ptr + sizeof(struct ipv6hdr));

    memmove(move_to, move_from, ipv6_payload);
    memset(move_from, 0, PDM_EXTHDR_SIZE);


    // // 3.) Load the new blank space as exthdr and pdm
    struct ipv6_opt_hdr *pdm_dsthdr = (struct ipv6_opt_hdr *) (ip6h_ptr + sizeof(struct ipv6hdr));
    struct destopt_op *pdm_dstopt = (struct destopt_op *) (ip6h_ptr + sizeof(struct ipv6hdr) + sizeof(struct ipv6_opt_hdr));
    struct pdm *pdm = (struct pdm *) (ip6h_ptr + sizeof(struct ipv6hdr) + sizeof(struct ipv6_opt_hdr) + sizeof(struct destopt_op));

    // // 4.) Set the pdm values.
    pdm_dsthdr->nexthdr = ip6h->nexthdr;
    pdm_dsthdr->hdrlen = 0x1;

    pdm_dstopt->opttype = 0x0F;
    pdm_dstopt->optdatalen = 0x0A;
    pdm->psntp = psntp;
    pdm->psnlr = (uint16_t) htons(pdm_element.psntp);
    pdm->deltatlr = (uint16_t) htons(_time.delta);
    pdm->scaledtlr = _time.scale;
    pdm->deltatls = 0x00;
    pdm->scaledtls = 0x00;

    if(debug)
        __dump_time(_time);
    if(debug)
        __dump_pdm(pdm);

    // 5.) Set Padding

    // 6.) Overwrite the ipv6hdr fields.
    ip6h->nexthdr = 60;
    ip6h->payload_len =  htons( ntohs(ip6h->payload_len) + PDM_EXTHDR_SIZE);

    // 7.) Record the tx to calculate the RTT and RTD, at packet 3
    if ( !push_report_reg( psntp,  ktime_get_real_ns() ) ) {
        pr_info("Error : Unable to push the PDM in the finreg queue.");
    }

    return NF_ACCEPT;
}