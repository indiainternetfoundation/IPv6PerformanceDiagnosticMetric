#include <net/ipv6.h>
#include <linux/ktime.h>
#include "mem/kreg.c"
#include "net/pdm.h"

static unsigned int handle_rx_pkt( void *priv, struct sk_buff *skb, const struct nf_hook_state *state)  {
    uint8_t debug = 0;

    uint64_t pdm_packet_pointer = 0;

    if(ipv6_pdm_hdr(skb, &pdm_packet_pointer, debug) != 0){
        struct pdm *pdm_packet = (struct pdm *) pdm_packet_pointer;

        if(debug)
            __dump_pdm(pdm_packet);

        switch(pdm_packet_type(pdm_packet)){
            case 0:
                // Packet A

                // Identify the protocol and its identifier
                struct protoid protocol_id;
                if(!protocol_identifier(&protocol_id, skb, debug))
                    return NF_ACCEPT;

                if(!populate_protocol_id(&protocol_id, debug))
                    return NF_ACCEPT;

                if(debug)
                    __dump_protoid(protocol_id);

                // Construct kregister element and push it to the memory
                struct pdm_segmented_key_array pdm_element = {
                    .id_value = protocol_id.proto_id_value,
                    .time = ktime_get_real_ns(),
                    .psntp = ntohs(pdm_packet->psntp),
                    .proto_type = protocol_id.proto_type
                };

                if (debug)
                    pr_info("Pushing PDM Entry (%d) at %llu : %llx", ntohs(pdm_packet->psntp), IDX(pdm_element.id_value, protocol_id.proto_type), pdm_element.time);
                if ( kreg_push( protocol_id.proto_id_value, protocol_id.proto_type, pdm_element, debug ) == -1) {
                    pr_info("Unable to push the PDM as well as the protocol identifier in the kreg queue.");
                }
                return NF_ACCEPT;
            case 1:
                // Packet B
                return NF_ACCEPT;
            case 2:
                // Packet C
                uint64_t rx = ktime_get_real_ns();

                struct time tls_time = {
                    .delta = pdm_packet->deltatls,
                    .scale = pdm_packet->scaledtls
                };
                uint64_t tls = _astons(tls_time);

                uint64_t rtt = rx - pop_report_reg(pdm_packet->psnlr);

                uint64_t rtd = rtt-tls;

                pr_info("Performance and Diagnostic Metrics//{'saddr': '%pI6', 'rtt': '%llu ns', 'rtd': '%llu ns'}", &ipv6_hdr(skb)->saddr, rtt, rtd);
                return NF_ACCEPT;
	    
            default:
                return NF_ACCEPT;
        }
	

        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}
