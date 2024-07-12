
#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_DEBUG
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/vmalloc.h>

//#undef __KERNEL__
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
//#define __KERNEL__

#include <net/ipv6.h>
#include <net/ip_vs.h>

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/time.h>
// #include <linux/inet6.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/random.h>

#include <linux/slab.h>
#include <linux/ktime.h>

#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */

#include "kreg.h"
// #include "kreg.c"
// #include "pdm/ipv6.c"
#include "pdm/pdm.c"
#include "pdm/proto_utils.c"
#include "pdm/time_utils.c"
#include "finreg.h"


#define PROCFS_MAX_SIZE		1024
#define PROCFS_NAME 		"pdm_buffer"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arnav Das");
MODULE_DESCRIPTION("IPv6 Performance and Diagnostic Metrics (PDM) Destination Option");

static int debug = 0;
module_param(debug, int, 0660);

static unsigned int handle_tx_pkt( void *priv, struct sk_buff *skb, const struct nf_hook_state *state)  {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);

    struct protoid protocol_id;
    populate_protocol_type(&protocol_id, ip6h, 0);
    populate_protocol_id(&protocol_id);

    if(debug)
        __dump_protoid(protocol_id);

    struct pdm_segmented_key_array pdm_element = kreg_pop(protocol_id.proto_id_value, protocol_id.proto_type);

    if (debug){
        pr_debug("struct pdm_segmented_key_array pdm_element = {");
        pr_debug("    .id_value = %u,", pdm_element.id_value);
        pr_debug("    .time = %llu,", pdm_element.time);
        pr_debug("    .psntp = %u,", pdm_element.psntp);
        pr_debug("    .proto_type = %u", pdm_element.proto_type);
        pr_debug("};");
    }

    int psntp = 0x00;
    get_random_bytes(&psntp, sizeof(psntp));
    uint64_t tlr = ktime_get_real_ns() - pdm_element.time;
    struct time _time = _nstoas(tlr);


    uint8_t PDM_EXTHDR_SIZE = 16;

    // 1.) Add header space of PDM
    int ipv6_payload = (skb_tail_pointer(skb) - skb->data) - sizeof(struct ipv6hdr);
    int headroom = skb_headroom(skb);
    int tailroom = skb_tailroom(skb);

    // Ensure there's enough tailroom for the new data
    if (tailroom < PDM_EXTHDR_SIZE) {
        if (pskb_expand_head(skb, 0, PDM_EXTHDR_SIZE - tailroom, GFP_ATOMIC)) {
            pr_err("Failed to expand skb\n");
            return NF_ACCEPT;
        }
    }

    // Adjust skb pointers to add data to the payload
    skb_put(skb, PDM_EXTHDR_SIZE);

    // Get the ipv6 header
    ip6h = ipv6_hdr(skb);

    // 2.) Shift ipv6hdr to udp
    unsigned long long ip6h_ptr = (unsigned long long)ip6h;

    memmove(ip6h_ptr + sizeof(struct ipv6hdr) + PDM_EXTHDR_SIZE, ip6h_ptr + sizeof(struct ipv6hdr), ipv6_payload);
    memset(ip6h_ptr + sizeof(struct ipv6hdr), 0, PDM_EXTHDR_SIZE);

    // 3.) Load the new blank space as exthdr and pdm
    struct exthdr *pdm_dsthdr = (struct exthdr *) (ip6h_ptr + sizeof(struct ipv6hdr));
    struct __pdm *pdm_dstopt = (struct __pdm *) (ip6h_ptr + sizeof(struct ipv6hdr) + sizeof(struct exthdr));

    // 4.) Set the pdm values.
    pdm_dsthdr->nh = ip6h->nexthdr;
    pdm_dsthdr->hlen = 0x1;

    pdm_dstopt->opttype = 0x0F;
    pdm_dstopt->optdatalen = 0x0A;
    pdm_dstopt->psntp = psntp;
    pdm_dstopt->psnlr = (uint16_t) htons(pdm_element.psntp);
    pdm_dstopt->deltatlr = (uint16_t) htons(_time.delta);
    pdm_dstopt->scaledtlr = _time.scale;
    pdm_dstopt->deltatls = 0x00;
    pdm_dstopt->scaledtls = 0x00;

    // get_random_bytes(pdm_dstopt->psntp, sizeof(u_int16_t));
    if(debug)
        __dump_time(_time);
    if(debug)
        __dump_pdm_packet(pdm_dstopt);

    // 5.) Set Padding

    // 6.) Overwrite the ipv6hdr fields.
    ip6h->nexthdr = 60;
    ip6h->payload_len = ip6h->payload_len + PDM_EXTHDR_SIZE;

    // 7.) Record the tx to calculate the RTT and RTD, at packet 3
    // if (debug)

    if ( !push_report_reg( psntp,  ktime_get_real_ns() ) ) {
        pr_err("Unable to push the PDM in the finreg queue.");
    }

    return NF_ACCEPT;
}
static unsigned int handle_rx_pkt( void *priv, struct sk_buff *skb, const struct nf_hook_state *state)  {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);

    unsigned char *pdm_packet_pointer = ipv6_pdm_hdr(skb, 0);

    if(pdm_packet_pointer != 0){
        struct __pdm *pdm_packet = (struct __pdm *) pdm_packet_pointer;
        __u16  psntp     = ntohs(pdm_packet->psntp);
        __u16  psnlr     = ntohs(pdm_packet->psnlr);
        __u16  deltatlr  = ntohs(pdm_packet->deltatlr);
        __u16  deltatls  = ntohs(pdm_packet->deltatls);
        __u8   scaledtlr = pdm_packet->scaledtlr;
        __u8   scaledtls = pdm_packet->scaledtls;
        __u8   opttype   = pdm_packet->opttype;
        __u8   optdatalen= pdm_packet->optdatalen;

        if (debug)
            __dump_pdm_packet(pdm_packet);

        if (!psnlr){
            // Got Packet 1

            // Identify the protocol and its identifier
            struct protoid protocol_id;
            populate_protocol_type(&protocol_id, ip6h, 0);
            populate_protocol_id(&protocol_id);

            if(debug)
                __dump_protoid(protocol_id);

            struct pdm_segmented_key_array pdm_element = {
                .id_value = protocol_id.proto_id_value,
                .time = ktime_get_real_ns(),
                .psntp = psntp,
                .proto_type = protocol_id.proto_type
            };

            if (debug)
                pr_debug("Pushing PDM Entry (%d) at %d : %llx", psntp, IDX(pdm_element.id_value, protocol_id.proto_type), pdm_element.time);
            if ( !kreg_push( protocol_id.proto_id_value, protocol_id.proto_type, pdm_element )) {
                pr_err("Unable to push the PDM as well as the protocol identifier in the kreg queue.");
            }


        } else if (scaledtlr){
            // Got Packet 2
        }else {
            // Got Packet 3
            uint64_t rx = ktime_get_real_ns();
            pr_debug("pdm_packet->psnlr : %llu", pdm_packet->psnlr);

            struct time tls_time = {
                .delta = pdm_packet->deltatls,
                .scale = pdm_packet->scaledtls
            };
            uint64_t tls = _astons(tls_time);

            // print_report_reg();
            // uint64_t nowrtt = ktime_get_real_ns();
            // uint64_t rtt = nowrtt - fetch_report_reg(pdm_packet->psnlr);
            uint64_t rtt = ktime_get_real_ns() - pop_report_reg(pdm_packet->psnlr);
            uint64_t rtd = rtt-tls;
            // pr_info("RTT : %llu - %llu ns", nowrtt, pop_report_reg(pdm_packet->psnlr));
            // pr_info("      %llu ns", rtt);
            // pr_info("RTD : %llu - %llu ns", rtt, tls);
            // pr_info("      %llu ns", rtt - tls);

            pr_info("Performance and Diagnostic Metrics//{'saddr': '%pI6', 'rtt': '%llu ns', 'rtd': '%llu ns'}", &ipv6_hdr(skb)->saddr, rtt, rtt - tls);
            // pr_info("{");
            // pr_info("    'saddr': '%pI6',", &ipv6_hdr(skb)->saddr);
            // pr_info("    'rtt': '%llu',", rtt);
            // pr_info("    'rtd': '%llu',", rtd);
            // pr_info("}");
            pr_info("");
            // print_report_reg();
        }

    }
    return NF_ACCEPT;
}

static struct nf_hook_ops tx_hook_ops = {
	.hook     = handle_tx_pkt,
	.pf       = PF_INET6,
	// .hooknum  = NF_INET_POST_ROUTING,   // For Ethernet Faame,
	.hooknum  = NF_INET_LOCAL_OUT,      // For IP Packet,
	.priority = NF_IP6_PRI_FILTER,
};
static struct nf_hook_ops rx_hook_ops = {
	.hook     = handle_rx_pkt,
	.pf       = PF_INET6,
	.hooknum  = NF_INET_LOCAL_IN,
	.priority = NF_IP6_PRI_FILTER,
};

static int __init ipv6_pdm_init(void) {
    pr_debug(KERN_DEBUG "Starting PDM listener...\n");

    kreg_init();

    // Register Receiving and Transmission hooks
    nf_register_net_hook(&init_net, &tx_hook_ops);
    nf_register_net_hook(&init_net, &rx_hook_ops);
    return 0;    // Non-zero return means that the module couldn't be loaded.
}
static void __exit ipv6_pdm_cleanup(void) {

    nf_unregister_net_hook(&init_net, &tx_hook_ops);
    nf_unregister_net_hook(&init_net, &rx_hook_ops);

    kreg_destroy();

    pr_debug(KERN_DEBUG "Cleaning up module.\n");
}

module_init(ipv6_pdm_init);
module_exit(ipv6_pdm_cleanup);
