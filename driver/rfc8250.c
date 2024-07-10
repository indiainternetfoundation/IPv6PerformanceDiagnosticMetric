
#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
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
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/random.h>

#include <linux/slab.h>
#include <linux/ktime.h>

#include "kreg.h"
// #include "kreg.c"
// #include "pdm/ipv6.c"
#include "pdm/pdm.c"
#include "pdm/proto_utils.c"
#include "pdm/time_utils.c"
// #include "pdm/utils.c"

static int debug = 0;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arnav Das");
MODULE_DESCRIPTION("IPv6 Performance and Diagnostic Metrics (PDM) Destination Option");

static unsigned int handle_tx_pkt( void *priv, struct sk_buff *skb, const struct nf_hook_state *state)  {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);

    // printk(",--------------- TX -----------------,");
    // print_hex_dump(KERN_DEBUG, "[ TX ] ", DUMP_PREFIX_OFFSET, 8, 1, ip6h, skb_tail_pointer(skb) - skb->data, 1);
    // printk("'------------------------------------'");


    struct protoid protocol_id;
    populate_protocol_type(&protocol_id, ip6h, 0);
    populate_protocol_id(&protocol_id);

    if(debug)
        __dump_protoid(protocol_id);

    struct pdm_segmented_key_array pdm_element = kreg_fetch(protocol_id.proto_id_value, protocol_id.proto_type);

    if (debug){
        printk("struct pdm_segmented_key_array pdm_element = {");
        printk("    .id_value = %u,", pdm_element.id_value);
        printk("    .time = %llu,", pdm_element.time);
        printk("    .psntp = %u,", pdm_element.psntp);
        printk("    .proto_type = %u", pdm_element.proto_type);
        printk("};");
    }


    int psntp = 0x00;
    get_random_bytes(&psntp, sizeof(psntp));
    uint64_t tlr = ktime_get_real_ns() - pdm_element.time;
    struct time _time = _nstoas(tlr);
    printk("Time Last Received : %llu", tlr);
    printk("Time Last Received : 0x%llx", tlr);

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
    pdm_dstopt->psnlr = (uint16_t) htons(psntp);
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

    return NF_ACCEPT;
}
static unsigned int handle_rx_pkt( void *priv, struct sk_buff *skb, const struct nf_hook_state *state)  {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);

    // printk(",--------------- RX -----------------,");
    // print_hex_dump(KERN_DEBUG, "[ RX ] ", DUMP_PREFIX_OFFSET, 8, 1, ip6h, skb_tail_pointer(skb) - skb->data, 1);
    // printk("'------------------------------------'");

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

            // Strip PDM Header
            // if (debug)
            //     printk("Striping PDM Destination Option Extension Header");
            // size_t new_size = strip_destination_option(ip6h, skb_tail_pointer(skb) - skb->data, 0);
            // if (debug)
            //     print_hex_dump(KERN_DEBUG, "[ NX ] ", DUMP_PREFIX_OFFSET, 8, 1, ip6h, new_size, 1);

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
                printk("Pushing PDM Entry (%d) at %d : %llx", psntp, IDX(pdm_element.id_value, protocol_id.proto_type), pdm_element.time);
            if ( !kreg_push( protocol_id.proto_id_value, protocol_id.proto_type, pdm_element )) {
                pr_err("Unable to push the PDM as well as the protocol identifier in the kreg queue.");
            }


        } else if (scaledtlr){
            // Got Packet 2
        }else {
            // Got Packet 3
        }
        // suppose time datatype is ktime_t
        // (struct map_queue) *queue = init_map_queue(64, sizeof(ktime_t)) // Maximum 64 elements buffer
        //
        // If First packet received :
        // Note: Note the rx time of packet
        // push(queue, pdm_packet->psntp, current_time);
        // When Second packet transmitting :
        // Note: Fetch the rx time of packet, along with new pdm id
        // ktime_t *rx_time_pt = fetch(queue, pdm_packet->psntp);
        // int deltalr = current_time - *rx_time_pt;
        // new_psn = (rx_time_pt - queue + offset);
        // If Second packet received :
        // If Third packet received :
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
    printk(KERN_INFO "Starting PDM listener...\n");


    // printk(",----------------- TEST ---------------------,");
    // struct time _time = _nstoas(ktime_get_real_ns());


    // /*
    //     atto_now: 0x732e8fe0
    //     static struct time {
    //         uint16_t delta : 8d88;
    //         uint8_t scale : 44;
    //     }
    //  */
    // struct time _time = _nstoas(0x9b9e * 1000);
    // __dump_time(_time);



    // /*
    //     atto_now: 0xcae81200
    //     static struct time {
    //         uint16_t delta : e033;
    //         uint8_t scale : 49;
    //     }
    // */
    // _time = _nstoas(0x785E3D500);
    // __dump_time(_time);



    // /*
    //     atto_now: 0x1af62c00
    //     static struct time {
    //         uint16_t delta : a688;
    //         uint8_t scale : 46;
    //     }
    // */
    // _time = _nstoas(3000000000);
    // __dump_time(_time);



    // struct time _time = _nstoas(3 * 1000000000);
    // printk("Time : %llx", _astons(_time) / 1000);
    // printk("'----------------- TEST ---------------------'");

    kreg_init();

    // kreg_push(13, 2, 0x13a1e8572e95);
    // kreg_push(13, 0x13a1e857e3aa);
    // kreg_push(14, 0x13a1e857e3aa);

    // printk_kreg();

    // Register Receiving and Transmission hooks
    nf_register_net_hook(&init_net, &tx_hook_ops);
    nf_register_net_hook(&init_net, &rx_hook_ops);
    return 0;    // Non-zero return means that the module couldn't be loaded.
}
static void __exit ipv6_pdm_cleanup(void) {

    nf_unregister_net_hook(&init_net, &tx_hook_ops);
    nf_unregister_net_hook(&init_net, &rx_hook_ops);

    // printk_kreg();
    kreg_destroy();

    printk(KERN_INFO "Cleaning up module.\n");
}

module_init(ipv6_pdm_init);
module_exit(ipv6_pdm_cleanup);
