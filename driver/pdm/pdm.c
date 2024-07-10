#include <net/ipv6.h>
#include "./structure.h"
#include "./ipv6.c"
#include "./utils.c"

struct __pdm{
	    u_int8_t    opttype;
    	u_int8_t    optdatalen;

        u_int8_t	scaledtlr;
        u_int8_t	scaledtls;

        // As RFC
        // u_int32_t   psntp;
        // u_int32_t   psnlr;
        // As Wireshark
        u_int16_t   psntp;
        u_int16_t   psnlr;

        u_int16_t   deltatlr;
        u_int16_t   deltatls;

}  __attribute__((packed));

struct strip_ipv6_exthdr{
    u_int8_t parent_type; // if 0 - parent is ipv4hdr, if 1 - parent is exthdr
    u_int8_t nh; // next header to the stripped section
    char* parent; // pointer to parent
    size_t dlen; // Delta Length
};

// unsigned char *pdm_packet_pointer = ipv6_pdm_hdr(skb);

static unsigned char *ipv6_pdm_hdr(struct sk_buff *skb, int debug);
static size_t strip_destination_option(struct ipv6hdr *ip6h, unsigned int pkt_length, int debug);
void __dump_pdm_packet(struct __pdm* pkt);
void __dump_strip(struct strip_ipv6_exthdr* strip);

static unsigned char *ipv6_pdm_hdr(struct sk_buff *skb, int debug){
    /*
     This function does not implicitly check if the header
     exists in the packet or not, and will stuck in an infinite
     loop if the header doesnot exist. Careful!!! You have been
     warned!!!
    */
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    unsigned char *hdr_ptr = (unsigned char *)ip6h + sizeof(struct ipv6hdr); // skb->data is usually skb + 40 is size of ipv6
    struct exthdr *ext = (struct exthdr *) hdr_ptr;
    int nh = ip6h->nexthdr;

    for (int _i = 0; _i < 100 && nh != 0x00; _i++  ){

        if (nh == 0x3c)
        {
            if(debug){
                printk("Found Destination Option.");
                __dump_exthdr(hdr_ptr);
            }
            // Detected Destination Header
            struct exthdr* destination_option_hdr = (struct exthdr*) hdr_ptr;
            unsigned char* option_ptr = hdr_ptr + sizeof(struct ipv6_opt_hdr);
            struct destopt_op *option;

            for (unsigned int i = 0; i < destination_option_hdr->hlen; i++){
                option = (struct destopt_op *)option_ptr;

                if(debug)
                    __dump_exthdr_opt(option);

                if (option->opttype == 0x0F)
                    return option_ptr;

                option_ptr += sizeof(struct destopt_op) + option->optdatalen;
            }

        }

        // Go to next extension header...
        hdr_ptr = get_next_exthdr(hdr_ptr);
        ext = (struct exthdr *) hdr_ptr;
        nh = ext->nh;
    }
    return NULL;

}
/* Strips PDM - Destination Option Header - IPv6 Extension Header from a socket buffer.
 *
 * strip_destination_option(struct ipv6hdr *ip6h, unsigned int pkt_length, int debug)
 * Usage :
 *     size_t new_size = strip_destination_option(ip6h, skb_tail_pointer(skb) - skb->data, 0);
*/
static size_t strip_destination_option(struct ipv6hdr *ip6h, unsigned int pkt_length, int debug){

    struct strip_ipv6_exthdr strip;

    unsigned char *hdr_ptr = (unsigned char *)ip6h + sizeof(struct ipv6hdr); // skb->data is usually skb + 40 is size of ipv6
    struct exthdr *ext = (struct exthdr *) hdr_ptr;
    int nh = ip6h->nexthdr;

    for (int _i = 0; _i < 100 && nh != 0x00; _i++  ){

        if(ext->nh == 0x3c || nh == 0x3c){
            // Next Ext is Destination Option
            unsigned char* dst_ptr;
            unsigned char* prev_ptr;
            uint8_t prev_ptr_type;
            uint8_t found_pdm = 0x00;

            if(ext->nh == 0x3c){
                // Prior ExtHdrs exists
                strip.parent = (unsigned char*) hdr_ptr;
                strip.parent_type = 0x01; // Privious Pointer points to an Extension Header
                dst_ptr = get_next_exthdr(hdr_ptr);
            } else {
                // Prior ExtHdrs do not exist
                strip.parent = (unsigned char*) ip6h;
                strip.parent_type = 0x00; // Privious Pointer points to IPv6 Packet
                dst_ptr = hdr_ptr;
            }

            if(debug)
                printk("Found Destination Option.");
            if(debug)
                __dump_exthdr(hdr_ptr);

            // Detected Destination Header
            struct exthdr* destination_option_hdr = (struct exthdr*) hdr_ptr;
            unsigned char* option_ptr = hdr_ptr + sizeof(struct ipv6_opt_hdr); // Dont know what those 2 bytes are doing!!
            struct destopt_op *option;

            for (unsigned int i = 0; i < destination_option_hdr->hlen; i++){
                option = (struct destopt_op *)option_ptr;

                if(debug)
                    __dump_exthdr_opt(option);

                if (option->opttype == 0x0F)
                {
                    // PDM Found
                    struct __pdm* pdm_hdr = (struct __pdm*) (option_ptr + sizeof(*option));
                    found_pdm = 0x01;
                    // break;
                }
                option_ptr += sizeof(struct destopt_op) + option->optdatalen;

            }
            if(found_pdm){

                if(debug){
                    printk("=== OBJECTS DEBUG DURING STRIP ===");
                    __dump_exthdr((unsigned char *)destination_option_hdr);
                    __dump_exthdr_opt(option);
                    printk("=== OBJECTS DEBUG DURING STRIP ===");
                }

                strip.dlen = (option_ptr - dst_ptr);
                strip.nh = destination_option_hdr->nh;

                // Remove the section
                remove_section((unsigned char*)ip6h, pkt_length, dst_ptr, option_ptr - 1);

                __dump_strip(&strip);

               // ip6h->payload_len -= strip.dlen;
               printk("ip6h->payload_len : %x", ntohs(ip6h->payload_len));
               printk("strip.dlen : %x", strip.dlen);
               ip6h->payload_len = htons(ntohs(ip6h->payload_len) - strip.dlen);
               printk("ip6h->payload_len : %x", ntohs(ip6h->payload_len));

               if (strip.parent_type == 0x0){
                    // Parent is IPv6
                    ip6h->nexthdr = strip.nh;
               } else {
                    // Parent is Extension Header
                    ((struct exthdr*) strip.parent)->nh = strip.nh;
               }

                return pkt_length - (option_ptr - dst_ptr);
            }

        }

        // Go to next extension header...
        hdr_ptr = get_next_exthdr(hdr_ptr);
        ext = (struct exthdr *) hdr_ptr;
        nh = ext->nh;
    }
    return NULL;
}


void __dump_pdm_packet(struct __pdm* pdm_packet){
    printk("struct __pdm {");
    printk("\t\tu_int8_t  opttype : %x;", pdm_packet->opttype);
    printk("\t\tu_int8_t  optdatalen : %x;", pdm_packet->optdatalen);
    printk("\t\tu_int8_t  scaledtlr : %x;", pdm_packet->scaledtlr);
    printk("\t\tu_int8_t  scaledtls : %x;", pdm_packet->scaledtls);
    printk("\t\tu_int16_t psntp : %x;", ntohl(pdm_packet->psntp));
    printk("\t\tu_int16_t psnlr : %x;", ntohl(pdm_packet->psnlr));
    printk("\t\tu_int16_t deltatlr : %x;", ntohs(pdm_packet->deltatlr));
    printk("\t\tu_int16_t deltatls : %x;", ntohs(pdm_packet->deltatls));
    printk("}");
}
void __dump_strip(struct strip_ipv6_exthdr* strip){
    printk("struct strip_ipv6_exthdr{");
    printk("\t\tchar*    parent : %x;", strip->parent);
    printk("\t\tsize_t   dlen : %d;", strip->dlen);
    printk("\t\tu_int8_t nh : %x;", strip->nh);
    printk("\t\tu_int8_t parent_type : %d;", strip->parent_type);
    printk("};");
}
