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
                pr_debug("Found Destination Option.");
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

void __dump_pdm_packet(struct __pdm* pdm_packet){
    pr_debug("struct __pdm {");
    pr_debug("\t\tu_int8_t  opttype : %x;", pdm_packet->opttype);
    pr_debug("\t\tu_int8_t  optdatalen : %x;", pdm_packet->optdatalen);
    pr_debug("\t\tu_int8_t  scaledtlr : %x;", pdm_packet->scaledtlr);
    pr_debug("\t\tu_int8_t  scaledtls : %x;", pdm_packet->scaledtls);
    pr_debug("\t\tu_int16_t psntp : %x;", ntohl(pdm_packet->psntp));
    pr_debug("\t\tu_int16_t psnlr : %x;", ntohl(pdm_packet->psnlr));
    pr_debug("\t\tu_int16_t deltatlr : %x;", ntohs(pdm_packet->deltatlr));
    pr_debug("\t\tu_int16_t deltatls : %x;", ntohs(pdm_packet->deltatls));
    pr_debug("}");
}
void __dump_strip(struct strip_ipv6_exthdr* strip){
    pr_debug("struct strip_ipv6_exthdr{");
    pr_debug("\t\tchar*    parent : %x;", strip->parent);
    pr_debug("\t\tsize_t   dlen : %d;", strip->dlen);
    pr_debug("\t\tu_int8_t nh : %x;", strip->nh);
    pr_debug("\t\tu_int8_t parent_type : %d;", strip->parent_type);
    pr_debug("};");
}
