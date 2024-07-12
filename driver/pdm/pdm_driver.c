#include <net/ipv6.h>

struct exthdr {
	u_int8_t    nh;
	u_int8_t    hlen;

	// u_int8_t    opttype;
	// u_int8_t    optdatalen;

    // u_int8_t    *optdata;
} __attribute__((packed));

struct destopt_exthdr {
	u_int8_t    nh;
	u_int8_t    hlen;
    // u_int8_t    *optdata;
} __attribute__((packed));

struct destopt_options{
	u_int8_t    opttype;
	u_int8_t    optdatalen;

} __attribute__((packed));

struct __pdm{
	    u_int8_t    opttype;
    	u_int8_t    optdatalen;

        u_int8_t	scaledtlr;
        u_int8_t	scaledtls;
        u_int32_t   psntp;
        u_int32_t   psnlr;
        u_int16_t   deltatlr;
        u_int16_t   deltatls;

}  __attribute__((packed));

struct time_repr {
    __u16 delta;
    __u8 scale;
} __attribute__((packed));

static unsigned char *ipv6_pdm_hdr(struct sk_buff *skb);

static unsigned char *ipv6_pdm_hdr(struct sk_buff *skb){
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    __u8 nexthdr = ip6h->nexthdr;
    pr_debug("nexthdr: %u i.e. %d", nexthdr, nexthdr);
    unsigned char *hdr_pointer = skb->data;
    struct dst_exthdr *deh = (struct dst_exthdr *) (hdr_pointer + sizeof(struct ipv6hdr));

    // catch for any extension header
    while (ipv6_ext_hdr(nexthdr)) {
        // loop over all Option headers

        if (deh->opttype == 0x0F){
            return (hdr_pointer + sizeof(struct ipv6hdr) + 4);
        }
        nexthdr = deh->nexthdr;
        hdr_pointer = hdr_pointer + (4 + deh->optdatalen);
        deh = (struct dst_exthdr *) (hdr_pointer + sizeof(struct ipv6hdr));
    }

    return 0;
}


// Function to count the number of significant bits (1s and 0s) in the binary representation
int static countSignificantBits(uint64_t n) {
    int count = 0;
    while (n > 0) {
        count += 1; // Increment count if the least significant bit is 1
        n >>= 1; // Right shift n to process the next bit
    }
    return count;
}

static __u16 removeBitsFromLSB(uint64_t n, int bit_count) {
    return (__u16)(n >> bit_count);
}

static struct time_repr get_delta_scale(uint64_t time){
        __u8 scale = (countSignificantBits(time) - 16);
        return (struct time_repr){removeBitsFromLSB(time, scale), scale};
}
