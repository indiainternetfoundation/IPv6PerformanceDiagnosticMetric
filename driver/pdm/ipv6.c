#include <net/ipv6.h>
#include "./structure.h"

unsigned char *get_next_exthdr( unsigned char* hdr_ptr );
unsigned char *get_exthdr_data( unsigned char* hdr_ptr );
void __dump_exthdr_opt(struct destopt_op* destopt_packet);
void __dump_exthdr( unsigned char* hdr_ptr );

unsigned char *get_next_exthdr( unsigned char* hdr_ptr ){
    struct exthdr *ext = (struct exthdr*) hdr_ptr;
    return (unsigned char*)(hdr_ptr + sizeof(*ext) + ext->hlen);
    //    `------' `-----------' `----------'
    //    Starting    Size    +   Size of
    //     of Hdr    of ext         Data
    //    `------' `-----------------------'
    //    Starting         Total Size
    //     of Hdr            of ext
}
unsigned char *get_exthdr_data( unsigned char* hdr_ptr ){
    struct exthdr *ext = (struct exthdr*) hdr_ptr;
    return (unsigned char*)(hdr_ptr + sizeof(*ext));
    //    `------' `-----------'
    //    Starting    Size
    //     of Hdr    of ext
}

void __dump_exthdr( unsigned char* hdr_ptr ){
    struct exthdr *ext = (struct exthdr*) hdr_ptr;
    pr_debug("struct exthdr {");
    pr_debug("\t\tu_int8_t nh : %x;", ext->nh);
    pr_debug("\t\tu_int8_t hlen : %x;", ext->hlen);
    pr_debug("}");
    print_hex_dump(KERN_DEBUG, ".data ", DUMP_PREFIX_OFFSET, 8, 1, get_exthdr_data(hdr_ptr), ext->hlen, 1);
    return;
}
void __dump_exthdr_opt(struct destopt_op* destopt_packet){
    pr_debug("struct destopt_op {");
    pr_debug("\t\tu_int8_t opttype : %x;", destopt_packet->opttype);
    pr_debug("\t\tu_int8_t optdatalen : %x;", destopt_packet->optdatalen);
    pr_debug("}");
    // pr_debug("sizeof(struct destopt_op) : %x", sizeof(struct destopt_op));
    print_hex_dump(KERN_DEBUG, ".data ", DUMP_PREFIX_OFFSET, 8, 1, destopt_packet + 1, destopt_packet->optdatalen, 1);

}
void __dump_udphdr(struct udphdr* udp){
    pr_debug("struct udphdr {");
    pr_debug("\t\t__be16 source : %x;", htons(udp->source));
    pr_debug("\t\t__be16 dest   : %x;", htons(udp->dest));
    pr_debug("\t\t__be16 len    : %x;", htons(udp->len));
    pr_debug("\t\t__sum16 check : %x;", htons(udp->check));
    pr_debug("}");
    print_hex_dump(KERN_DEBUG, ".data ", DUMP_PREFIX_OFFSET, 8, 1, udp + 1, htons(udp->len), 1);
}
