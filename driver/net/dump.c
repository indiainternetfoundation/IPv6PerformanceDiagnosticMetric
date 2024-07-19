#include <net/ipv6.h>
#include "application_layer.h" // Application Layer Mapping
#include "struct.c" // Datatype for extension headers
#include "dump.h"

void __dump_exthdr( uint8_t nexthdr, uint64_t hdr_ptr ){
    struct ipv6_opt_hdr *ext = (struct ipv6_opt_hdr*) hdr_ptr;
    pr_info("struct ipv6_opt_hdr {");
    pr_info("\t\tu_int8_t nexthdr : %x;", ext->nexthdr);
    pr_info("\t\tu_int8_t hdrlen : %x;", ext->hdrlen);
    pr_info("}");
    uint hdr_data_size = 0;
    if (nexthdr == NEXTHDR_DEST){
        hdr_data_size = (8 + (ext->hdrlen * 8))  -  sizeof(struct ipv6_opt_hdr);
    } else {
        hdr_data_size = ext->hdrlen;
    }

    print_hex_dump(KERN_DEBUG, ".data ", DUMP_PREFIX_OFFSET, 8, 1, (uint64_t *)(hdr_ptr + sizeof(struct ipv6_opt_hdr)), hdr_data_size, 1);
}
void __dump_exthdr_opt(struct destopt_op* destopt_packet){
    pr_info("struct destopt_op {");
    pr_info("\t\tu_int8_t opttype : %x;", destopt_packet->opttype);
    pr_info("\t\tu_int8_t optdatalen : %x;", destopt_packet->optdatalen);
    pr_info("}");
    // pr_info("sizeof(struct destopt_op) : %x", sizeof(struct destopt_op));
    print_hex_dump(KERN_DEBUG, ".data ", DUMP_PREFIX_OFFSET, 8, 1, destopt_packet + 1, destopt_packet->optdatalen, 1);

}
void __dump_udphdr(struct udphdr* udp){
    pr_info("struct udphdr {");
    pr_info("\t\t__be16 source : %x;", htons(udp->source));
    pr_info("\t\t__be16 dest   : %x;", htons(udp->dest));
    pr_info("\t\t__be16 len    : %x;", htons(udp->len));
    pr_info("\t\t__sum16 check : %x;", htons(udp->check));
    pr_info("}");
    print_hex_dump(KERN_DEBUG, ".data ", DUMP_PREFIX_OFFSET, 8, 1, udp + 1, htons(udp->len), 1);
}
void __dump_pdm(struct pdm* pdm_packet){
    pr_info("struct pdm {");
    pr_info("\t\tu_int8_t  scaledtlr : %x;", pdm_packet->scaledtlr);
    pr_info("\t\tu_int8_t  scaledtls : %x;", pdm_packet->scaledtls);
    pr_info("\t\tu_int16_t psntp : %x;", ntohl(pdm_packet->psntp));
    pr_info("\t\tu_int16_t psnlr : %x;", ntohl(pdm_packet->psnlr));
    pr_info("\t\tu_int16_t deltatlr : %x;", ntohs(pdm_packet->deltatlr));
    pr_info("\t\tu_int16_t deltatls : %x;", ntohs(pdm_packet->deltatls));
    pr_info("}");
}
void __dump_protoid(struct protoid proto_id){
    pr_info("static struct protoid {");
    pr_info("    uint8_t     proto_type : %u;", proto_id.proto_type);
    pr_info("    char*       proto_id_name : %s;", proto_id.proto_id_name);
    pr_info("    uint64_t    proto_id_value : %llu;", proto_id.proto_id_value);
    pr_info("    unsigned char* proto : %p;", proto_id.proto);
    pr_info("};");
}