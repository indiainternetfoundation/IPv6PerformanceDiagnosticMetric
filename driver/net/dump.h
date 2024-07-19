#include <net/ipv6.h>
#include "struct.c" // Datatype for extension headers
#include "application_layer.h"


void __dump_exthdr_opt(struct destopt_op* destopt_packet);
void __dump_exthdr( uint8_t nexthdr, uint64_t hdr_ptr );
void __dump_udphdr(struct udphdr* udp);
void __dump_pdm(struct pdm* pdm_packet);
void __dump_protoid(struct protoid proto_id);
