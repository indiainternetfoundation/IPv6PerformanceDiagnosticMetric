#include <net/ipv6.h>
#include "struct.c"

static unsigned int ipv6_pdm_hdr(struct sk_buff *skb, uint64_t *pdm_ptr, int debug);
static uint8_t pdm_packet_type(struct pdm* pdm_packet);
