#ifndef IPV6_STRUCT

// Any IPv6 Extension Header will have this structure,
// a `next-header` field, followed by a `header-length`
// field. // Same as ipv6_opt_hdr
struct exthdr {
	u_int8_t    nh;
	u_int8_t    hlen;
} __attribute__((packed));

// This is the same as `exthdr` as Destination Option
// is also an Extension Header. This struct will be
// made obsolete later.
struct destopt_exthdr {
	u_int8_t    nh;
	u_int8_t    hlen;
} __attribute__((packed));

// This structure is for Options in Destination Option
// Extension Header.
struct destopt_op{
	u_int8_t    opttype;
	u_int8_t    optdatalen;

} __attribute__((packed));

#define IPV6_STRUCT
#endif


#ifndef PROTO_STRUCT

//DNS header structure
struct dns_struct
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

#define PROTO_STRUCT
#endif