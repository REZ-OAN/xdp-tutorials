#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// the header cursor to keep track of current parsing position

struct hdr_cursor {
    void *pos;
};

// inline functions

static __always_inline int parse_ethhdr(struct hdr_cursor *hdr_p, void *data_end, struct ethhdr **ethhdr) {
    struct ethhdr *eth = hdr_p->pos;
    int hdr_size = sizeof(*eth);

    // bytes bound check 
    if(hdr_p->pos + hdr_size > data_end)
        return -1;

    hdr_p->pos +=hdr_size;

    *ethhdr = eth;

    return eth->h_proto;
}


SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct icmp6hdr *icmp6;

    __u32 action = XDP_PASS;

    struct hdr_cursor hdr_p;

    int hdr_type;

    // initialize with starting position
    hdr_p.pos = data;

    // parsing the ethernet header
    hdr_type = parse_ethhdr(&hdr_p, data_end, &eth);

    if(hdr_type == bpf_htons(ETH_P_IP)) {
        bpf_printk("got ipv4 packets %d\n",hdr_type);
    }
    if(hdr_type == bpf_htons(ETH_P_IPV6)) {
        bpf_printk("got ipv6 packets %d\n",hdr_type);
    }

    return action;

}

char _license[] SEC("license") = "GPL";