#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
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

static __always_inline int parse_ip6hdr(struct hdr_cursor *hdr_p,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = hdr_p->pos;

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if ((void *)ip6h + sizeof(*ip6h) > data_end)
		return -1;

	hdr_p->pos += sizeof(*ip6h);
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

static __always_inline int parse_iphdr(struct hdr_cursor *hdr_p,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = hdr_p->pos;
	int hdr_size;
	if ((void *)iph + sizeof(*iph) > data_end)
		return -1;

	hdr_size = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdr_size < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (hdr_p->pos + hdr_size > data_end)
		return -1;

	hdr_p->pos += hdr_size;
	*iphdr = iph;

	return iph->protocol;
}

static __always_inline int parse_udphdr(struct hdr_cursor *hdr_p,
					void *data_end,
					struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = hdr_p->pos;

	if ((void *)h + sizeof(*h) > data_end)
		return -1;

	hdr_p->pos += sizeof(*h) ;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *hdr_p,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = hdr_p->pos;

	if ((void *)h + sizeof(*h) > data_end)
		return -1;

	len = h->doff * 4;
	/* Sanity check packet field is valid */
	if(len < sizeof(*h))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (hdr_p->pos + len > data_end)
		return -1;

	hdr_p->pos += len;
	*tcphdr = h;

	return len;
}

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    __u32 sum = (csum & 0xffff) + (csum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)~sum;
}

SEC("xdp")
int xdp_rewrite_func(struct xdp_md *ctx) {

    struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
    int action = XDP_PASS;
    int eth_type, ip_type;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct hdr_cursor hdr_p;


    // initialize with starting position
    hdr_p.pos = data;

    // parsing the ethernet header
    eth_type = parse_ethhdr(&hdr_p, data_end, &eth);
    if (eth_type < 0) {
		action = XDP_ABORTED;
        bpf_printk("eth_type is invalid -> aborting packet\n");
		return action;
	}

    if (eth_type == bpf_htons(ETH_P_IP)) {
        // if it's ipv4 then parse the protocol for ipv4
		ip_type = parse_iphdr(&hdr_p, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        // if it's ipv6 then parse the protocol for ipv6
		ip_type = parse_ip6hdr(&hdr_p, data_end, &ipv6hdr);
	} else {
		action = XDP_ABORTED;
        bpf_printk("eth_type is invalid -> aborting packet\n");
		return action;
	}


	if(ip_type == IPPROTO_UDP) {
		if(parse_udphdr(&hdr_p, data_end, &udphdr) < 0){
			action = XDP_ABORTED;
			bpf_printk(" udp block packet len is not valid -> aborting packet\n");
			return action;
		}
		 struct udphdr udphdr_old;
		 __u32 csum = udphdr->check;
		 udphdr_old = *udphdr;
		 udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
		 csum = bpf_csum_diff((__be32 *)&udphdr_old, 4, (__be32 *)udphdr, 4, ~csum);
		 udphdr->check = csum_fold_helper(csum);

	} else if (ip_type == IPPROTO_TCP) {
			if (parse_tcphdr(&hdr_p, data_end, &tcphdr) < 0) {
						action = XDP_ABORTED;
						bpf_printk("tcp block packet len is not valid -> aborting packet\n");
						return action;
					}
			tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
			tcphdr->check += bpf_htons(1);
			if (!tcphdr->check)
				tcphdr->check += bpf_htons(1);
	} else {
		action = XDP_ABORTED;
        bpf_printk("none block ip_type is invalid -> aborting packet %d\n",ip_type);
		return action;
	}

    return action;

}

char _license[] SEC("license") = "GPL";