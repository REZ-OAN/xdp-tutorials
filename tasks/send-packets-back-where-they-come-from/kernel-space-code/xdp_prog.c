#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/bpf.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define VLAN_MAX_DEPTH 2

struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

struct icmphdr_common {
	__u8		type;
	__u8		code;
	__sum16	cksum;
};

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static __always_inline __u16 icmp_checksum_diff(__u16 seed, struct icmphdr_common *icmphdr_new,	struct icmphdr_common *icmphdr_old)
{
	__u32 csum, size = sizeof(struct icmphdr_common);

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}

static __always_inline int proto_is_vlan(__u16 h_proto) {
    return (h_proto == bpf_htons(ETH_P_8021Q) ||
            h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	__u8 h_tmp[ETH_ALEN];

	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

static __always_inline void swap_src_dst_ipv6(struct ipv6hdr *ipv6)
{
	struct in6_addr tmp = ipv6->saddr;

	ipv6->saddr = ipv6->daddr;
	ipv6->daddr = tmp;
}

static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	__be32 tmp = iphdr->saddr;

	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = tmp;
}

static __always_inline int parse_vlan(struct hdr_cursor *hdr_p, void *data_end, struct ethhdr **ethhdr) {
    struct vlan_hdr *vlh;
    __u16 h_proto;
    int i;
    struct ethhdr *eth = hdr_p->pos;
    int hdr_size = sizeof(*eth);

    if (hdr_p->pos + hdr_size > data_end) {
        bpf_printk("VLAN: Ethernet header goes past data end\n");
        return -1;
    }

    hdr_p->pos += hdr_size;

    *ethhdr = eth;
    h_proto = eth->h_proto;

    #pragma unroll
    for (i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (!proto_is_vlan(h_proto))
            break;

        vlh = (struct vlan_hdr *)hdr_p->pos;
        if (hdr_p->pos + sizeof(*vlh) > data_end) {
            bpf_printk("VLAN: VLAN header goes past data end\n");
            return -1;
        }

        h_proto = vlh->h_vlan_encapsulated_proto;
        hdr_p->pos += sizeof(*vlh);
    }

    return h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *hdr_p, void *data_end, struct iphdr **iphdr) {
    struct iphdr *iph = hdr_p->pos;
    int hdr_size = sizeof(*iph);

    if (hdr_p->pos + hdr_size > data_end) {
        bpf_printk("IPv4: Header goes past data end\n");
        return -1;
    }

    if (iph->ihl * 4 < hdr_size) {
        bpf_printk("IPv4: Invalid header length\n");
        return -1;
    }

    hdr_p->pos += hdr_size;
    *iphdr = iph;

    return iph->protocol;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *hdr_p, void *data_end, struct ipv6hdr **ip6hdr) {
    struct ipv6hdr *ip6h = hdr_p->pos;
    int hdr_size = sizeof(*ip6h);

    if (hdr_p->pos + hdr_size > data_end) {
        bpf_printk("IPv6: Header goes past data end\n");
        return -1;
    }

    hdr_p->pos += hdr_size;
    *ip6hdr = ip6h;

    return ip6h->nexthdr;
}

static __always_inline int parse_icmphdr_common(struct hdr_cursor *hdr_p, void *data_end,	struct icmphdr_common **icmphdr)
{
	struct icmphdr_common *h = hdr_p->pos;

	if ((void*)h + sizeof(*h) > data_end)
		return -1;

	hdr_p->pos  = (void*)h + sizeof(*h);
	*icmphdr = h;

	return h->type;
}

SEC("xdp")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor hdr_p;
	struct ethhdr *eth ;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	__u16 echo_reply;
	__sum16 old_csum;
	struct icmphdr_common *icmphdr;
	struct icmphdr_common icmphdr_old;
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	hdr_p.pos = data;
	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_vlan(&hdr_p, data_end, &eth);
	bpf_printk("Packet Proto 0x%x\n",eth_type);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&hdr_p, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP) {
             bpf_printk("Not ICMP Request Simply Dropping\n");
			return XDP_DROP; 
            }
		bpf_printk("Got IPv4 ICMP Packets\n");
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&hdr_p, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6) {
			 bpf_printk("Not ICMP Request Simply Dropping\n");
             return XDP_DROP;
        }
		bpf_printk("Got IPv6 ICMP Packets\n");
	} else if(eth_type == bpf_htons(ETH_P_ARP)) {
		bpf_printk("ARP request Simply Passing\n");
		return XDP_PASS;
	} else {
		bpf_printk("we don't want to process this type of packets\n");
		return XDP_DROP;
	}

	/*
	 * We are using a special parser here which returns a stucture
	 * containing the "protocol-independent" part of an ICMP or ICMPv6
	 * header.  For purposes of this Assignment we are not interested in
	 * the rest of the structure.
	 */
	icmp_type = parse_icmphdr_common(&hdr_p, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO) {
		bpf_printk("This is an echo_REPLY IPv4\n");
		/* Swap IP source and destination */
		swap_src_dst_ipv4(iphdr);
		echo_reply = ICMP_ECHOREPLY;
		bpf_printk("Swaping SRC and DST IP Completed IPv4\n");
	} else if (eth_type == bpf_htons(ETH_P_IPV6)
		   && icmp_type == ICMPV6_ECHO_REQUEST) {
		bpf_printk("This is an echo_REPLY IPv6\n");
		/* Swap IPv6 source and destination */
		swap_src_dst_ipv6(ipv6hdr);
		echo_reply = ICMPV6_ECHO_REPLY;
		bpf_printk("Swaping SRC and DST IP Completed IPv6\n");
	} else {
        bpf_printk("Not ICMP REPLY Simply Passing\n");
		return XDP_PASS;
	}

	/* Swap Ethernet source and destination */
	swap_src_dst_mac(eth);
	bpf_printk("Swaping SRC and DST MAC\n");
	if((void *)icmphdr + sizeof(*icmphdr) > data_end) {
		bpf_printk("Courrepted Data Dropping\n");
		return XDP_DROP;
	}
	// /* Patch the packet and update the checksum.*/
	old_csum = icmphdr->cksum;
	icmphdr->cksum = 0;
	icmphdr_old = *icmphdr;
	icmphdr->type = echo_reply;
	icmphdr->cksum = icmp_checksum_diff(~old_csum, icmphdr, &icmphdr_old);
    bpf_printk("Simply XDP_TX because it is ICMP request\n");
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";