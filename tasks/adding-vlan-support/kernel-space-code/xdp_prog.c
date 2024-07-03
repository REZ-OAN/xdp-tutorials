#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/bpf.h>
#include<linux/if_vlan.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define VLAN_MAX_DEPTH 5

struct hdr_cursor {
	void *pos;
};

// vlan header structure which is not exported from any of the ip header files.
// copied from the internal kernel headers
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

// checking is the proto is a vlan
static __always_inline int proto_is_vlan(__u16 h_proto) {
	return (h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

// to parse the vlan headers with ether headers if it is nested upto 5 times  you can change the MAX iteration
static __always_inline int parse_vlan(struct hdr_cursor *hdr_p, void *data_end, struct ethhdr **ethhdr) {
    struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;
	struct ethhdr *eth = hdr_p->pos;
    int hdr_size = sizeof(*eth);

    if(hdr_p->pos + hdr_size > data_end){
        return -1;
    }

    hdr_p->pos += hdr_size;

    *ethhdr = eth;
	h_proto = eth->h_proto;
	

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
        
		if (!proto_is_vlan(h_proto))
			break;

        vlh = (struct vlan_hdr*)hdr_p->pos;
		if ( hdr_p->pos + sizeof(*vlh)> data_end )
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
        hdr_p->pos += sizeof(*vlh);
	}

	return h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *hdr_p, void *data_end, struct iphdr **iphdr) {
        struct iphdr *iph = hdr_p->pos;
        int hdr_size = sizeof(*iph);
        
        if(hdr_p->pos + hdr_size > data_end){
            return -1;
        }

        if(iph->ihl*4 < hdr_size) {
            return -1;
        }

        hdr_p->pos += hdr_size;
        *iphdr = iph;

        return iph->protocol;
}


static __always_inline int parse_ip6hdr(struct hdr_cursor *hdr_p, void *data_end, struct ipv6hdr **ip6hdr){
        struct ipv6hdr *ip6h = hdr_p->pos;
        int hdr_size = sizeof(*ip6h);

        if(hdr_p->pos + hdr_size > data_end){
            return -1;
        }

        hdr_p->pos += hdr_size;
        *ip6hdr = ip6h;

        return ip6h->nexthdr;
}


SEC("xdp")
int xdp_vlan_parser(struct xdp_md *ctx){
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *iph6;

	int packet_type,ip_type;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct hdr_cursor hdr_p;

	hdr_p.pos = data;
    packet_type = parse_vlan(&hdr_p, data_end, &eth);
    if(packet_type <0){
        bpf_printk("Packet Dropping Ethernet Header Invalid\n");
        return XDP_DROP;
    }
    if(packet_type == bpf_htons(ETH_P_IP)) {
        bpf_printk("Got IPv4 Packets\n");
        ip_type = parse_iphdr(&hdr_p, data_end, &iph);
        if(ip_type < 0){
            bpf_printk("Packet Dropping Can't Extract the ip header\n");
            return XDP_DROP;
        }
        bpf_printk("Protocol %d\n",ip_type);
        return XDP_PASS;

    } else if (packet_type == bpf_htons(ETH_P_IPV6)) {
        bpf_printk("Got IPv6 Packets\n");
        ip_type = parse_ip6hdr(&hdr_p, data_end, &iph6);
        if(ip_type < 0){
            bpf_printk("Packet Dropping Can't Extract the ip header\n");
            return XDP_DROP;
        }
        bpf_printk("Protocol %d\n",ip_type);
        return XDP_PASS;
    } else {
        bpf_printk("Packet Is Dropped Because Can't Resolve The Appropriate Proto from ehternet header");
        return XDP_DROP;
    }

    return XDP_PASS;

}
char _license[] SEC("license") = "GPL";

















