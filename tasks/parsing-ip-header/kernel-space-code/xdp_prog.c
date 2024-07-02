#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct hdr_cursor {
	void *pos;
};


static __always_inline int parse_ehthdr(struct hdr_cursor *hdr_p, void *data_end, struct ethhdr **ethhdr){
	struct ethhdr *eth = hdr_p->pos;
    int hdr_size = sizeof(*eth);

    if(hdr_p->pos + hdr_size > data_end){
        return -1;
    }

    hdr_p->pos += hdr_size;

    *ethhdr = eth;

    return eth->h_proto;
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
int xdp_parse_func(struct xdp_md *ctx) {
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *iph6;


	int eth_type, ip_type;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct hdr_cursor hdr_p;

	hdr_p.pos = data;

	eth_type = parse_ehthdr(&hdr_p, data_end, &eth);

    if(eth_type < 0) {
        bpf_printk("Packet Is Dropped Because Can't Resolve The Proto from ehternet header\n");
        return XDP_DROP;
    }

    if(eth_type == bpf_htons(ETH_P_IP)) {
        bpf_printk("Got IPv4 Packets\n");
        ip_type = parse_iphdr(&hdr_p, data_end, &iph);
        if(ip_type < 0){
            bpf_printk("Packet Dropping Can't Extract the ip header\n");
            return XDP_DROP;
        }
        bpf_printk("Protocol %d\n",ip_type);
        return XDP_PASS;

    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
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