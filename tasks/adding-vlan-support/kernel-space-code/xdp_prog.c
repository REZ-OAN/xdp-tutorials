#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/bpf.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define VLAN_MAX_DEPTH 5

struct hdr_cursor {
    void *pos;
};

// VLAN header structure
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// ARP header structure
struct arp_hdr {
    __be16 ar_hrd;    /* format of hardware address */
    __be16 ar_pro;    /* format of protocol address */
    __u8 ar_hln;      /* length of hardware address */
    __u8 ar_pln;      /* length of protocol address */
    __be16 ar_op;     /* ARP opcode (command) */
    __u8 ar_sha[ETH_ALEN];  /* sender hardware address */
    __u8 ar_sip[4];   /* sender IP address */
    __u8 ar_tha[ETH_ALEN];  /* target hardware address */
    __u8 ar_tip[4];   /* target IP address */
};

// Check if the proto is a VLAN
static __always_inline int proto_is_vlan(__u16 h_proto) {
    return (h_proto == bpf_htons(ETH_P_8021Q) ||
            h_proto == bpf_htons(ETH_P_8021AD));
}

// Parse VLAN headers
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

// Parse IPv4 header
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

// Parse IPv6 header
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

// Parse ARP header
static __always_inline int parse_arphdr(struct hdr_cursor *hdr_p, void *data_end, struct arp_hdr **arphdr) {
    struct arp_hdr *arph = hdr_p->pos;
    int hdr_size = sizeof(*arph);

    if (hdr_p->pos + hdr_size > data_end) {
        bpf_printk("ARP: Header goes past data end\n");
        return -1;
    }

    hdr_p->pos += hdr_size;
    *arphdr = arph;

    return arph->ar_op;
}

SEC("xdp")
int xdp_vlan_parser(struct xdp_md *ctx) {
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *iph6;
    struct arp_hdr *arph;

    int packet_type, ip_type;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct hdr_cursor hdr_p;
    hdr_p.pos = data;

    packet_type = parse_vlan(&hdr_p, data_end, &eth);
    if (packet_type == -1) {
        bpf_printk("Error parsing VLAN headers\n");
        return XDP_DROP;
    }

    bpf_printk("Packet type: 0x%x\n", packet_type);

    if (packet_type == bpf_htons(ETH_P_IP)) {
        bpf_printk("Got IPv4 packet\n");
        ip_type = parse_iphdr(&hdr_p, data_end, &iph);
        if (ip_type < 0) {
            bpf_printk("Error parsing IPv4 header\n");
            return XDP_DROP;
        }
        bpf_printk("IPv4 Protocol: %d\n", ip_type);
        return XDP_PASS;
    } else if (packet_type == bpf_htons(ETH_P_IPV6)) {
        bpf_printk("Got IPv6 packet\n");
        ip_type = parse_ip6hdr(&hdr_p, data_end, &iph6);
        if (ip_type < 0) {
            bpf_printk("Error parsing IPv6 header\n");
            return XDP_DROP;
        }
        bpf_printk("IPv6 Protocol: %d\n", ip_type);
        return XDP_PASS;
    } else if (packet_type == bpf_htons(ETH_P_ARP)) {
        bpf_printk("Got ARP packet\n");
        int arp_op = parse_arphdr(&hdr_p, data_end, &arph);
        if (arp_op < 0) {
            bpf_printk("Error parsing ARP header\n");
            return XDP_DROP;
        }
        bpf_printk("ARP Operation: %d\n", arp_op);
        return XDP_PASS;
    } else {
        bpf_printk("Unsupported packet type: 0x%x\n", packet_type);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
