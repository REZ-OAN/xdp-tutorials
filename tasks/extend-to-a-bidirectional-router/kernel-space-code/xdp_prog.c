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

struct backend {
    __u32 saddr;
    __u32 daddr;
    unsigned char hwaddr[6];
    __u16 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, struct backend);
} redirect_packets SEC(".maps");

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


static __always_inline void construct_arp_reply(struct ethhdr *eth, struct arp_hdr *arph) {
    unsigned char tmp_mac[ETH_ALEN];
    __u32 tmp_ip;

    // Swap source and destination MAC addresses
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // Set ARP reply opcode
    arph->ar_op = bpf_htons(ARPOP_REPLY);

    // Swap source and destination hardware addresses
    __builtin_memcpy(tmp_mac, arph->ar_sha, ETH_ALEN);
    __builtin_memcpy(arph->ar_sha, arph->ar_tha, ETH_ALEN);
    __builtin_memcpy(arph->ar_tha, tmp_mac, ETH_ALEN);

    // Swap source and destination protocol addresses
    __builtin_memcpy(&tmp_ip, arph->ar_sip, sizeof(tmp_ip));
    __builtin_memcpy(arph->ar_sip, arph->ar_tip, sizeof(tmp_ip));
    __builtin_memcpy(arph->ar_tip, &tmp_ip, sizeof(tmp_ip));
}

SEC("xdp")
int xdp_redirect_router(struct xdp_md *ctx) {
    struct ethhdr *eth;
    struct iphdr *iph;
    struct arp_hdr *arph;
    int packet_type,ip_type;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct hdr_cursor hdr_p;
    hdr_p.pos = data;

    struct backend *dest;

    packet_type = parse_vlan(&hdr_p, data_end, &eth);
    if (packet_type == -1) {
        bpf_printk("Error parsing VLAN headers\n");
        return XDP_DROP;
    }

    bpf_printk("Packet type: 0x%x\n", bpf_ntohs(packet_type));
    if(packet_type == bpf_htons(ETH_P_IP)) {
        bpf_printk("Got IPv4 Packets\n");
        ip_type = parse_iphdr(&hdr_p, data_end, &iph);
        if(ip_type < 0){
            bpf_printk("Packet Dropping Can't Extract the ip header\n");
            return XDP_DROP;
        }
        bpf_printk("Protocol %d\n",ip_type);

    }   else if (packet_type == bpf_htons(ETH_P_ARP)) {
        bpf_printk("Got ARP packet\n");
        int arp_op = parse_arphdr(&hdr_p, data_end, &arph);
        if (arp_op < 0) {
            bpf_printk("Error parsing ARP header\n");
            return XDP_DROP;
        }
        bpf_printk("ARP Operation: %d\n", arp_op);
        if (arph->ar_op == bpf_htons(ARPOP_REQUEST)) {
            bpf_printk("GOT ARP request op\n");
            construct_arp_reply(eth,arph);
            return XDP_TX;

        } else if(arph->ar_op == bpf_htons(ARPOP_REPLY)){
            bpf_printk("Sending ARP reply\n");
            __u32 tip;
            __builtin_memcpy(&tip, arph->ar_tip, sizeof(tip));
            dest = bpf_map_lookup_elem(&redirect_packets, &tip);
            if (!dest) {
                bpf_printk("Target IP not found in the map\n");
                return XDP_DROP;
            }
            // Update Ethernet header
            __builtin_memcpy(eth->h_dest, dest->hwaddr, ETH_ALEN);
            return bpf_redirect(dest->ifindex, 0);
        }
    } else {
        bpf_printk("We don't process with these kindof packets\n");
        return XDP_PASS;
    }
    __u32 saddr = iph->saddr;
    bpf_printk("original source MAC %x:%x:%x:%x:%x:%x", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    bpf_printk("original dest MAC %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    dest = bpf_map_lookup_elem(&redirect_packets,&saddr);
    bpf_printk("Source : %d\n",iph->saddr);
    if(!dest){
        bpf_printk("Source Not Found In the MAP\n");
        return XDP_DROP;
    }
    bpf_printk("Changed iph source from this %d to this %d",iph->saddr, dest->saddr);
    iph->saddr = dest->saddr;
    bpf_printk("Changed iph Destination from this %d to this %d",iph->daddr, dest->daddr);
    iph->daddr = dest->daddr;
    

    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    bpf_printk("new source hwaddr %x:%x:%x:%x:%x:%x", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    __builtin_memcpy(eth->h_dest,dest->hwaddr,sizeof(eth->h_dest));
    bpf_printk("new dest hwaddr %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_redirect(dest->ifindex, 0);
    return XDP_TX;

}

char _license[] SEC("license") = "GPL";