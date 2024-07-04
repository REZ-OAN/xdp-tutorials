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
    void* pos;
};

// VLAN header structure
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// check for the vlan proto
static __always_inline int proto_is_vlan(__u16 h_proto) {
    return (h_proto == bpf_htons(ETH_P_8021Q) ||
            h_proto == bpf_htons(ETH_P_8021AD));
}

// parsing ether header with the vlan parse functionality
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

// adding-vlan-tags to header
static __always_inline int vlan_tag_push(struct xdp_md *ctx, struct ethhdr *eth, int vlid)
{

	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
    int vlh_size = sizeof(*vlh);
    int ethh_size = sizeof(*eth);
    
	/* First copy the original Ethernet header */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	/* Then add space in front of the packet */
	if (bpf_xdp_adjust_head(ctx, 0 - vlh_size))
		return -1;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 */
	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	if ((void *)eth + ethh_size > data_end)
		return -1;

	/* Copy back Ethernet header in the right place, populate VLAN tag with
	 * ID and proto, and set outer Ethernet header to VLAN type.
	 */
	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

	vlh = (void *)eth + ethh_size ;

	if ((void *)vlh + vlh_size > data_end)
		return -1;

	vlh->h_vlan_TCI = bpf_htons(vlid);
	vlh->h_vlan_encapsulated_proto = eth->h_proto;

	eth->h_proto = bpf_htons(ETH_P_8021Q);
	return 0;
}



SEC("xdp") 
int xdp_add_vlan_tag(struct xdp_md *ctx) {
    	void *data_end = (void *)(long)ctx->data_end;
	    void *data = (void *)(long)ctx->data;
        int vid = 100;
        struct hdr_cursor hdr_p;
        int hdr_type;
        hdr_p.pos = data;
        struct ethhdr *eth;

        hdr_type = parse_vlan(&hdr_p, data_end, &eth);

        if (hdr_type < 0) {
            bpf_printk("Packet Dropping Because Of Invalid eth header\n");
		    return XDP_DROP;
        }
        
        if(!proto_is_vlan(eth->h_proto)) {
            bpf_printk("Attaching VLAN TAGS To Packet\n");
            int res = vlan_tag_push(ctx, eth,vid);
            if(res == 0) {
                bpf_printk("Added VLAN TAGS To Packet\n");
            } else if (res < 0) {
                bpf_printk("Packets Dropping\n");
                return XDP_DROP;
            } 
        } else {
            bpf_printk("Dropping Packet\n");
            return XDP_DROP;
        }
    
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";