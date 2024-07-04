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

// removing the outermost vlan tags
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr eth_cpy;

	struct vlan_hdr *vlh;
    int ethh_size = sizeof(*eth);
    int vlanh_size = sizeof(*vlh);
	__be16 h_proto;
	int vlid;

	if (!proto_is_vlan(eth->h_proto))
		return 0;

	/* Careful with the parenthesis here */
	vlh = (void *)eth + ethh_size;

	/* Still need to do bounds checking */
	if ((void *) vlh + vlanh_size > data_end)
		return -1;


	/* Save vlan ID for returning, h_proto for updating Ethernet header */
	vlid = bpf_ntohs(vlh->h_vlan_TCI);
	h_proto = vlh->h_vlan_encapsulated_proto;

	/* Make a copy of the outer Ethernet header before we cut it off */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));
    
	/* Actually adjust the head pointer */
	if (bpf_xdp_adjust_head(ctx, vlanh_size))
		return -1;
    
	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	eth = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if ((void *)eth + ethh_size > data_end)
		return -1;
	/* Copy back the old Ethernet header and update the proto type */
	__builtin_memcpy(eth, &eth_cpy, sizeof(eth_cpy));
	eth->h_proto = h_proto;
	return vlid;
}

SEC("xdp") 
int xdp_remove_outermost_vlan_tag(struct xdp_md *ctx) {
    	void *data_end = (void *)(long)ctx->data_end;
	    void *data = (void *)(long)ctx->data;

        struct hdr_cursor hdr_p;
        int hdr_type;
        hdr_p.pos = data;
        struct ethhdr *eth;

        hdr_type = parse_vlan(&hdr_p, data_end, &eth);

        if (hdr_type < 0) {
            bpf_printk("Packet Dropping Because Of Invalid eth header\n");
		    return XDP_DROP;
        }
        
        if(proto_is_vlan(eth->h_proto)) {
            bpf_printk("Removing Packet VLAN TAGS\n");
            int res = vlan_tag_pop(ctx, eth);
            if(res == 0) {
                bpf_printk("Packet Passing Because There is no VLAN Tags\n");
            } else if (res < 0) {
                bpf_printk("Packets Dropping\n");
                return XDP_DROP;
            } else {
                bpf_printk("Packet Passing The VLAN ID was %d\n",res);
            }
        } else {
                bpf_printk("Packet Passing Because There is no VLAN Tags\n");

        }
    
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";