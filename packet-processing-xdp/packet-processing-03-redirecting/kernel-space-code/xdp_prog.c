#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


/* XDP enabled TX ports for redirect map */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1024);
} tx_port SEC(".maps");


SEC("xdp")
int xdp_redirect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    eth_header = data;
    if ((void *)eth_header + sizeof(*eth_header) > data_end) {
        return XDP_DROP;
    }


    __u16 h_proto = eth_header->h_proto;

    /* anything that is not IPv4 (including ARP) goes up to the kernel */
    if (h_proto != bpf_htons(ETH_P_IP)) {  // htons(ETH_P_IP) -> 0x08U
        return XDP_DROP;
    }
    ip_header = data + sizeof(*eth_header);
    if ((void *)ip_header + sizeof(*ip_header) > data_end) {
        return XDP_DROP;
    }

    if (ip_header->protocol != IPPROTO_ICMP) { // IPPROTO_ICMP = 1
        return XDP_DROP;
    }

    // if icmp, we send it back to the gateway
    // Create bpf_fib_lookup to help us route the packet
    struct bpf_fib_lookup fib_params;
    
    // fill struct with zeroes, so we are sure no data is missing
    __builtin_memset(&fib_params, 0, sizeof(fib_params));

    fib_params.family	= AF_INET;
    // use daddr as source in the lookup, so we refleect packet back (as if it wcame from us)
    fib_params.ipv4_src	= ip_header->daddr;
    // opposite here, the destination is the source of the icmp packet..remote end
    fib_params.ipv4_dst	= ip_header->saddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    bpf_printk("doing route lookup dst: %d\n", fib_params.ipv4_dst);
    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if ((rc != BPF_FIB_LKUP_RET_SUCCESS) && (rc != BPF_FIB_LKUP_RET_NO_NEIGH)) {
        bpf_printk("Dropping packet\n");
        return XDP_DROP;
    } else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
        // here we should let packet pass so we resolve arp.
        bpf_printk("Passing packet, lookup returned %d\n", BPF_FIB_LKUP_RET_NO_NEIGH);
        return XDP_PASS;
    }
    bpf_printk("route lookup success, ifindex: %d\n", fib_params.ifindex);
    bpf_printk("mac to use as dst is: %lu\n", fib_params.dmac);

    // Swap src with dst ip
    __u32 oldipdst = ip_header->daddr;
    ip_header->daddr = ip_header->saddr;
    ip_header->saddr = oldipdst;

    // copy resulting dmac/smac from the fib lookup
    __builtin_memcpy(eth_header->h_dest, fib_params.dmac, ETH_ALEN);
    __builtin_memcpy(eth_header->h_source, fib_params.smac, ETH_ALEN);

    // redirect packet to the resulting ifindex
    return bpf_redirect_map(&tx_port, fib_params.ifindex, 0);

}

char _license[] SEC("license") = "GPL";