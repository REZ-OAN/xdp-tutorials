#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>



#define XDP_ACTION_MAX 5


/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* Calculate packet length */
	__u64 bytes = data_end - data;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += bytes;
    bpf_printk("current rx packets -> %d  and current rx byte size -> %d",rec->rx_packets,rec->rx_bytes);
	return action;
}


SEC("xdp")
int  xdp_pass_func(struct xdp_md *ctx)
{
	__u32 action = XDP_PASS; /* XDP_PASS = 2 */
    bpf_printk("xdp_pass encountered %d\n",xdp_stats_record_action(ctx, action));
	return XDP_PASS;
}

SEC("xdp")
int  xdp_drop_func(struct xdp_md *ctx)
{
	__u32 action = XDP_DROP;
    bpf_printk("xdp_drop encountered\n");
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp")
int  xdp_abort_func(struct xdp_md *ctx)
{
	__u32 action = XDP_ABORTED;
    bpf_printk("xdp_abort encountered\n");
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";