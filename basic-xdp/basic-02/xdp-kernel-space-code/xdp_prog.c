#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_pass(struct xdp_md *ctx) {
    bpf_printk("All Packets are XDP_PASSED");
    return XDP_PASS;
}

SEC("xdp")
int xdp_prog_drop(struct xdp_md *ctx) {
    bpf_printk("All Packets are XDP_DROPPED");
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";