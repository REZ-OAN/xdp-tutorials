#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_main(struct xdp_md *ctx) {
    
    bpf_printk("All Packets are XDP_ABORTED");
    return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";