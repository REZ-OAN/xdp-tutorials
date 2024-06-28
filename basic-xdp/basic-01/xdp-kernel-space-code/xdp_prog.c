#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_main(struct xdp_md *ctx) {
    
    bpf_printk("All Packets are XDP_PASSED");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";