#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


// declaring a map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, long);
    __type(value, __u32);
} packet_counts SEC(".maps");

SEC("xdp")
int xdp_map_counter(struct xdp_md *ctx) {
    
    long key = 0;
    // lookup the corresponding value from the map
    __u32 *count = bpf_map_lookup_elem(&packet_counts,&key);

    // checking to NULL
    if(!count){
        bpf_printk("Map Is NULL for key -> %d\n",key);
        return XDP_ABORTED;
    }
    *count+=1;

    bpf_map_update_elem(&packet_counts,&key,count,BPF_ANY);
    
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";