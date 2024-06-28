#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct packet_info {
     __u32 count;
     __u32 size;
};
// declaring a map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, long);
    __type(value,struct packet_info);
} packet_counts SEC(".maps");

SEC("xdp")
int xdp_map_counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
    long key = 0;
    // lookup the corresponding value from the map
   struct packet_info *packet = bpf_map_lookup_elem(&packet_counts,&key);

    // checking to NULL
    if(!packet){
        bpf_printk("Map Is NULL for key -> %d\n",key);
        return XDP_ABORTED;
    }
    packet->count +=1;
    // size of the bytes process
    packet->size += data_end - data ;

    bpf_map_update_elem(&packet_counts,&key,packet,BPF_ANY);
    
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";