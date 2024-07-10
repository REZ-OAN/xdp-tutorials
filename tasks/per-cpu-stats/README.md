# Task-02 (per-cpu-stats)

## Prerequisite
 - [Create Environment](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/Environment-Setup/README.md)

## BPF_MAP_TYPE_PERCPU_ARRAY

`BPF_MAP_TYPE_PERCPU_ARRAY` is a type of `BPF` map that allows each CPU to have its own instance of the map's values. This means that updates to the map are done on a per-CPU basis. `BPF_MAP_TYPE_PERCPU_ARRAY` uses a different memory region for each CPU. To restrict storage to a single CPU, you may use a `BPF_MAP_TYPE_PERCPU_ARRAY`. When a program reads from or writes to a `BPF_MAP_TYPE_PERCPU_ARRAY` map, it accesses the version specific to the CPU it is running on. This makes it efficient for operations that are frequently updated, like packet counters, because it reduces the overhead associated with synchronization across multiple CPUs.


## Demonstration


This `XDP` program defines a map to record statistics of packets processed by **XDP actions**. The map, `xdp_stats_map`, is a per-CPU array that stores packet and byte counts for up to five XDP actions. The program includes three XDP functions: `xdp_pass_func`, `xdp_drop_func`, and `xdp_abort_func`, which are triggered for corresponding actions (XDP_PASS, XDP_DROP, XDP_ABORTED). Each function calls `xdp_stats_record_action` to update the statistics in the map for the specific action, incrementing the packet count and adding the packet's byte size. Additionally, an user_space_prog in Go is used for logging packet counts and sizes to the console.

### Packet Flow

![packet-flow](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/per-cpu-stats/images/pacekt-flow.png)


Firstly you have to navigate to `tasks/per-cpu-stats/user-space-code` this directory. After doing all the necessary steps from the prerequisite. You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `xdp-abort`
```
go build
```
4. Run the binary with `-iface <interface name> -prog <xdp_pass, xdp_drop, or xdp_abort>`   with `sudo` privileges
```
sudo ./xdp-per-cpu-stats -iface veth-h -prog xdp_drop
```
**Note**: I have used `veth-h` as interface name. Because I am working on the `default` environment setup.


## Testing results

- Pinging and  Tracing for `xdp_pass`

![xdp-pass-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/per-cpu-stats/images/xdp_pass_logs.png)

- Pinging and  Tracing for `xdp_drop`

![xdp-drop-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/per-cpu-stats/images/xdp_drop_logs.png)

- Pinging and  Tracing for `xdp_abort`

![xdp-abort-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/per-cpu-stats/images/xdp_abort_logs.png)