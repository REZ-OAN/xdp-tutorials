# Packet-Processing-03 (Learn redirect the packet using bpf_redirect_map and bpf_fib_lookup)

## Table of contents
 - [Introduction](#introduction)
 - [Sending packets back to the interface they came from](#sending-packets-back-to-the-interface-they-came-from)
 - [Packet Redirect To Another Interfaces](#packet-redirect-to-another-interfaces)
    - [bpf_redirect_map](#bpf_redirect_map)
    - [BPF_MAP_TYPE_DEVMAP](#bpf_map_type_devmap)
    - [bpf_redirect](#bpf_redirect)
    - [bpf_fib_lookup](#bpf_fib_lookup)
 - [Environment Setup](#environment-setup)
 - [Demonstration](#demonstration)

## Introduction
Now that you have come this far, you know how to parse packet data, and how to modify packets. These are two of the main components of a packet processing system, but there is one additional component that is missing: how to redirect packets and transmit them back out onto the network. This lesson will cover this aspect of packet processing.

## Sending packets back to the interface they came from
The `XDP_TX` return value can be used to send the packet back from the same interface it came from. This functionality caXDP_TXn be used to implement load balancers, to send simple ICMP replies, etc.

## Packet Redirect To Another Interfaces
Packets can be redirected to different network interfaces using `bpf_redirect` or `bpf_redirect_map`, which return `XDP_REDIRECT`. The `bpf_redirect` helper takes the **interface index** of the redirect port as parameter and may be used with other helpers such as `bpf_fib_lookup`, while `bpf_redirect_map` uses a special map (**BPF_MAP_TYPE_DEVMAP**) to map virtual ports to network devices.

### bpf_redirect_map
 - Redirects packets to a specified network device index (ifindex) using a BPF map (In this example we used `tx_port`).
 - Directs the packet to the network interface specified by ifindex. (`bpf_redirect_map(&tx_port, ifindex, 0)`)
### BPF_MAP_TYPE_DEVMAP
 - Represents a BPF map type (`struct bpf_map_def`).
 - Stores mappings from key to value where keys are network device indices (`int`).
### bpf_redirect
 - Redirects packets to a specified network device index (`ifindex`).
 - Signals the `XDP` program to forward the packet to the specified network interface.
### bpf_fib_lookup
 - Performs a routing table lookup (`FIB`) to determine the output `interface` and `MAC address` for a given `destination IP` address.
 - Takes a `struct bpf_fib_lookup` containing IP addresses (**ipv4_src, ipv4_dst**) and other routing details. 
 - Returns success or error codes (**BPF_FIB_LKUP_RET_SUCCESS** or **BPF_FIB_LKUP_RET_NO_NEIGH**).       

## Environment Setup
In this setup we will create two network namespaces, and create two veth-pair, one is to communicate with the host machine from the created network namespace (for example `ns1`) and other one is to communicate between the created network namespaces (for example `ns1` and `ns2`).

**Note**: you must be on this `packet-processing-xdp/packet-processing-03-redirecting` directory to use the `Makefile` for environment setup

### Setup Overview

![setup-overview](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-03-redirecting/images/environment-setup.png)

In this figure you can see that there is no direct route to the `ns2` from the `host` or `root` network namespace.

Default setup uses following `default_arguments`
```
VETH0 = veth-h-1
VETH1 = veth-ns1-1
VETH2 = veth-ns1-2
VETH3 = veth-ns2-1

NODE1 = ns1
NODE2 = ns2

NETWORK = 192.168.1.0/24

IP0 = 192.168.0.3/24

IP1 = 192.168.0.2/24
IP1-INET = 192.168.0.2

IP2 = 192.168.1.4/24
IP2-INET = 192.168.1.4

IP3 = 192.168.1.5/24

```

#### Build the whole environment setup
```
make build
```
#### To enter into the network namespace `ns1`
```
make exec_ns1
```
#### To enter into the network namespace `ns2`
```
make exec_ns2
```
#### Clean the whole environment setup
```
make clean
```
## Demonstration 

The provided code defines an XDP (eXpress Data Path) program that processes network packets and uses an eBPF (Extended Berkeley Packet Filter) map called tx_port to redirect packets to different interfaces.

The main function, xdp_redirect, starts by validating packet boundaries and checking if the packet is IPv4. If it is an ICMP (Internet Control Message Protocol) packet, the program prepares a FIB (Forwarding Information Base) lookup structure to route the packet back to its source.

The lookup result determines whether the packet should be dropped, passed, or redirected. If successful, the program swaps the source and destination IP addresses, updates the Ethernet header with new MAC addresses from the FIB lookup, and redirects the packet using the tx_port map to the appropriate interface.

Let's try on your own how it works :

Firtly you have to navigate to `packet-processing-xdp/packet-processing-03-redirecting/user-space-code` this directory. Now You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `xdp-redirect`
```
go build
```
4. Go to this `packet-processing-xdp/packet-processing-03-redirecting/` directory and  enter into the network namespace `ns1`
```
make exec_ns1packet-processing-xdp/packet-processing-03-redirecting/
```
5. Now go to this `packet-processing-xdp/packet-processing-03-redirecting/user-space-code` directory from the network namespace `ns1` and

   run the binary with `sudo` privileges. This requires a argument `-iface <interface name>`.
```
sudo ./xdp-redirect -iface veth-ns1-1
```

### Testing result
 - Before Attaching xdp program
```
ping 192.168.1.5
```
![can't-ping-to-ns2-from-host](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-03-redirecting/images/can't-ping.png)

 - Attach the program

![attach-program-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-03-redirecting/images/attach_program.png)

 - After attached xdp program to the `veth-ns1-1` 

![can-ping-to-ns2-from-host](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-03-redirecting/images/can-ping.png)