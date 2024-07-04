# Adding VLAN support while Parsing eth_hdr

## Table of contents
 - [Prerequisite](#prerequisite)
 - [Introduction](#introduction)
 - [Creation of VLANS and Hardware Offloading](#creation-of-vlans-and-hardware-offloading)
 - [Why before the kernel assigns?](#why-before-the-kernel-assigns)
 - [Defining VLAN header struct](#defining-vlan-header-struct)
 - [`ether_type` of a VLAN tag](#ether_type-of-a-vlan-tag)
 - [Environment Setup](#environment-setup)
 - [Demonstration](#demonstration)
 
## Prerequisite
 - [How VLAN works](https://github.com/REZ-OAN/xdp-tutorials/blob/main/docs/vlan-working.md)
## Introduction
Now that you have come this far, you know how to parse packet data, and how to modify packets. we can improve it to also correctly handle VLAN tags on the Ethernet packets, as an example of how to parse multiple variable headers depending on the payload.

## Creation of VLANS and Hardware Offloading
In Linux, VLANs are configured by creating virtual interfaces of type vlan; but since the XDP program runs directly on the real interface, it will see all packets with their VLAN tags, before the kernel assigns them to the virtual VLAN interfaces.

To create a virtual interface of type vlan :
```
 ip link add link <interface_name> name <vlan_inteerface_name> type vlan id <vlan_id>
```
### Why before the kernel assigns?
When kernel assigns the vlan packets to the virtual VLAN interfaces it removes the VLAN tags from the packet header. So it is important to turn off VLAN hardware offloading(which most of the hardware NICs support).

To turn off the hardware offloading use below command.
```
ethtool --offload <interface_name> rxvlan off txvlan off
```
## Defining VLAN header struct 
Unfortunately, the VLAN tag header is not exported by any of the IP header files. However, it is quite simple, so we can just define it ourselves, like this (copied from the internal kernel headers):
```
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};
```
## `ether_type` of a VLAN tag 
The ethertype of a VLAN tag is either `ETH_P_8021Q` or `ETH_P_8021AD`, both of which are defined in `if_ether`. So we can define a simple helper function to check if a VLAN tag is present:
```
static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}
```
## Handling Nested VLAN tags
Another thing to bear in mind is that a single packet can have several nested VLAN tags. We can handle this by using an unrolled loop to parse subsequent VLAN headers, as long as their encapsulated protocol continues to be on of the VLAN types. By default xdp_programs are restricted to use loops in the program, but if we know the no of iteration in the compile time then we can use the loop placing `#pragma unroll` before writing the loop.
```
int i=0;
#pragma unroll
for (; i<5; i++ ) {

}
```
## Environment Setup
In this setup we will create two network namespaces, and create one veth-peer. The veth-peer is to communicate between the created network namespaces (for example `ns1` and `ns2`). And also the veth-peer will give the virtual interfaces to create the VLANs.


**Note**: you must be on this `tasks/adding-vlan-support` directory to use the `Makefile` for environment setup

### Setup Overview

![setup-overview](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/adding-vlan-support/images/environment-setup.png)

Default setup uses following `default_arguments`
```
NS1 = ns1
NS2 = ns2
VETH0 = veth0
VETH1 = veth1
VETH0_VLAN = veth0.100
VETH1_VLAN = veth1.100
NS1_IP = 192.168.5.3/24
NS2_IP = 192.168.5.6/24
NS1_VLAN_IP = 192.168.89.3/24
NS2_VLAN_IP = 192.168.89.32/24

```

#### Build the whole environment setup
```
make setup
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

Provided XDP program parses Ethernet frames, handles VLAN tags, and identifies whether the packet is IPv4, IPv6, or ARP. Based on the packet type, it either logs information about the packet or drops it.


Let's try on your own how it works :

Firtly you have to navigate to `tasks/adding-vlan-support/user-space-code` this directory. Now You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `xdp-vlan-parsing`
```
go build
```
4. Go to this `tasks/adding-vlan-support` directory and  enter into the network namespace `ns1`
```
make exec_ns1
```
5. Now go to this `tasks/adding-vlan-support/user-space-code` directory from the network namespace `ns1` and

   run the binary with `sudo` privileges. This requires a argument `-iface <interface name>`.
```
sudo ./xdp-vlan-parsing -iface veth-ns1-1
```

### Testing result
 - Attach the program

![attach-program-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/adding-vlan-support/images/attached-xdp-into-ns1.png)

 - Open another terminal and go to this directory  `tasks/adding-vlan-support/`. And enter into `ns1` using following command.

    ```
    make exec_ns1
    ```
    - Now you have to get the IPv4 and IPv6 address of the `veth0.100` and `veth0`. To get those you have to execute the following command while you are in `ns1`.
        ```
            ip addr show
        ```
![ip-address-overview](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/adding-vlan-support/images/get-ip-addresses.png)
 - Now open two terminal side by side.
    - In one terminal enter into `ns2`. Using the following command
    ```
        sudo ip netns exec ns2 bash
    ```
    - In the another trace the xdp program logs using the `bpftool`
    ```
        sudo bpftool prog tracelog 
    ```
On the terminal you have entered into `ns2` do the followings :
 - PING IPv4 packets to `veth0`
![ping-logs-ipv4-veth0](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/adding-vlan-support/images/pingipv4toveth0.png)

 - PING IPv6 packets to `veth0`
![ping-logs-ipv6-veth0](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/adding-vlan-support/images/pingipv6toveth0.png)

 - PING IPv4 packets to `veth0.100`
![ping-logs-ipv4-veth0.100](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/adding-vlan-support/images/pingIpv4toveth0.100.png)

 - PING IPv6 packets to `veth0.100`
![ping-logs-ipv6-veth0.100](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/adding-vlan-support/images/pingivp6toveth0.100.png)

