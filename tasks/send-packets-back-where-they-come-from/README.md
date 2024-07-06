# SEND-PACKETS Back where they come from (src)

## Introduction
Now that you have come this far, you know how to parse packet data, know how to rewrite packets. we can improve it to also correctly swap the ip and mac, as an example of how to redirect packets when comes to an interface.

## Defining common icmpheader struct 
We don't need the full struct of the icmp header for IPv4 or IPv6. There are some common part we need only those. So we declare icmphdr_common:
```
struct icmphdr_common {
	__u8		type;
	__u8		code;
	__sum16	cksum;
};
```

## Environment Setup
In this setup we will create one network namespace, and create one veth-peer. The veth-peer is to communicate between the created network namespace and the `root` namespace (for example `test-ns` to `root-ns`).


**Note**: you must be on this `tasks/send-packets-back-where-they-come-from` directory to use the `Makefile` for environment setup

### Setup Overview

![setup-overview](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/send-packets-back-where-they-come-from/images/setup.png)

Default setup uses following `default_arguments`
```
NS_NAME = test-ns
VETH_HOST = veth-h
VETH_NS = veth-ns
IP_HOST = 192.168.0.2/16
IP_NS = 192.168.0.4/16

```

#### Creating the namespace
```
make create_ns
```
#### Creating the veth-peer connection
```
make create_veth
```
#### To enter into the network namespace `test-ns`
```
make exec_ns
```
#### Clean the whole environment setup
```
make clean
```
## Demonstration 

Provided XDP program parses necessary headers, all the helper functions defining the program. Then if it is an ICMP paket it swaps the source and destination ip address and also swaps the source and destination mac address. 

![pacekt-flow](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/send-packets-back-where-they-come-from/images/packet-flow.png)

Let's try on your own how it works :

Firtly you have to navigate to `tasks/send-packets-back-where-they-come-from/user-space-code` this directory. Now You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `xdp-send-back`
```
go build
```
4. Go to this `tasks/send-packets-back-where-they-come-from/` directory and  enter into the network namespace `test-ns`
```
make exec_ns
```
5. Now go to this `tasks/send-packets-back-where-they-come-from/user-space-code` directory from the network namespace `test-ns` and

   run the binary with `sudo` privileges. This requires a argument `-iface <interface name>`.
```
sudo ./xdp-send-back -iface veth-ns
```

### Testing result

- ping IPv4 ICMP packets from `root-ns`

```
ping -i veth-h 192.168.0.4
```
![pinging-ipv4-icmp](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/send-packets-back-where-they-come-from/images/ipv4-packet.png)

- ping IPv6 ICMP packets from `root-ns` 

```
ping6 -i veth-h <ip-address ipv6>
```

![pinging-ipv6-icmp](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/send-packets-back-where-they-come-from/images/ipv6-packet.png)