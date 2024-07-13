# Task-04 (parsing icmp-header and take action with sequence number)

## Introduction

To access the sequence number we have to look up the structure of the `ICMP` packets for `IPv4` and `IPv6`.

For IPv4 the structure of ICMP packets

```
struct icmphdr {
  __u8		type;
  __u8		code;
  __sum16	checksum;
  union {
	struct {
		__be16	id;
		__be16	sequence;
	} echo;
	__be32	gateway;
	struct {
		__be16	__unused;
		__be16	mtu;
	} frag;
	__u8	reserved[4];
  } un;
};
```
For IPv6 the structure of ICMP packets

```
struct icmp6hdr {
    __u8    icmp6_type;   // Type of the ICMPv6 message
    __u8    icmp6_code;   // Code for the ICMPv6 message
    __sum16 icmp6_cksum;  // Checksum of the ICMPv6 message

    union {
        struct {
            __be16  identifier;  // Identifier for Echo Request/Reply
            __be16  sequence;    // Sequence number for Echo Request/Reply
        } u_echo;
    } icmp6_dataun;

};
```
## Demonstration

This code implements an `XDP` (eXpress Data Path) program for parsing and filtering `ICMP` packets in both `IPv4` and `IPv6` networks. The program examines incoming network packets, parsing their headers layer by layer (Ethernet, IP, and ICMP). For `IPv4` packets, it drops **odd-sequenced** `ICMP` packets and passes **even-sequenced** ones. Conversely, for `IPv6` packets, it drops **even-sequenced** `ICMPv6` packets and passes **odd-sequenced** ones. The code uses inline functions to parse each header type, ensuring proper bounds checking to prevent buffer overflows. It employs `BPF` (Berkeley Packet Filter) helper functions for operations like byte order conversion and logging.

### Packet Flow

![packet-flow](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/parsing-ICMP-headers/images/packet-flow.png)


Firstly you have to navigate to `tasks/parsing-ICMP-headers/user-space-code` this directory. After doing all the necessary steps from the prerequisite. You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `xdp-icmp-parsing`
```
go build
```
4. Run the binary with `sudo` privileges. It will attach the xdp program to the `loopback` interface
```
sudo ./xdp-icmp-parsing
```
###  Testing

- For IPv4 packets

![IPv4-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/parsing-ICMP-headers/images/ipv4-logs.png)

- For IPv6 packets

![IPv6-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/parsing-ICMP-headers/images/ipv6-logs.png)