# Packet-Processing-01 (Learn Parsing Packets)

## Table of contents
 - [Introduction](#introduction)
 - [Definition of struct xdp_md](#definition-of-struct-xdp_md)
 - [Definition of stuct hdr_cursor](#definition-of-struct-hdr_cursor)
 - [Bound Checking](#bound-checking)
 - [Packet Header Definitions and Byte Order](#packet-header-definitions-and-byte-order)
 - [Function inlining](#function-inlining)
 - [Demonstration](#demonstration)

## Introduction
Now that you have completed the basic steps of the tutorial, you are ready to begin writing packet processing programs. In this lesson, you'll learn how to:
- Parse packet contents.
- Ensure your programs are accepted by the kernel verifier (Bound Checking).

## Definition of struct xdp_md
When an XDP program is executed, it will receive as a parameter a pointer to a struct `xdp_md` object, which contains context information about the packet. This object is defined in bpf.h as follows:
```
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index  */
};
```
The last two items in this struct are just data fields which contain the **ifindex** and **RX queue index** that the packet was received on. The program can use this in its decision making (along with the packet data itself).

The first three items are pointers, even though they use the `__u32` type. The data field points to the start of the packet, data_end points to the end, and data_meta points to the metadata area for extra information. In this lesson, we will focus on the data and data_end fields.
### Accessing Packet Data
```
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

```
## Definition of struct hdr_cursor
When parsing packet headers, it's important to track the current position. Helper functions that parse headers often need to update this position. Instead of using pointer arithmetic, we use a cursor object, which is a single-entry struct, to simplify this process. The cursor can be passed to helper functions to manage the parsing position.

Here is the definition of the struct hdr_cursor :
```
/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};
```
## Bound Checking
In `XDP` programs, direct memory reads are used to access packet data. The verifier ensures these accesses are safe by checking that the program performs its own bounds checking. The data_end pointer indicates the end of the packet, helping the verifier ensure safety.

At load time, the verifier performs static analysis, tracking memory address offsets and looking for comparisons with data_end. This ensures that any memory read within the packet data is within valid bounds, preventing out-of-bounds access.

For example, consider the following bounds check:
```
 void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct hdr_cursor hdr_p;
        
    // initialize with starting address
    hdr_p.pos = data;

    eth = hdr_p.pos;

    int hdr_size = sizeof(*eth);

    // bytes bound check 
    if(hdr_p->pos + hdr_size > data_end)
        return XDP_DROP;

    return XDP_PASS;
```
## Packet Header Definitions and Byte Order
An XDP program receives a pointer to a raw data buffer and must parse packet headers itself. The kernel headers provide structs for the packet header fields to assist with this. Parsing packets involves casting data buffers to the appropriate struct types. In this lesson, we will use the following header definitions:

| Struct Name   | Header File          |
|---------------|----------------------|
| `ethhdr`      | `<linux/if_ether.h>` |
| `ipv6hdr`     | `<linux/ipv6.h>`     |
| `iphdr`       | `<linux/ip.h>`       |
| `icmp6hdr`    | `<linux/icmpv6.h>`   |
| `icmphdr`     | `<linux/icmp.h>`     |

Since the packet data comes straight off the wire, the data fields will be in network byte order. Use the `bpf_ntohs()` and `bpf_htons()` functions to convert to and from host byte order, respectively.

## Function Inlining 
`eBPF` programs have limited support for function calls, so helper functions must be inlined into the main function. The `__always_inline` marker on the function definition ensures this, overriding the compiler's usual inlining decisions.

## Demonstration 
In the `kernel-space-code/xdp_prog.c` program parses the Ethernet header of incoming packets and checks if the packet is `IPv4` or `IPv6`. If it is either, the packet is passed to the next layer of the network stack (**XDP_PASS**). If the packet is of any other type, it is also passed to the next layer by default. The program does not currently take any other actions based on the packet content. 

Let's try on your own how it works :

Firtly you have to navigate to `packet-processing-xdp/packet-processing-01-parsing/user-space-code` this directory. Now You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `eth-hdr-parse`
```
go build
```
4. Run the binary with `sudo` privileges
```
sudo ./eth-hdr-parse
```
By default it will attach the `XDP` program to the `lo` interface of the host machine.

### Testing result
- Start the program

![initial-logs-starting](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-01-parsing/images/starting.png)

- Tracing 
Execute the following command in a terminal. This will send `IPv4` packets to the `lo` interface
```
ping 127.0.0.1
```
In the another terminal execute the following command :
```
sudo bpftool prog tracelog
```
![ping-IPv4](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-01-parsing/images/pingIPV4.png)

For the `IPv6` packets use following command :
```
ping -6 ::1
```
![ping-IPv6](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-01-parsing/images/pingIPV6.png)