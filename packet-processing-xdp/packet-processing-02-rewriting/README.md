# Packet-Processing-02 (Learn rewrite the packet by changing ports)

## Table of contents
 - [Introduction](#introduction)
 - [Layout of an IP network packet](#layout-of-an-ip-network-packet)
 - [Demonstration](#demonstration)

## Introduction
In packet-processing-01, you've mastered packet parsing by learning to structure it effectively, ensuring proper bounds checking to access packet data safely, and using return codes to determine the packet's outcome. Building on this foundation, the next lesson demonstrates how to effectively modify packet contents.

## Layout of an IP network packet
Layout of an IP network packet, starting with an Ethernet header, followed
by an IP header, and then the Layer 4 data :

![ip-network-packet-layout](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-02-rewriting/images/packet-data.png)
## Demonstration 
This **eBPF** program intercepts and modifies packets at the `XDP` layer based on Ethernet and IP header information. It demonstrates how eBPF can be used for inline packet processing, manipulating **UDP** and **TCP** headers in-flight while ensuring robust error handling and checksum validation.
Mainly we are manipulating the **UDP** and **TCP** headers :
- If the IP protocol is UDP (`IPPROTO_UDP`), it parses the UDP header (**udphdr**), adjusts the destination port (udphdr->dest) and recalculates the checksum (udphdr->check) using `bpf_csum_diff` and `csum_fold_helper`.
- If the IP protocol is TCP (`IPPROTO_TCP`), it parses the TCP header (**tcphdr**), adjusts the destination port (tcphdr->dest) and increments the checksum (tcphdr->check).

Adjusting the destination port, actually we are **decreasing** the `port` by `1`.

Let's try on your own how it works :

Firtly you have to navigate to `packet-processing-xdp/packet-processing-02-rewriting/user-space-code` this directory. Now You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `packet-rewriting`
```
go build
```
4. Run the binary with `sudo` privileges
```
sudo ./packet-rewriting
```
By default it will attach the `XDP` program to the `lo` interface of the host machine.

### Testing result
- Start the program

![initial-logs-starting](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-02-rewriting/images/starting-logs.png)

- Tracing 
Execute the following command in a terminal. This will send `tcp` packets to the `lo` interface
```
echo "test" | socat - TCP4:127.0.0.1:2000
```
In the another terminal execute the following command to analyze the packets :
```
sudo tcpdump -i lo tcp -vv
```
![tcp-packets](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-02-rewriting/images/tcp-packet.png)

For the `UDP` packets use following command :
```
socat - UDP4-DATAGRAM:127.0.0.1:2000

```
And write something on the terminal.

In the another terminal execute the following command to analyze the packets :
```
sudo tcpdump -i lo udp -v
```
![udp-packets](https://github.com/REZ-OAN/xdp-tutorials/blob/main/packet-processing-xdp/packet-processing-02-rewriting/images/udp-packet.png)