# XDP Tutorials (Learn eXpress Data Path from scratch with Hands On Tutorial)

# Table of contents

 - [Host Setup](https://github.com/REZ-OAN/xdp-tutorials/blob/main/docs/host-setup.md)
 - [Introduction](#introduction)
 - [Why XDP and What problems does it solves](#why-xdp-and-what-problems-does-it-solves)
 - [Attaching Approaches of XDP](#attaching-approaches-of-xdp-programs)
 - [Operation of XDP](#operations-of-xdp-programs)
 - [Hands On Tutorials]()
 - [References]()

# Introduction 

## **eBPF** (Extended Berkeley Packet Filter)
It is a technology in the linux kernel that allows running custom code in response to various system events.

Some of the applications of this tech 
- **Network Monitoring** 
Analyze network traffic without delay in processing.
- **Security**
Implement custom security policies to detect anomalies.
- **Performance Profiling**
Collect performance metrics and trace system calls.

It allows deep inspection and modification of the system behaviour with minimal overhead, enchancing security, performance and observability.

## **XDP** (eXpress Data Path)
A feature of `eBPF` focused on high-performance packet processing at the network interface level.

Some of the applications of this feature
- **DDOS Protection**
Drop malicious traffic before it reaches the operating system.
- **Load Balancing**
Distribute network traffic efficiently across multiple servers.
- **Packet Filtering**
Apply custom filtering rules at the earliest point in the network stack.

It offers extremely fast packet processing capabilities, reducing latency and improving throughput.

# Why XDP and What problems does it solves

In traditional way to packet processing is to **kernel bypass**. This technique allows applications to directly access hardware resources, such as network interface cards (NICs), without involving the operating system kernel. 

How kernel bypass works?
- Traditional networking involves multiple steps through the kernel (e.g., **context switches**, **network stack** processing, and **interrupts**).
- With kernel bypass, applications or eBPF programs interact directly with the `NIC`, skipping these kernel steps.
This kernel bypass technique has some drawbacks. 
- eBPF programs need to write their own drivers and handle low-level hardware interactions. This creates extra works for the developers.
- Applications must implement network functions typically handled by the kernel, increasing development effort.

XDP can solve the upper drawbacks. XDP provides following advantages over the traditional technique :
- **Simplifies** high-performance networking with `eBPF`.
- Allows **direct** reading and writing of `network packet` data.
- Enables decision-making on packet processing before **kernel involvement**.
- XDP provides a framework that simplifies packet-processing, allowing developers to focus on the core functionality of their eBPF programs without dealing with **low-level** driver details.

# Attaching Approaches of XDP programs
**XDP** (eXpress Data Path) can be attached at specific points in the network stack to enable high-performance packet processing. Here are the places where you can attach **XDP** programs:

- **Network Interface Cards (NICs)**
    - **Driver Mode**: Attaches directly to the network driver, allowing packet processing at the earliest point possible, right after the packet is received by the NIC. In this approach it is called **native XDP**
    - **Hardware Offload**: Some NICs support offloading XDP programs to the hardware, which can further reduce latency and CPU usage. In this approach it is called **offloaded XDP**
- **Virtual Network Devices**
XDP can be attached to virtual network interfaces like `veth` pairs, `tap` devices, which are often used in container networking setups.
This allows for efficient packet processing in virtualized environments.
- **General Networking Stack**
XDP can be attached at the general network stack level, providing flexibility for packet processing without requiring specific hardware support. In this approach it is called **generic XDP**

![xdp-attach](https://github.com/REZ-OAN/xdp-tutorials/blob/main/images/xdp_packet_flow.png)

# Operations of XDP programs

XDP programs processes network packets. So, it performs some operations on the packets. Here are the fundamental operations of XDP program can perform with the packets it recieves, once it is connected to a network interface.

- **XDP_DROP**
    - Drops the packet and does not process it further.

**Use Case**: Analyzing traffic patterns and using filters to drop specific types of packets, such as malicious traffic.

- **XDP_PASS**
    - Forwards the packet to the normal network stack for further processing.

**Use Case**: The XDP program can modify the content of the packet before it is processed by the normal network stack.

- **XDP_TX**
    - Forwards the packet, possibly modified, to the same network interface that received it.

**Use Case**: Immediate retransmission or forwarding on the same interface.

- **XDP_REDIRECT**
    - Bypasses the normal network stack and redirects the packet to another network interface.

**Use Case**: Directing traffic to a different NIC without passing through the kernel’s network stack.


![xdp-operations](https://github.com/REZ-OAN/xdp-tutorials/blob/main/images/xdp-operations.png)

# Tutorials
- Basic-XDP
    - [Environment Setup](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/Environment-Setup)
    - [Basic-01-loading-attaching-detaching-xdp](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-01)
    - [Basic-02-selection-of-a-program](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-02)
    - [Basic-03-how-to-use-maps](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-03)
    - [Basic-04-pin-maps](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-04)

# References
- [xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)
- [Academic Paper](https://github.com/xdp-project/xdp-paper/blob/master/xdp-the-express-data-path.pdf)
- [Cilium BPF](https://docs.cilium.io/en/latest/bpf/)
- [Netdev Conference](https://www.netdevconf.org/0x13/session.html?tutorial-XDP-hands-on)