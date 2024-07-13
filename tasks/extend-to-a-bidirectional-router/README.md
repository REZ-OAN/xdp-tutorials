# Task-09 (create a bidirectional router)

## Environment Setup

![environment-architechture](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/extend-to-a-bidirectional-router/images/environment-setup.png)

### Default Parameters

```
NS1_IP ?= 10.10.20.5
NS2_IP ?= 10.10.20.7
BRIDGE_IP ?= 10.10.20.19
NETMASK = 24
```
### Create Environment

```
make setup
```

### Clean Environment

```
make clean
```
### Enter Into Network Namespaces

```
make < exec_ns1 or exec_ns2 >
```

**Note:** To execute the `make` commands you have to be on this `tasks/extend-to-a-bidirectional-router` directory 

## Demonstration

This code implements an `XDP` (eXpress Data Path) program for packet processing and routing in Linux. It handles both `IPv4` and `ARP` packets, performing packet **redirection** and address translation based on a predefined map of `backend` servers. The program parses Ethernet, VLAN, IP, and ARP headers, and can construct `ARP` replies for incoming ARP requests. For `IPv4` packets, it modifies the source and destination MAC and IP addresses based on the information stored in the redirect_packets map. The code also includes extensive error checking and debugging output using `bpf_printk()`.

Let's try on your own how it works :

Firtly you have to navigate to `tasks/extend-to-a-bidirectional-router/user-space-code` this directory. Now You can proceed with following procedure :
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

4. Now go to this `tasks/extend-to-a-bidirectional-router/user-space-code` directory and run the binary with `sudo` privileges. This requires arguments
```
-src_ip <source ip address>
-dest_ip <destination ip address>
-src_mac <source mac address>
-dest_mac <destination mac address>
-src_id <source interface id>
-dest_id <destination interface id>
```

Run below command to attach the `xdp` program:

```
sudo ./xdp-redirect -iface test-br -src_ip 10.10.20.5 -dest_ip 10.10.20.7 -src_mac d2:01:ae:0d:ef:29 -dest_mac a6:a0:9b:98:6f:63 -src_id 6 -dest_id 8
```
## Testingtasks/extend-to-a-bidirectional-router/images/start-logs.png

- Starting The program

![start-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/extend-to-a-bidirectional-router/images/start-logs.png)

### Before Applying **TCPDUMP** on `test-br`

![before-tcpdump-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/extend-to-a-bidirectional-router/images/before-tcpdump-logs.png)

### After Applying **TCPDUMP** on `test-br`

![after-tcpdump-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/extend-to-a-bidirectional-router/images/after-tcpdump-logs.png)

## Testing without attaching the XDP program

![testing-without-attaching-xdp](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/extend-to-a-bidirectional-router/images/testing-withoutxdp.png)

## Testing with applying **TCPDUMP** first then attaching the XDP program

![tcpdump-first-xdp-attach-second](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/extend-to-a-bidirectional-router/images/ftcpdump-sxdp.png)