# Task-03 (parsing ip-header)

## Introduction 

First talk about the packet structure. THe packet structure shown below is the structure of a normal packet (without VLAN support). The `Ip Header` can have different size based on the type of the `Ip Header`. If the header is a `IPv6` packets Ip Header then it will have a fixed size. On the other hand if the header is of `IPv4` then it will have variable size.So, Firstly we have to verify that the iphdr struct itself fits in the packet payload, then compute the actual header size as `hdrsize = iph->ihl * 4`, and finally verify that this full size fits in the packet (and adjust the nexthdr pointer accordingly).

```
| Destination MAC | Source MAC  | EtherType | IP Header | Payload |
| 6 bytes         | 6 bytes     | 2 bytes   | 20+ bytes | ...     |
```

For IPv4

```
static __always_inline int parse_iphdr(struct hdr_cursor *hdr_p, void *data_end, struct iphdr **iphdr) {
        struct iphdr *iph = hdr_p->pos;
        int hdr_size = sizeof(*iph);
        
        if(hdr_p->pos + hdr_size > data_end){
            return -1;
        }

        if(iph->ihl*4 < hdr_size) {
            return -1;
        }

        hdr_p->pos += hdr_size;
        *iphdr = iph;

        return iph->protocol;
}
```

For IPv6

```
static __always_inline int parse_ip6hdr(struct hdr_cursor *hdr_p, void *data_end, struct ipv6hdr **ip6hdr){
        struct ipv6hdr *ip6h = hdr_p->pos;
        int hdr_size = sizeof(*ip6h);

        if(hdr_p->pos + hdr_size > data_end){
            return -1;
        }

        hdr_p->pos += hdr_size;
        *ip6hdr = ip6h;

        return ip6h->nexthdr;
}

```
## Demonstration


### Packet Flow

![packet-flow](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/parsing-ip-header/images/packet-flow.png)


Firstly you have to navigate to `tasks/parsing-ip-header/user-space-code` this directory. After doing all the necessary steps from the prerequisite. You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `xdp-parse-ip-header`
```
go build
```
4. Run the binary with `sudo` privileges. It will attach the xdp program to the `loopback` interface
```
sudo ./xdp-parse-ip-header
```
###  Testing
- Start the program

![attaching-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/parsing-ip-header/images/start-logs.png)

- For IPv4 packets

![IPv4-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/parsing-ip-header/images/ipv4-logs.png)

- For IPv6 packets

![IPv6-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/parsing-ip-header/images/ipv6-logs.png)