# Task-06 (removing outermost vlan tags)
 
 
## Prerequisite
 - [How VLAN works and see the packet structure](https://github.com/REZ-OAN/xdp-tutorials/blob/main/docs/vlan-working.md)
## Introduction
Now that you have come this far, you know how to parse the vlan tags data from the packets. Now in this task we are going to remove the outer-most vlan tags from the packet. You can setup the environment like in the task [adding-vlan-support](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/adding-vlan-support) describes. But you have to keep in mind that to use the Makefile you have to be on this `tasks/remove-outermost-VLAN-tag` directory.

## How to move the pointer on ctx
The `bpf_xdp_adjust_head` function is used to adjust the packet's data pointer, effectively modifying the beginning of the packet. In this specific call, it is used to remove the VLAN header from the packet.
```
bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh))
```
## Demonstration 
In this environment we are gonna send vlan packets from the `ns2` network namespace to `ns1`. In `ns1` on `veth0` a xdp program is attached which is responsible for removing the outer-most vlan tags from the incomming packets.

![packet-flow](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/remove-outermost-VLAN-tag/images/packet-flow.png)

Let's try on your own how it works :

Firtly you have to navigate to `tasks/remove-outermost-VLAN-tag/user-space-code` this directory. Now You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `xdp-remove-outer-most-vlan-tags`
```
go build
```
4. Go to this `tasks/remove-outermost-VLAN-tag` directory and  enter into the network namespace `ns1`
```
make exec_ns1
```
5. Now go to this `tasks/remove-outermost-VLAN-tag/user-space-code` directory from the network namespace `ns1` and

   run the binary with `sudo` privileges. This requires a argument `-iface <interface name>`.
```
sudo ./xdp-remove-outer-most-vlan-tags -iface veth0
```

### Testing result
 - Open four terminal windows and go to this directory  `tasks/remove-outermost-VLAN-tag` on three of the terminals. And do the followings :
    - In first terminal

    ```
    make exec_ns2
    ```
    - In second terminal

    ```
    make exec_ns1
    ``` 
    - In third terminal

    ```
    make exec_ns2
    ```
    - In fourth terminal

    ```
    sudo bpftool prog tracelog
    ```
- In the second terminal analyzing the incomming and outgoing packets using `tcpdump`

```
sudo tcpdump -i veth0 -vv
```
- In the third terminal analyzing the incomming and outgoing packets using `tcpdump`

```
sudo tcpdump -i veth1 -vv
```
- Now ping from the first termnal 
    - To `veth0.100` send IPv4 packets

        ```
        ping -c 3 -I veth1.100 192.168.89.3
        ```
    ![ping-to-veth0.100-ipv4](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/remove-outermost-VLAN-tag/images/ipv4-test.png)

    - To `veth0` send IPv4 packets

        ```
        ping -c 3 -I veth1.100 192.168.5.3
        ```
    ![ping-to-veth0-ipv4](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/remove-outermost-VLAN-tag/images/ipv4-to-veth0.png)

    - To `ns1` send IPv6 packets    

        ```
        ping6 -c 3 -I veth1.100 fe80::1c49::4ff::fe16::d5a8
        ```

    ![ping-to-ns1-ipv6](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/remove-outermost-VLAN-tag/images/ipv6-test.png)

The IPv6 and IPv4 ip-addresses can be found using `ip addr show` when you are in the `ns1` network namespace.