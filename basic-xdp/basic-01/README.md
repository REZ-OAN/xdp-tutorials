# Basic-01 (Learn loading, attaching, detaching of a Simple XDP program)

## Prerequisite
 - [Create Environment](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/Environment-Setup/README.md)

## Compilation of xdp programs
Navigate to `basic-xdp/basic-01/xdp-kernel-space-code` directory then execute following command on your terminal :
```
clang -O2 -target bpf -g -c xdp_prog.c -o xdp_prog.o
```
The command compiles the `xdp_prog.c` source file into an object file `xdp_prog.o` in that directory which is optimized for eBPF:

- **clang**: The compiler used.
- **-O2**: Optimization level 2, for better performance.
- **-target bpf**: Specifies the target architecture as eBPF.
- **-g**: Includes debugging information.
- **-c**: Compiles the source file without linking.

![compilation_logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-01/images/compilation.png)

## Looking into the BPF-ELF object
Navigate to `basic-xdp/basic-01/xdp-kernel-space-code` directory then execute following command on your terminal :
```
llvm-objdump -S xdp_prog.o
```
The command disassembles the object file `xdp_prog.o` to show the human-readable assembly code:

- **llvm-objdump**: The tool used for disassembling.
- **-S**: Option to show the source code intermixed with the assembly code.

![object-dump-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-01/images/object-dump.png)

## Loading XDP object files
As you should understand by now, the BPF byte code is stored in an **ELF** file. To load `BPF` byte code from an ELF file into the kernel, you need an ELF loader. The `libbpf` library provides this, plus BPF helper functions, supporting BPF Type Format (`BTF`) and [CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/) relocation. `libxdp` builds on `libbpf` for managing XDP programs and **AF_XDP** sockets.

The tutorial's example shows how to write a **GO** program to load and attach an XDP program from `xdp_prog.o` to a network device. While this approach helps integrate BPF into other projects, you can also use tools like `iproute2` or `xdp-loader` from **xdp-tools**.
## Packet Flow of Implemented `xdp_prog`

![pacekt-flow](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-01/images/packet-flow.png)
## Load-Attach-Detach Using GO
Firtly you have to navigate to `basic-xdp/basic-01/xdp-user-space-code` this directory

Then follow the procedure:
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
![go_generate_logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-01/images/go-generate-logs.png)

3. Build the go binary. It will generate a file in the same directory called xdp-pass
```
go build
```
4. Now run the binary with `-iface <interface name>` with `sudo` privileges
```
sudo ./xdp-pass -iface veth-h
```
**Note**: I have used `veth-h` as interface name. Because I am working on the `default` environment setup.

![load-attach-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-01/images/main-prog-start.png)

### Inspecting what's happening
Navigate to `basic-xdp/Environment-Setup` this directory and then do the followings :
1. Enter into the network namespace `test-ns`
```
make exec_ns
```
2. Now open another terminal and execute 
```
sudo bpftools prog tracelogs
```
3. Now go to the terminal where you have enter to the network namespace. And then `ping 192.168.0.2`

![ping-logs-with-tracing](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-01/images/testwith-tracelogs.png)

4. Now terminate the running go program by pressing `ctrl+c` 

![terminate-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-01/images/termination-of-program.png)

## Load-Attach-Detach Using iproute2 
**Iproute2** provides `libbpf` based BPF loading capability that can be used with the standard ip tool; so in this case you can actually load and attach our ELF-file xdp_prog.o (where we named our ELF section “xdp”) like this. Navigate to `basic-xdp/basic-01/xdp-kernel-space-code` and execute following command:
```
sudo ip link set dev veth-h xdpgeneric obj xdp_prog.o sec xdp
```
To verify that the `XDP` program is attached or not you can verify with following command:
```
sudo ip link show dev veth-h
```
You will get the output like below
```
6: veth-h@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 46:67:e1:9e:2a:93 brd ff:ff:ff:ff:ff:ff link-netns test-ns
    prog/xdp id 85 name xdp_prog_main tag 332626fdca672360 jited  
```
Now you can test with the enviroment setup. And trace for the logs after pinging.

To detach the `XDP` program from the interface `veth-h`. You need to execute following command :

```
sudo ip link set dev veth-h xdpgeneric off
```
To verify `XDP` program detached or not. Again execute the following command
```
sudo ip link show dev veth-h
```
You will get the output like below
```
6: veth-h@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 46:67:e1:9e:2a:93 brd ff:ff:ff:ff:ff:ff link-netns test-ns
```
## Load-Attach-Detach Using xdp-loader
The `xdp-tools` project provides the **xdp-loader** tool which has commands for loading, unloading and showing the status of loaded XDP programs.

We can load our `xdp_prog.o` program and attach it using the XDP **multi-dispatch** protocol like this:
```
sudo xdp-loader load -m skb veth-h xdp_prog.o
```
We can show the status of the XDP programs attached to the device:
```
sudo xdp-loader status lo
```
You will get output like below
```
CURRENT XDP PROGRAM STATUS:

Interface        Prio  Program name      Mode     ID   Tag               Chain actions
--------------------------------------------------------------------------------------
veth-h                 xdp_dispatcher    skb      96   4d7e87c0d30db711 
 =>              50     xdp_prog_main             105  332626fdca672360  XDP_PASS
```
To detach the program. Execute the following command
```
sudo xdp-loader unload veth-h --all
``` 