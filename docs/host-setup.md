# SETUP Host Machine (UBUNTU Based)
## Table of contents
- [Install one by one](#install-necessary-packages)
- [Install all at a time](#install-all)
## Install Necessary Packages
- First update your linux package index
```
sudo apt-get update
```
Then install the following packages :


- `clang` compiler for compiling eBPF programs
```
sudo apt-get install -y clang
```
- `llvm` provides libraries and tools for manipulating intermediate code, used by clang.
```
sudo apt-get install -y llvm
```
- `libelf-dev` helps in working with **ELF** (Executable and Linkable Format) files, which are used for eBPF bytecode.
```
sudo apt-get install -y libelf-dev
```
- `libbpf-dev` library for loading and interacting with eBPF programs.
```
sudo apt-get install -y libbpf-dev
```
- `libpcap-dev` provides functions for network packet capture, useful for testing and debugging.
```
sudo apt-get install -y libpcap-dev
```
- `gcc-multilib` allows compiling programs for both 32-bits and 64-bits architechtures.
```
sudo apt-get install -y gcc-multilib
```
- `build-essential` package that includes essential tools for compiling software (like gcc,make).
```
sudo apt-get install -y build-essential
```
- `linux-tools-common` provides common tools for kernel developers.
```
sudo apt-get install -y linux-tools-common
```
- `linux-headers-$(uname -r)` kernel headers specific to your sudoning kernel version, needed for compiling kernel modules.
```
sudo apt-get install -y linux-headers-$(uname -r)
```
- `linux-tools-$(uname -r)` tools specific to your sudoning kernel version, useful for performance monitoring.
```
sudo apt-get install -y linux-tools-$(uname -r)
```
- `linux-headers-generic` generic kernel headers, useful for compiling kernel modules across different kernel versions.
```
sudo apt-get install -y linux-headers-generic
```
- `linux-tools-generic` generic tools for various kernel versions, useful for performance and debugging.
```
sudo apt-get install -y linux-tools-generic
```
- `iproute2` collection of utilities for network configuration and management.
```
sudo apt-get install -y iproute2
```
- `iputils-ping` provides the ping utility for testing network connectivity.
```
sudo apt-get install -y iputils-ping
```
- `dwarves` contains tools like `pahole` to inspect the structure of compiled programs.
```
sudo apt-get install -y dwarves
```
- `tcpdump` a packet analyzer that allows you to capture and display network packets.
```
sudo apt-get install -y tcpdump
```
- `bind9-dnsutils` provides tools for **DNS** querying and testing. (nslookup, dig like tools)
```
sudo apt-get install -y bind9-dnsutils
```
## Install All
```
sudo apt-get update 

sudo apt-get install -y clang llvm libelf-dev libbpf-dev libpcap-dev gcc-multilib build-essential linux-tools-common

sudo apt-get install -y linux-headers-$(uname -r) linux-tools-$(uname -r) linux-headers-generic linux-tools-generic

sudo apt-get install -y iproute2 iputils-ping dwarves tcpdump bind9-dnsutils
```
