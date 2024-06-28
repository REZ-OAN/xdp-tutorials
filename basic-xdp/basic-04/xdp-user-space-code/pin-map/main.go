package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp_map_counter ../../xdp-kernel-space-code/xdp_prog.c
var iface string

// to store the map and prog object
type Collect struct {
	Prog *ebpf.Program `ebpf:"xdp_map_counter"`
	Map  *ebpf.Map     `ebpf:"packet_counts"`
}

// to store the packet_info struct from the kernel space
type packetInfo struct {
	Count uint32
	Size  uint32
}

func main() {
	// if there is a pinned map created before remove it
	dirPath := "/sys/fs/bpf/test/globals/packet_counts"
	if err := os.Remove(dirPath); err != nil {
		fmt.Fprintf(os.Stderr, "[error] failed to delete map %s: %v\n", dirPath, err)
	} else {
		fmt.Printf("[success] map on this dir %s deleted\n", dirPath)
	}

	// taking the interface from the user
	flag.StringVar(&iface, "iface", "", "network interface to attach XDP program")
	flag.Parse()

	if iface == "" {
		fmt.Println("[error] network interface not specified")
		os.Exit(1)
	}

	// loading the object file of xdp_prog
	spec, err := loadXdp_map_counter()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] loading eBPF object: %v\n", err)
		os.Exit(1)
	}
	var collect = &Collect{}

	// loading the objects of prog and map
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		panic(err)
	}
	fmt.Printf("[success] successfully loaded XDP\n")

	// pin the map to a bpf mount dir
	mapPath := "/sys/fs/bpf/test/globals/packet_counts"
	if err := os.MkdirAll("/sys/fs/bpf/test/globals", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create directory: %v\n", err)
		os.Exit(1)
	}
	if err := collect.Map.Pin(mapPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to pin map: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[success] map pinned to %s\n", mapPath)

	// Initialize the map
	key := int64(0)
	packet := &packetInfo{Count: uint32(0), Size: uint32(0)}
	collect.Map.Update(unsafe.Pointer(&key), unsafe.Pointer(packet), ebpf.UpdateAny)

	fmt.Printf("[success] map initialized successfully\n")
	link, err := netlink.LinkByName(iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding network interface: %v\n", err)
		os.Exit(1)
	}

	if err := netlink.LinkSetXdpFdWithFlags(link, collect.Prog.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		panic(err)
	}
	fmt.Printf("[success] successfully attached XDP to interface %s\n", iface)

	defer func() {
		// Detach the XDP program when the program terminates
		netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE)
		fmt.Printf("[success] successfully detached XDP from interface %s\n", iface)

		// deleting the pinned map when the program crashes or terminates
		dirPath := "/sys/fs/bpf/test/globals/packet_counts"
		if err := os.Remove(dirPath); err != nil {
			fmt.Fprintf(os.Stderr, "[error] failed to delete map %s: %v\n", dirPath, err)
		} else {
			fmt.Printf("[success] map on this dir %s deleted\n", dirPath)
		}
	}()

	// Handle Ctrl+C signal for clean detachment
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	<-sig
}
