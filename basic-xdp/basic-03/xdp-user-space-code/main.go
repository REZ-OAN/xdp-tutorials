package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp_map_counter ../xdp-kernel-space-code/xdp_prog.c

var iface string

// to store the map and prog object
type Collect struct {
	Prog *ebpf.Program `ebpf:"xdp_map_counter"`
	Map  *ebpf.Map     `ebpf:"packet_counts"`
}

func main() {
	flag.StringVar(&iface, "iface", "", "network interface to attach XDP program")
	flag.Parse()

	if iface == "" {
		fmt.Println("[error] network interface not specified")
		os.Exit(1)
	}

	spec, err := loadXdp_map_counter()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] loading eBPF object: %v\n", err)
		os.Exit(1)
	}
	var collect = &Collect{}
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		panic(err)
	}
	fmt.Printf("[success] successfully loaded XDP\n")
	// for key
	key := int64(0)
	// for value
	count := uint32(0)

	// initializing for RECIEVED PACKET COUNT
	collect.Map.Update(unsafe.Pointer(&key), unsafe.Pointer(&count), ebpf.UpdateAny)

	fmt.Printf("[success] map initialized successfully\n")

	link, err := netlink.LinkByName(iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding network interface: %v\n", err)
		os.Exit(1)
	}

	if err := netlink.LinkSetXdpFdWithFlags(link, collect.Prog.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		panic(err)
	}
	fmt.Printf("[success] successfully attached XDP\n")

	defer func() {
		// go routine to detach the XDP program, when go program crashes or terminated
		netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE)
		fmt.Printf("[success] successfully dettached XDP\n")
	}()

	// Handle Ctrl+C signal for clean detachment
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to periodically display counts
	go func() {
		ticker := time.NewTicker(5 * time.Second) // Adjust interval as needed
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Printf("[info] displaying the map contents\n")
				key := int64(0)
				count := uint32(0)
				collect.Map.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&count))
				fmt.Printf("[info] total packet recieved %d\n", count)
			case <-sig:
				return
			}
		}
	}()
	<-sig
}
