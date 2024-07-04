package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp_prog ../kernel-space-code/xdp_prog.c

var iface string

// to store the program object
type Collect struct {
	Prog *ebpf.Program `ebpf:"xdp_add_vlan_tag"`
}

func main() {
	flag.StringVar(&iface, "iface", "", "network interface to attach XDP program")
	flag.Parse()

	if iface == "" {
		fmt.Println("[error] must give the interface name")
		os.Exit(1)
	}

	// loading the xdp_parser_func program object
	spec, err := loadXdp_prog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] loading eBPF object: %v\n", err)
		os.Exit(1)
	}
	var collect = &Collect{}

	// loading the object into the struct
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		panic(err)
	}
	fmt.Printf("[success] successfully loaded XDP\n")

	// getting the inerface link
	link, err := netlink.LinkByName(iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding network interface: %v\n", err)
		os.Exit(1)
	}

	// attach xdp program to the given interface
	if err := netlink.LinkSetXdpFdWithFlags(link, collect.Prog.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		panic(err)
	}
	fmt.Printf("[success] successfully attached XDP\n")

	defer func() {
		// go routine which will detach the XDP program if the program crashes or terminated
		netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE)
		fmt.Printf("[success] successfully dettached XDP\n")
	}()

	// Handle Ctrl+C signal for clean detachment
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
