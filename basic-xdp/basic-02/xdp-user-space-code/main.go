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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp_prog_by_name ../xdp-kernel-space-code/xdp_prog.c

var iface string
var progName string

// defining a common interface to select the Program File Descriptor
type XdpProgramByName interface {
	FD() int
}

// struct for storing Prog object of xdp_prog_pass
type Collect_pass struct {
	Prog *ebpf.Program `ebpf:"xdp_prog_pass"`
}

// Prog.FD() for the xdp_prog_pass
func (c *Collect_pass) FD() int {
	return c.Prog.FD()
}

// struct for storing Prog object of xdp_prog_drop
type Collect_drop struct {
	Prog *ebpf.Program `ebpf:"xdp_prog_drop"`
}

// Prog.FD() for the xdp_prog_drop
func (c *Collect_drop) FD() int {
	return c.Prog.FD()
}

func main() {
	flag.StringVar(&iface, "iface", "", "network interface to attach XDP program")
	flag.StringVar(&progName, "prog", "xdp_pass", "XDP program to attach (xdp_pass or xdp_drop)")
	flag.Parse()

	if iface == "" {
		fmt.Println("[error] network interface not specified")
		os.Exit(1)
	}

	// loading the program
	spec, err := loadXdp_prog_by_name()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] loading eBPF object: %v\n", err)
		os.Exit(1)
	}
	var collect XdpProgramByName
	if progName == "xdp_pass" {
		c := &Collect_pass{}
		// loading the object file
		if err := spec.LoadAndAssign(c, nil); err != nil {
			panic(err)
		}
		collect = c
		fmt.Printf("[success] successfully loaded XDP_PASS\n")
	} else if progName == "xdp_drop" {
		c := &Collect_drop{}
		// loading the object file
		if err := spec.LoadAndAssign(c, nil); err != nil {
			panic(err)
		}
		collect = c
		fmt.Printf("[success] successfully loaded XDP_DROP\n")
	}

	// get the interface link
	link, err := netlink.LinkByName(iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding network interface: %v\n", err)
		os.Exit(1)
	}
	// attaching the XDP program to the interface
	if err := netlink.LinkSetXdpFdWithFlags(link, collect.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		panic(err)
	}
	fmt.Printf("[success] successfully attached XDP program: %s\n", progName)

	defer func() {
		// defining go routine to detach the XDP program when crashed or terminated
		if err := netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE); err != nil {
			fmt.Fprintf(os.Stderr, "[error] detaching XDP: %v\n", err)
		} else {
			fmt.Printf("[success] successfully detached XDP program: %s\n", progName)
		}
	}()

	// Handle Ctrl+C signal for clean detachment
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
