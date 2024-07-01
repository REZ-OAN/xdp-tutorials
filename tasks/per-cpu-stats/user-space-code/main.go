package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp_prog_by_name ../kernel-space-code/xdp_prog.c

var iface string
var progName string
var Key uint32

type Datarec struct {
	RxPackets uint64
	RxBytes   uint64
}

// XdpProgramByName interface to select the Program File Descriptor
type XdpProgramByName interface {
	FD() int
	MAP() *ebpf.Map
}

// CollectPass stores the Prog object of xdp_pass_func
type CollectPass struct {
	Prog *ebpf.Program `ebpf:"xdp_pass_func"`
	Map  *ebpf.Map     `ebpf:"xdp_stats_map"`
}

func (c *CollectPass) FD() int {
	return c.Prog.FD()
}

func (c *CollectPass) MAP() *ebpf.Map {
	return c.Map
}

// CollectDrop stores the Prog object of xdp_drop_func
type CollectDrop struct {
	Prog *ebpf.Program `ebpf:"xdp_drop_func"`
	Map  *ebpf.Map     `ebpf:"xdp_stats_map"`
}

func (c *CollectDrop) FD() int {
	return c.Prog.FD()
}

func (c *CollectDrop) MAP() *ebpf.Map {
	return c.Map
}

// CollectAbort stores the Prog object of xdp_abort_func
type CollectAbort struct {
	Prog *ebpf.Program `ebpf:"xdp_abort_func"`
	Map  *ebpf.Map     `ebpf:"xdp_stats_map"`
}

func (c *CollectAbort) FD() int {
	return c.Prog.FD()
}

func (c *CollectAbort) MAP() *ebpf.Map {
	return c.Map
}

func main() {
	flag.StringVar(&iface, "iface", "", "network interface to attach XDP program")
	flag.StringVar(&progName, "prog", "xdp_pass", "XDP program to attach (xdp_pass, xdp_drop, or xdp_abort)")
	flag.Parse()

	if iface == "" {
		fmt.Println("[error] network interface not specified")
		os.Exit(1)
	}

	// Load the program
	spec, err := loadXdp_prog_by_name()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] loading eBPF object: %v\n", err)
		os.Exit(1)
	}

	var collect XdpProgramByName

	switch progName {
	case "xdp_pass":
		collect = &CollectPass{}
		Key = uint32(2)
	case "xdp_drop":
		collect = &CollectDrop{}
		Key = 1
	case "xdp_abort":
		collect = &CollectAbort{}
		Key = 0
	default:
		fmt.Println("[error] unknown program name specified")
		os.Exit(1)
	}

	// Load and assign the eBPF object
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		fmt.Fprintf(os.Stderr, "[error] loading and assigning eBPF object: %v\n", err)
		os.Exit(1)
	}

	// Initialize the map with a default Key-value pair
	// Initialize the map with a default Key-value pair
	numCpus := runtime.NumCPU()
	defaultValue := make([]Datarec, numCpus)
	for i := uint32(0); i < 3; i++ {
		if err := collect.MAP().Update(unsafe.Pointer(&i), defaultValue, ebpf.UpdateAny); err != nil {
			fmt.Fprintf(os.Stderr, "[error] initializing map: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("[success] successfully loaded XDP program: %s\n", progName)

	// Get the interface link
	link, err := netlink.LinkByName(iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] finding network interface: %v\n", err)
		os.Exit(1)
	}

	// Attach the XDP program to the interface
	if err := netlink.LinkSetXdpFdWithFlags(link, collect.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		fmt.Fprintf(os.Stderr, "[error] attaching XDP program: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[success] successfully attached XDP program: %s\n", progName)

	// Ensure the program is detached on exit
	defer func() {
		if err := netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE); err != nil {
			fmt.Fprintf(os.Stderr, "[error] detaching XDP program: %v\n", err)
		} else {
			fmt.Printf("[success] successfully detached XDP program: %s\n", progName)
		}
	}()

	// Handle Ctrl+C signal for clean detachment
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to periodically display counts
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Println("[info] displaying the map contents")
				value := make([]Datarec, numCpus)
				if err := collect.MAP().Lookup(unsafe.Pointer(&Key), &value); err != nil {
					fmt.Printf("[error] looking up Key %d: %v\n", Key, err)
					return
				}
				for cpu, v := range value {
					fmt.Printf("Key: %d, CPU: %d, RxPackets: %d, RxBytes: %d\n", Key, cpu, v.RxPackets, v.RxBytes)
				}

			case <-sig:
				return
			}
		}
	}()

	<-sig
}
