package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp_map_counter ../../xdp-kernel-space-code/xdp_prog.c

type packetInfo struct {
	Count uint32
	Size  uint32
}

type Collect struct {
	Map *ebpf.Map `ebpf:"packet_counts"`
}

func main() {
	var collect = &Collect{}

	mapSpec, err := ebpf.LoadPinnedMap("/sys/fs/bpf/test/globals/packet_counts", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] loading eBPF map: %v\n", err)
		os.Exit(1)
	}
	collect.Map = mapSpec
	fmt.Printf("[success] successfully loaded map\n")

	defer func() {
		fmt.Printf("wow!! you have successfully completed basic-xdp\n")
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
				packet := &packetInfo{}
				collect.Map.Lookup(unsafe.Pointer(&key), unsafe.Pointer(packet))
				fmt.Printf("[info] total packet received %d and total bytes %d\n", packet.Count, packet.Size)
			case <-sig:
				return
			}
		}
	}()

	<-sig
}
