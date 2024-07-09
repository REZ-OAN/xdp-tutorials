package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp_prog ../kernel-space-code/xdp_prog.c

// mac len
const (
	ETH_ALEN = 6
)

var iface string
var src_ip string
var dest_ip string
var router_ip string
var src_mac string
var dest_mac string
var router_mac string
var dest_id string
var src_id string

type MacAddr struct {
	Addr [ETH_ALEN]byte
}

// to store the program object
type Collect struct {
	Prog *ebpf.Program `ebpf:"xdp_redirect_router"`
	Map  *ebpf.Map     `ebpf:"redirect_packets"`
}

type backend struct {
	saddr    uint32
	daddr    uint32
	h_source [6]byte
	h_dest   [6]byte
	iface    uint32
}

// parseMAC parses a MAC address string and returns an MacAddr.
func parseMAC(macStr string) MacAddr {
	// Split the MAC address string by ":"
	parts := strings.Split(macStr, ":")

	// Initialize a byte slice of length 6
	var macAddress MacAddr

	// Convert each part from hexadecimal string to byte
	for i := 0; i < 6; i++ {
		b, err := hex.DecodeString(parts[i])
		if err != nil {
			fmt.Printf("[error] error decoding MAC address: %v\n", err)

		}
		macAddress.Addr[i] = b[0]
	}

	return macAddress
}

// parseIP parses an IP address string and returns it as a uint32.
func parseIP(ipStr string) uint32 {
	// Split IP address into octets
	parts := strings.Split(ipStr, ".")

	// Convert octets to integers
	var ip uint32
	for i := 0; i < 4; i++ {
		octet, _ := strconv.Atoi(parts[i])
		if octet < 0 || octet > 255 {
			fmt.Printf("Invalid octet value: %s\n", parts[i])
		}
		ip += uint32(octet) << (uint(i) * 8)
	}
	return ip
}

func main() {
	flag.StringVar(&iface, "iface", "", "network interface to attach XDP program")
	flag.StringVar(&src_ip, "src_ip", "", "source IP address")
	flag.StringVar(&router_ip, "router_ip", "", "Give the bridge IP Address")
	flag.StringVar(&dest_ip, "dest_ip", "", "destination IP address")
	flag.StringVar(&dest_mac, "dest_mac", "", "destination MAC address")
	flag.StringVar(&src_mac, "src_mac", "", "source MAC address")
	flag.StringVar(&router_mac, "router_mac", "", "rotuer MAC address")
	flag.StringVar(&dest_id, "dest_id", "", "destination interface id")
	flag.StringVar(&src_id, "src_id", "", "source interface id")
	flag.Parse()

	if src_id == "" || dest_id == "" || iface == "" || dest_ip == "" || src_ip == "" || router_ip == "" || router_mac == "" || src_mac == "" || dest_mac == "" {
		fmt.Println("[error] interface name not given")
		os.Exit(1)
	}
	source_ip := parseIP(src_ip)
	destination_ip := parseIP(dest_ip)
	// router_IP := parseIP(router_ip)
	// router_MAC := parseMAC(router_mac)
	source_mac := parseMAC(src_mac)
	destination_mac := parseMAC(dest_mac)
	dest_ID, _ := strconv.ParseUint(dest_id, 10, 32)
	src_ID, _ := strconv.ParseUint(src_id, 10, 32)
	bk2 := backend{
		saddr:    source_ip,
		daddr:    destination_ip,
		h_source: source_mac.Addr,
		h_dest:   destination_mac.Addr,
		iface:    uint32(dest_ID),
	}
	bk1 := backend{
		saddr:    destination_ip,
		daddr:    source_ip,
		h_dest:   source_mac.Addr,
		h_source: destination_mac.Addr,
		iface:    uint32(src_ID),
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
	if err := collect.Map.Put(source_ip, bk2); err != nil {
		fmt.Printf("[error] values updating failed in tx_port\n")
		panic(err)
	}
	if err := collect.Map.Put(destination_ip, bk1); err != nil {
		fmt.Printf("[error] values updating failed in tx_port\n")
		panic(err)
	}
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
