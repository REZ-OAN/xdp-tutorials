.PHONY: all setup clean xdp_prog

NS1 = ns1
NS2 = ns2
VETH0 = veth0
VETH1 = veth1
VETH0_VLAN = veth0.100
VETH1_VLAN = veth1.100
NS1_IP = 192.168.1.1/24
NS2_IP = 192.168.1.2/24
NS1_VLAN_IP = 192.168.100.1/24
NS2_VLAN_IP = 192.168.100.2/24
XDP_PROG = xdp_prog.o

all: setup xdp_prog

setup:
	# Create network namespaces
	ip netns add $(NS1)
	ip netns add $(NS2)

	# Create veth pair
	ip link add $(VETH0) type veth peer name $(VETH1)

	# Move veth interfaces to namespaces
	ip link set $(VETH0) netns $(NS1)
	ip link set $(VETH1) netns $(NS2)

	# Configure IP addresses
	ip netns exec $(NS1) ip addr add $(NS1_IP) dev $(VETH0)
	ip netns exec $(NS2) ip addr add $(NS2_IP) dev $(VETH1)

	# Bring up the interfaces
	ip netns exec $(NS1) ip link set dev $(VETH0) up
	ip netns exec $(NS2) ip link set dev $(VETH1) up

	# Create VLAN interfaces
	ip netns exec $(NS1) ip link add link $(VETH0) name $(VETH0_VLAN) type vlan id 100
	ip netns exec $(NS2) ip link add link $(VETH1) name $(VETH1_VLAN) type vlan id 100

	# Assign IP addresses to VLAN interfaces
	ip netns exec $(NS1) ip addr add $(NS1_VLAN_IP) dev $(VETH0_VLAN)
	ip netns exec $(NS2) ip addr add $(NS2_VLAN_IP) dev $(VETH1_VLAN)

	# Bring up the VLAN interfaces
	ip netns exec $(NS1) ip link set dev $(VETH0_VLAN) up
	ip netns exec $(NS2) ip link set dev $(VETH1_VLAN) up

	# Disable VLAN hardware offload
	ip netns exec $(NS1) ethtool --offload $(VETH0) rxvlan off txvlan off
	ip netns exec $(NS2) ethtool --offload $(VETH1) rxvlan off txvlan off

clean:
	# Delete network namespaces
	ip netns del $(NS1)
	ip netns del $(NS2)
