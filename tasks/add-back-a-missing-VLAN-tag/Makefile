.PHONY: all setup clean 

NS1 = ns1
NS2 = ns2
VETH0 = veth0
VETH1 = veth1
VETH0_VLAN = veth0.100
VETH1_VLAN = veth1.100
NS1_IP = 192.168.5.3/24
NS2_IP = 192.168.5.6/24
NS1_VLAN_IP = 192.168.89.3/24
NS2_VLAN_IP = 192.168.89.32/24

all: setup 
setup:
	# Create network namespaces
	sudo ip netns add $(NS1)
	sudo ip netns add $(NS2)

	# Create veth pair
	sudo ip link add $(VETH0) type veth peer name $(VETH1)

	# Move veth interfaces to namespaces
	sudo ip link set $(VETH0) netns $(NS1)
	sudo ip link set $(VETH1) netns $(NS2)

	# Configure IP addresses
	sudo ip netns exec $(NS1) ip addr add $(NS1_IP) dev $(VETH0)
	sudo ip netns exec $(NS2) ip addr add $(NS2_IP) dev $(VETH1)

	# Bring up the interfaces
	sudo ip netns exec $(NS1) ip link set dev $(VETH0) up
	sudo ip netns exec $(NS2) ip link set dev $(VETH1) up

	# Create VLAN interfaces
	sudo ip netns exec $(NS1) ip link add link $(VETH0) name $(VETH0_VLAN) type vlan id 100
	sudo ip netns exec $(NS2) ip link add link $(VETH1) name $(VETH1_VLAN) type vlan id 100

	# Assign IP addresses to VLAN interfaces
	sudo ip netns exec $(NS1) ip addr add $(NS1_VLAN_IP) dev $(VETH0_VLAN)
	sudo ip netns exec $(NS2) ip addr add $(NS2_VLAN_IP) dev $(VETH1_VLAN)

	# Bring up the VLAN interfaces
	sudo ip netns exec $(NS1) ip link set dev $(VETH0_VLAN) up
	sudo ip netns exec $(NS2) ip link set dev $(VETH1_VLAN) up

	# Disable VLAN hardware offload
	sudo ip netns exec $(NS1) ethtool --offload $(VETH0) rxvlan off txvlan off
	sudo ip netns exec $(NS2) ethtool --offload $(VETH1) rxvlan off txvlan off
exec_ns1 :
	sudo ip netns exec $(NS1) bash
exec_ns2 : 
	sudo ip netns exec $(NS2) bash
clean:
	# Delete network namespaces
	sudo ip netns del $(NS1)
	sudo ip netns del $(NS2)
