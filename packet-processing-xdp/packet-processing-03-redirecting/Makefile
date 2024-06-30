# Makefile

BUILD=build
CLEAN=clean

# Default values, can be overridden by changing the values

VETH0 = veth-h-1
VETH1 = veth-ns1-1
VETH2 = veth-ns1-2
VETH3 = veth-ns2-1
NODE1 = ns1
NODE2 = ns2
NETWORK = 192.168.1.0/24
IP0 = 192.168.0.3/24
IP1 = 192.168.0.2/24
IP1-INET = 192.168.0.2
IP2 = 192.168.1.4/24
IP2-INET = 192.168.1.4
IP3 = 192.168.1.5/24

.PHONY: build clean exec_ns1 exec_ns2 help

build:
	sudo ip netns add $(NODE1)
	sudo ip netns add $(NODE2)
	sudo ip link add $(VETH0) type veth peer name $(VETH1)
	sudo ip link add $(VETH2) type veth peer name $(VETH3)
	sudo ip link set $(VETH1) netns $(NODE1)
	sudo ip link set $(VETH2) netns $(NODE1)
	sudo ip link set $(VETH3) netns $(NODE2)
	sudo ip addr add $(IP0) dev $(VETH0)
	sudo ip netns exec $(NODE1) ip addr add $(IP1) dev $(VETH1)
	sudo ip netns exec $(NODE1) ip addr add $(IP2) dev $(VETH2)
	sudo ip netns exec $(NODE2) ip addr add $(IP3) dev $(VETH3)
	sudo ip link set up dev $(VETH0)
	sudo ip netns exec $(NODE1) ip link set up dev $(VETH1)
	sudo ip netns exec $(NODE1) ip link set up dev $(VETH2)
	sudo ip netns exec $(NODE1) ip link set up dev lo
	sudo ip netns exec $(NODE2) ip link set up dev $(VETH3)
	sudo ip netns exec $(NODE2) ip link set up dev lo
# delete created default route by kernel
	sudo ip netns exec $(NODE1) ip route del $(NETWORK)
# add the custom route 
	sudo ip netns exec $(NODE1) ip route add $(NETWORK) via $(IP2-INET) dev $(VETH2)
# add the route to the root-namespace
	sudo ip route add $(NETWORK) via $(IP1-INET)

exec_ns1:
	sudo ip netns exec $(NODE1) bash
exec_ns2: 
	sudo ip netns exec $(NODE2) bash
clean:
	sudo ip netns exec $(NODE1) ip route del $(NETWORK) via $(IP2-INET) dev $(VETH2)
	sudo ip route del $(NETWORK) via $(IP1-INET)
	sudo ip netns del $(NODE1)
	sudo ip netns del $(NODE2)

help:
	@echo "Usage:"
	@echo "	make build -> build the whole setup"
	@echo " make exec_ns1 -> enter into the network namespace $(NODE1)"
	@echo " make exec_ns2 -> enter into the network namespace $(NODE2)" 
	@echo "	make clean -> clean the whole environment"
	@echo "	make help"
