# Define variables
NS1 = ns1
NS2 = ns2
BRIDGE = test-br
VETH1 = veth1
VETH1_BR = veth1-br
VETH2 = veth2
VETH2_BR = veth2-br

## default ip addresses can be overwritten by user input
NS1_IP ?= 10.10.20.5
NS2_IP ?= 10.10.20.7
BRIDGE_IP ?= 10.10.20.19
NETMASK = 24

setup_network:
	@echo "Setting up network namespaces and bridge..."
	sudo ip netns add $(NS1)
	sudo ip netns add $(NS2)
	sudo ip link add $(BRIDGE) type bridge
	sudo ip link set $(BRIDGE) up
	sudo ip link add $(VETH1) type veth peer name $(VETH1_BR)
	sudo ip link add $(VETH2) type veth peer name $(VETH2_BR)
	sudo ip link set $(VETH1) netns $(NS1)
	sudo ip link set $(VETH2) netns $(NS2)
	sudo ip netns exec $(NS1) ip link set dev $(VETH1) up
	sudo ip netns exec $(NS2) ip link set dev $(VETH2) up
	sudo ip link set dev $(VETH1_BR) master $(BRIDGE)
	sudo ip link set dev $(VETH2_BR) master $(BRIDGE)
	sudo ip link set dev $(VETH1_BR) up
	sudo ip link set dev $(VETH2_BR) up
	sudo ip netns exec $(NS1) ip addr add $(NS1_IP)/$(NETMASK) dev $(VETH1)
	sudo ip netns exec $(NS2) ip addr add $(NS2_IP)/$(NETMASK) dev $(VETH2)
	sudo ip addr add $(BRIDGE_IP)/$(NETMASK) dev $(BRIDGE)
	sudo ip netns exec $(NS1) ip link set lo up
	sudo ip netns exec $(NS2) ip link set lo up
	# sudo ip netns exec $(NS1) ip route add default via $(BRIDGE_IP)
	# sudo ip netns exec $(NS2) ip route add default via $(BRIDGE_IP)
	sudo sysctl -w net.ipv4.ip_forward=1
set_rules:
	sudo iptables -A FORWARD -i $(BRIDGE) -o $(VETH0_BR) -j ACCEPT
	sudo iptables -A FORWARD -i $(BRIDGE) -o $(VETH1_BR) -j ACCEPT
	sudo iptables -A FORWARD -i $(VETH0_BR) -o $(BRIDGE) -j ACCEPT
	sudo iptables -A FORWARD -i $(VETH1_BR) -o $(BRIDGE) -j ACCEPT

del_rules :
	sudo iptables --delete FORWARD --in-interface $(VETH0_BR) --jump ACCEPT
	sudo iptables --delete FORWARD --out-interface $(VETH1_BR) --jump ACCEPT
	sudo iptables --delete FORWARD --in-interface $(VETH1_BR) --jump ACCEPT
	sudo iptables --delete FORWARD --out-interface $(VETH0_BR) --jump ACCEPT

exec_ns1:
	sudo ip netns exec $(NS1) bash
exec_ns2:
	sudo ip netns exec $(NS2) bash
clean:
	@echo "Cleaning up..."
	sudo ip netns del $(NS1) || true
	sudo ip netns del $(NS2) || true
	sudo ip link del $(BRIDGE) || true

.PHONY: all setup_network  clean
