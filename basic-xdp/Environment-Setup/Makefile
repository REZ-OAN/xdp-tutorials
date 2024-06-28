.PHONY: all create_ns create_veth clean

NS_NAME = test-ns
VETH_HOST = veth-h
VETH_NS = veth-ns
IP_HOST = 192.168.0.2/16
IP_NS = 192.168.0.4/16

all: create_ns create_veth

create_ns:
	@if [ -z "$$(ip netns list | grep $(NS_NAME))" ]; then \
		echo "Creating network namespace $(NS_NAME)"; \
		sudo ip netns add $(NS_NAME); \
		echo "Creating network namespace successfull"; \
	else \
		echo "Network namespace $(NS_NAME) already exists"; \
	fi

create_veth:
	@if [ -z "$$(ip link show $(VETH_HOST))" ]; then \
		echo "Creating veth pair $(VETH_HOST) and $(VETH_NS)"; \
		sudo ip link add $(VETH_HOST) type veth peer name $(VETH_NS); \
		echo "Creating veth pair successfull"; \
		echo "Moving $(VETH_NS) to namespace $(NS_NAME)"; \
		sudo ip link set $(VETH_NS) netns $(NS_NAME); \
		echo "Moving was successfull"; \
		echo "Assigning IP address $(IP_HOST) to $(VETH_HOST)"; \
		sudo ip addr add $(IP_HOST) dev $(VETH_HOST); \
		echo "Bringing up $(VETH_HOST)"; \
		sudo ip link set $(VETH_HOST) up; \
		echo "Assigning IP address $(IP_NS) to $(VETH_NS) in namespace $(NS_NAME)"; \
		sudo ip netns exec $(NS_NAME) ip addr add $(IP_NS) dev $(VETH_NS); \
		echo "Bringing up $(VETH_NS) in namespace $(NS_NAME)"; \
		sudo ip netns exec $(NS_NAME) ip link set $(VETH_NS) up; \
	else \
		echo "Veth pair $(VETH_HOST) and $(VETH_NS) already exists"; \
	fi
exec_ns:
	@if [ -z "$$(ip netns list | grep $(NS_NAME))" ]; then \
		echo "Network namespace $(NS_NAME)" not found; \
	else \
		sudo ip netns exec $(NS_NAME) bash; \
	fi
clean:
	@if [ ! -z "$$(ip link show $(VETH_HOST))" ]; then \
		echo "Deleting veth pair $(VETH_HOST) and $(VETH_NS)"; \
		sudo ip link delete $(VETH_HOST); \
	fi
	@if [ ! -z "$$(ip netns list | grep $(NS_NAME))" ]; then \
		echo "Deleting network namespace $(NS_NAME)"; \
		sudo ip netns delete $(NS_NAME); \
	fi