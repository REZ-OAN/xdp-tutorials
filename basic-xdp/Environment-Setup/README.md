# Environment Setup For basic-xdp tutorial

In this setup we will create a network namespace, and create a veth-pair to communicate with the host machine from the created network namespace.

![environment-overview](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/Environment-Setup/images/environment-setup.png)

Default setup uses following `default_arguments`
```
NS_NAME = test-ns
VETH_HOST = veth-h
VETH_NS = veth-ns
IP_HOST = 192.168.0.2/16
IP_NS = 192.168.0.4/16
```

## Create Namespace
```
make create_ns
```
## Create Veth-pair
```
make create_veth
```
## Enter into the network namespace
```
make exec_ns
```
## Clean the environment-setup
```
make clean
```