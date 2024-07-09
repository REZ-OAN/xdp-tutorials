# Basic-03 (Learn map reading and updateing)

## Prerequisite
 - [Create Environment](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/Environment-Setup/README.md)

## Demonstration

### Packet Flow

![packet-flow](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-03/images/packet-flow.png)

Firtly you have to navigate to `basic-xdp/basic-03/xdp-user-space-code` this directory. After doing all the necessary steps from the prerequisite. You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `xdp-map-counter`
```
go build
```
4. Run the binary with `-iface <interface name>` with `sudo` privileges
```
sudo ./xdp-map-counter -iface veth-h
```
**Note**: I have used `veth-h` as interface name. Because I am working on the `default` environment setup.

## Testing result
- Start the program
![initial-logs-starting](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-03/images/initial-logs.png)

- Tracing 
![when-pinging](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-03/images/logs-after-pinging.png)

