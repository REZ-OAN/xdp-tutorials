# Task-01 (XDP_ABORT operation)

## Prerequisite
 - [Create Environment](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/Environment-Setup/README.md)

## Demonstration

### Packet Flow

![packet-flow](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/xdp-abort-porgram/images/packet-flow.png)


Firstly you have to navigate to `tasks/xdp-abort-porgram/user-space-code` this directory. After doing all the necessary steps from the prerequisite. You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `xdp-abort`
```
go build
```
4. Run the binary with `-iface <interface name>`  with `sudo` privileges
```
sudo ./xdp-abort -iface veth-h
```
**Note**: I have used `veth-h` as interface name. Because I am working on the `default` environment setup.


## Testing results

- Pinging and  Tracing

![xdp-abort-logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/tasks/xdp-abort-porgram/images/logs.png)