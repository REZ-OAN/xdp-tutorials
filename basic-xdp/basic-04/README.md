# Basic-04 (Learn reading pinned map)

## Prerequisite
 - [Create Environment](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/Environment-Setup/README.md)

## Demonstration
Firtly you have to navigate to `basic-xdp/basic-04/xdp-user-space-code/pin-map` this directory. After doing all the necessary steps from the prerequisite. You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `pin-map`
```
go build
```
4. Run the binary with `-iface <interface name>` with `sudo` privileges
```
sudo ./pin-map -iface veth-h
```
This will pin the map on `/sys/fs/bpf/test/globals` named `packet_counts` and attach the xdp_program to the interface.

**Note**: I have used `veth-h` as interface name. Because I am working on the `default` environment setup.
### Verify pinned map
![pin_map_logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-04/images/pin-map-logs.png)

![verify-pinned-map](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-04/images/verify-pinmap-2.png)

Then you have to navigate to `basic-xdp/basic-04/xdp-user-space-code/read-map` this directory. Now proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `read-map`
```
go build
```
4. Run the binary with `sudo` privileges
```
sudo ./pin-map 
```
This will load the pinned map from `/sys/fs/bpf/test/globals` named `packet_counts`. And show the contents of the map.
## Testing result
![testing-read-map](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-04/images/testing-read-map.png)
