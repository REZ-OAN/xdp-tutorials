# Basic-02 (Learn selection of a program by name)

## Prerequisite
 - [Create Environment](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/Environment-Setup/README.md)

## Demonstration
Firtly you have to navigate to `basic-xdp/basic-02/xdp-user-space-code` this directory. After doing all the necessary steps from the prerequisite. You can proceed with following procedure :
1. Download the necessary modules
```
go mod tidy
```
2. Generate necessary files using `bpf2go`
```
go generate
```
3. Build the go binary. It will generate a file in the same directory called `xdp-prog-select`
```
go build
```
4. Run the binary with `-iface <interface name> -prog <xdp_pass or xdp_drop>`  with `sudo` privileges
```
sudo ./xdp-prog-select -iface veth-h -prog xdp_drop
```
**Note**: I have used `veth-h` as interface name. Because I am working on the `default` environment setup.


## Testing result for `xdp_drop`
- Start the program
![program-start_drop_logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-02/images/program-start-drop-logs.png)

- Tracing 
![xdp_drop_logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-02/images/xdp_drop_logs.png)

## Testing result for `xdp_pass`
- Start the program
![program-start_pass_logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-02/images/program-start-pass-logs.png)

- Tracing 
![xdp_pass_logs](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/basic-02/images/xdp_pass_logs.png)