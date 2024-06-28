# Basic-02 (Learn selection of a program by name)

## Prerequisite
 - [Create Environment](https://github.com/REZ-OAN/xdp-tutorials/blob/main/basic-xdp/Environment-Setup/README.md)
 - [Basic-01 for loading,attaching,detaching using go](https://github.com/REZ-OAN/xdp-tutorials/tree/main/basic-xdp/basic-01#load-attach-detach-using-go)

## Demonstration
Firtly you have to navigate to `basic-xdp/basic-02/xdp-user-space-code` this directory. After doing all the necessary steps from the prerequisite. You can proceed with following procedure :
1. Run the binary with `-iface <interface name> -prog <xdp_pass or xdp_drop>` with `sudo` privileges
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