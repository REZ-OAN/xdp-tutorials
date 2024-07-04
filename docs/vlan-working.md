# How VLANs Works

VLANs (Virtual Local Area Networks) are used to segment network traffic logically, allowing multiple networks to coexist on a single physical network infrastructure.

## Segmentation 
VLANs segment network traffic by grouping devices into separate broadcast domains. This means that devices in different VLANs cannot directly communicate with each other without a router or Layer 3 switch.
## VLAN Tags
VLANs use tags to identify and separate traffic. Each Ethernet frame can carry a VLAN tag that specifies the VLAN to which the frame belongs.
## Trunk and Access Ports
- **Access Ports**: These are connected to end devices and typically belong to a single VLAN. They don't carry VLAN tags.
- **Trunk Ports**: These are used to connect switches or other network devices. Trunk ports can carry traffic from multiple VLANs, and the frames are tagged with VLAN IDs.

## Packet Structure 
- Without VLAN tags
```
| Destination MAC | Source MAC  | EtherType | IP Header | Payload |
| 6 bytes         | 6 bytes     | 2 bytes   | 20+ bytes | ...     |

```
- With VLAN tags
```
| Destination MAC | Source MAC  | TPID    | TCI     | EtherType | IP Header | Payload |
| 6 bytes         | 6 bytes     | 0x8100  | 2 bytes | 2 bytes   | 20+ bytes | ...     |

```
## Working Process 
- **Tagging**
    When a packet is transmitted on a VLAN, it is tagged with a VLAN ID. The tag is added to the Ethernet frame and includes a 12-bit VLAN identifier, which allows for 4096 possible VLANs.

- **Transmission** 
    The tagged frame is transmitted across the network. Trunk ports on switches forward the tagged frames to other trunk ports or to access ports belonging to the same VLAN.

- **Untagging** 
    When the frame reaches an access port, the VLAN tag is removed before the frame is delivered to the end device.

- **Isolation**
    Devices in different VLANs are isolated from each other at Layer 2 (Data Link Layer). This means that broadcasts, multicasts, and unicast traffic are contained within each VLAN.

## Demonstrating the Packet Flow for environment setup.
```
+-------------+                             +-------------+
| Namespace   |                             | Namespace   |
|   ns1       |                             |   ns2       |
|             |                             |             |
|  veth0.100  |                             |  veth1.100  |
|192.168.100.1|                             |192.168.100.2|
|    |        |                             |      |      |
|    veth0    | <--- Virtual Link (veth pair) ---> | veth1|
|             |                             |             |
+-------------+                             +-------------+

Step-by-Step Packet Flow:

1. Packet sent from 192.168.100.1 (ns1) via veth0.100
   - Tagged with VLAN ID 100
2. Packet travels through veth0 -> veth1 (virtual link)
3. Packet received by veth1.100 in ns2
   - VLAN ID 100 recognized, tag removed
4. Packet delivered to 192.168.100.2 (ns2)

Reply follows the reverse path:
1. Packet sent from 192.168.100.2 (ns2) via veth1.100
   - Tagged with VLAN ID 100
2. Packet travels through veth1 -> veth0 (virtual link)
3. Packet received by veth0.100 in ns1
   - VLAN ID 100 recognized, tag removed
4. Packet delivered to 192.168.100.1 (ns1)

```