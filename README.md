# 🕷️ ARP Spoofing Lab — Python Raw Sockets

[![GitHub](https://img.shields.io/badge/github-repo-3776AB?style=for-the-badge&logo=github&logoColor=white)](https://github.com/)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![LAB](https://img.shields.io/badge/Security-Lab-8A2BE2?style=for-the-badge)]("https://github.com/3078756D627261/DNSpoofing/")

## ⚠️ Disclaimer

> [!WARNING]
> This project is designed for controlled security and networking laboratories. ARP spoofing can interfere with network communication and can be used in man-in-the-middle attacks. Only use it on systems and networks that you own or have explicit permission to test.

---

## ✨ Overview

A Python-based educational project that demonstrates **how ARP spoofing works at the Ethernet and ARP protocol level**.
The project intentionally constructs Ethernet frames and ARP packets using Linux raw sockets so that the complete process can be observed at the packet level.

---

## 🎯 Project Purpose

The primary goal of this project is to understand **how ARP spoofing works**, rather than simply using an existing ARP-spoofing library or tool. The script demonstrates the underlying process:
```
┌─────────────────┐
│  Local Machine  │
└────────┬────────┘
         │
         │ ARP Request
         ▼
┌─────────────────┐
│  Target Host    │
│  192.168.1.10   │
└────────┬────────┘
         │
         │ ARP Reply
         ▼
 Target MAC Address
         │
         ▼
┌──────────────────┐
│ Construct forged │
│    ARP packet    │
└────────┬─────────┘
         │
         │ ARP Reply
         ▼
┌─────────────────┐
│   Target Host   │
└─────────────────┘

```

The important concept is that `ARP does not provide authentication`. A host can receive an ARP message claiming that a particular IP address corresponds to a particular MAC address and potentially `update its ARP cache accordingly`.

---

## 🔥 Features

- 🐍 Written in Python 3
- 🔌 Uses Linux `AF_PACKET` raw sockets
- 🧱 Manually builds Ethernet frames
- 📡 Manually constructs ARP requests and replies
- 🔎 Resolves a target's MAC address using ARP
- 🧩 Demonstrates Ethernet + ARP encapsulation
- 🧮 Uses Python's struct module to pack and unpack binary headers
- 🖥️ Automatically retrieves interface IP and MAC addresses with `psutil`
- 🧪 Designed for controlled networking laboratories

---

## 🧠 Background

What is ARP?
`ARP (Address Resolution Protocol)` is used on IPv4 networks to `determine the MAC address associated with an IP address`.

For example, suppose a computer wants to communicate with:

```text
IP address: 192.168.1.10
```

but does not know the corresponding MAC address.

It can `broadcast an ARP request`:

```text
Who has 192.168.1.10?
```

The device that `owns that IP` can respond:

```text
192.168.1.10 is at AA:BB:CC:DD:EE:FF
```

The sender can then use that MAC address when constructing `Ethernet frames`.

---

## 🧠 How ARP Spoofing Works

ARP spoofing `(also called ARP cache poisoning)` is a local-network attack where an attacker sends forged ARP messages to make a device associate an IP address with the attacker's MAC address.

Normally, a host uses ARP to discover the `MAC address` associated with an `IPv4 address`:

```text
Who has 192.168.1.1? Tell 192.168.1.100
```

The legitimate host can respond:

```text
192.168.1.1 is at AA:AA:AA:AA:AA:AA
```

The target then associates:

```text
192.168.1.1 - AA:AA:AA:AA:AA:AA
```

### During ARP spoofing

An attacker can send a forged ARP message claiming a different MAC address for an IP:

```text
192.168.1.1 is at BB:BB:BB:BB:BB:BB
```

If the target accepts the forged information, its ARP cache may become:

```text
192.168.1.1 - BB:BB:BB:BB:BB:BB
```

The essential idea is therefore:

```text
       Legitimate ARP
             │
             │
             ▼
IP Address ─────► Legitimate MAC
             │
             │
             ▼
         Forged ARP
             │
             │
             ▼
IP Address ─────► Attacker MAC
```

This is the fundamental mechanism behind ARP cache poisoning.

---

## 🔬 What This Script Does

The script demonstrates this process at a low level:

01. Retrieves the local interface's `MAC address`.
02. Retrieves the local interface's `IPv4 address`.
03. Creates a Linux `AF_PACKET` raw socket.
04. Constructs an Ethernet frame.
05. Constructs an `ARP request`.
06. Sends the request to discover the target's MAC address.
07. Receives and parses the ARP response.
08. `Extracts` the target's MAC address.
09. Constructs an ARP packet containing the selected `spoofed IP`.
10. Encapsulates the `ARP packet` inside an Ethernet frame.
11. Repeatedly transmits the demonstration packet.

The important part is that the ARP packet is **constructed manually** instead of relying on a high-level ARP-spoofing library.

---

## 📡 Why Raw Sockets?

Using a high-level library can hide what is actually happening.

This project deliberately works with:

```text
socket.AF_PACKET
```
and:

```text
socket.SOCK_RAW
```

This allows the program to operate directly with Ethernet frames.

Conceptually:

```text
High-level networking
          │
          ▼
   TCP / UDP / HTTP
          │
          ▼
      OS Kernel
          │
          ▼
       Ethernet
```

---

## 🧩 Ethernet + ARP

The forged ARP message is not transmitted by itself.

It is placed inside an Ethernet frame:

```text
┌────────────────────────────────────────────────────────────────────────┐
| Preamble | Destination MAC | Source MAC | Ether Type | User Data | FCS |
└────────────────────────────────────────────────────────────────────────┘
|    8B    |       6B        |     6B     |     2B     | 46-1500B  | 4B  |
└────────────────────────────────────────────────────────────────────────┘
```

For Ethernet + IPv4 ARP:

```text
EtherType = 0x0806
```

The ARP header is 28 bytes, while the Ethernet II header is 14 bytes.

Therefore the complete frame constructed by the script is:

```text
14-byte Ethernet Header + 28-byte ARP Header = 42 bytes
```

---

## 🔎 Discovering the Target MAC

Before constructing the demonstration packet, the script needs the target's MAC address.

It sends an ARP request and waits for a response:

```text
 Python Script
       │
       │ ARP Request
       ▼
┌──────────────┐
│ Target Host  │
└──────┬───────┘
       │ ARP Response
       ▼
 Python Script
       │
       ▼
Target MAC Address
```

The response is then decoded using:

```text
struct.unpack()
```

The script extracts:

```text
Sender MAC
Sender IPv4 address
```

---

## 🧮 Understanding the ARP Fields

The ARP packet contains several important fields:

```text

┌────────────────────────────────────────────────────────────────────────────────────────┐
|                Hardware type                      |            Protocol type           |
└────────────────────────────────────────────────────────────────────────────────────────┘
| Hardware address length | Protocol address length |               Opcode               |
┌────────────────────────────────────────────────────────────────────────────────────────┐
|                               Source hardware address                                  |
└────────────────────────────────────────────────────────────────────────────────────────┘
|                               Source protocol address                                  |
┌────────────────────────────────────────────────────────────────────────────────────────┐
|                               Destination hardware address                             |
└────────────────────────────────────────────────────────────────────────────────────────┘
|                               Destination protocol address                             |
┌────────────────────────────────────────────────────────────────────────────────────────┐
|                                         Data                                           |
└────────────────────────────────────────────────────────────────────────────────────────┘

* Hardware type                  : 16
* Protocol type                  : 16
* Hardware address length        : 8
* Protocol address length        : 8
* Opcode                         : 16
* Source hardware address        : 48
* Source protocol address        : 32
* Destination hardware address   : 48
* Destination protocol address   : 32
```

| Field | Example |
| --- | --- |
| Hardware Type | `1` |
| Protocol Type | `0x0800` |
| Hardware Size | `6` |
| Protocol Size | `4` |
| Opcode | `1` / `2` |
| Sender MAC | `xx:xx:xx:xx:xx:xx` |
| Sender IP | `192.168.x.x` |
| Target MAC | `xx:xx:xx:xx:xx:xx` |
| Target IP | `192.168.x.x` |

The interesting part for understanding spoofing is the relationship between:

```text
Sender IP
    +
Sender MAC
```

ARP spoofing manipulates this relationship.

---

## 🧪 Laboratory Environment

The project should be tested in an **isolated network**.

For example:

```text
             Isolated Lab Network
                     │
          ┌──────────┴──────────┐
          │                     │
     ┌────▼─────┐          ┌────▼─────┐
     │ Attacker │          │  Target  │
     │   VM     │          │    VM    │
     │          │          │          │
     │ Python   │          │ Test     │
     │ Script   │          │ Machine  │
     └──────────┘          └──────────┘
```

A three-machine laboratory can additionally include a dedicated gateway:

```
                 ┌───────────┐
                 │  Gateway  │
                 └─────┬─────┘
                       │
                Isolated Network
                       │
              ┌────────┴────────┐
              │                 │
        ┌─────▼─────┐     ┌─────▼─────┐
        │  Attacker │     │   Target  │
        │    VM     │     │     VM    │
        └───────────┘     └───────────┘
```

Do not perform these experiments on networks that you do not control.

---

## 🔍 Observe It With Wireshark

A major goal of the project is to **see the spoofing process**, not just execute it.

Capture traffic on the laboratory interface and use:

```text
arp
```

as the display filter.

You can inspect:

- Ethernet source MAC
- Ethernet destination MAC
- ARP opcode
- ARP sender MAC
- ARP sender IP
- ARP target MAC
- ARP target IP

A packet analyzer makes the relationship between the Python code and the actual network traffic much easier to understand.

---

## 🧪 Check the ARP Cache

On Linux, you can inspect the local ARP/neighbor table with:

```
ip neigh
```

On Windows, you can inspect the local ARP/neighbor table with:

```text
arp -a
```

This allows you to compare the expected IP-to-MAC mapping with the mapping stored by the operating system.

The educational experiment can therefore be understood as:

```text
    BEFORE
      ↓
   ARP Cache
      ↓
IP ───────► Legitimate MAC
      ↓
    AFTER
      ↓
  ARP Spoofing
      ↓
   ARP Cache
      ↓
IP ───────► Different MAC
```
---

## 🛠️ Requirements

### Operating System

The project uses Linux:

- Linux
- Python 3.8+
- `AF_PACKET` support
- Isolated laboratory network

> [!TIP]
> `AF_PACKET` is Linux-specific, so the script is not directly portable to Windows.

### Python Dependency

Install `psutil`:

```text
python3 -m pip install psutil
sudo apt-get install python3-psutil
```

The following modules are included with Python:

```text
argparse
sys
socket
struct
```

---

## 🚀 Usage

Clone the repository and enter the project directory:
```text
git clone https://github.com/3078756D627261/ARPSpoofer.git
cd ARPSpoofer
```

Show the available options:

```text
python3 ARPSpoofer.py --help
```

The script supports:

```text
-i, --iface
-t, --target
-s, --spoof
```

Example for an isolated lab:

```text
sudo python3 ARPSpoofer.py --iface eth0 --target <LAB_TARGET_IP> --spoof <LAB_SPOOFED_IP>
```

Use only IP addresses belonging to your authorized laboratory environment.

---

## 🧱 Important Functions

### `socket_creation()`

Creates the Layer 2 raw socket:

```text
socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
```

---

### `ethernet_encapsulation()`

Creates the Ethernet II header:

```text
Destination MAC
Source MAC
EtherType
```

For ARP:

```text
0x0806
```

---

### `arp_encapsulation()`

Constructs the ARP header

---

### `find_target_mac_addr()`

Performs ARP discovery and obtains the target MAC address.

---

### `arp_decapsulation()`

Parses a received Ethernet + ARP frame and extracts ARP fields.

---

### `send_arp_request()`

Transmits the constructed raw Ethernet/ARP frame through the raw socket.

---

## 🧮 Why `struct.pack()`?

Network packets are ultimately sequences of bytes.

For example:

```text
struct.pack("!H", 1)
```

converts the integer:

```text
1
```

into a 16-bit network-order representation.

The format string:

```text
!H
```

means:

```text
!  = network byte order
H  = unsigned 16-bit integer
```

This is one of the most important concepts in the project:

> [!IMPORTANT]
> Networking protocols define fields as bytes, while Python normally works with higher-level values.

`struct` bridges those two worlds.

---

## 📖 Learning Objectives

After working through this project, you should understand:

- What ARP does
- How ARP maps IPv4 addresses to MAC addresses
- Why ARP spoofing is possible
- What an ARP request looks like
- What an ARP reply looks like
- How an Ethernet frame encapsulates an ARP packet
- How raw sockets work on Linux
- How `AF_PACKET` provides Layer 2 access
- How binary protocol fields are represented
- How `struct.pack()` constructs packet fields
- How `struct.unpack()` parses packet fields
- How ARP cache poisoning can affect a local network
- How to observe the entire process using Wireshark

---

## ⚠️ Limitations

This project is intentionally simple and educational.

It does not attempt to be a production-quality networking or security tool.

Some limitations include:

- Linux-specific `AF_PACKET` implementation.
- Basic input validation.
- Simple ARP response handling.
- No comprehensive packet validation.
- No ARP cache restoration mechanism.
- Continuous transmission until interrupted.
- Assumes Ethernet + IPv4 ARP.
- Requires appropriate privileges for raw socket access.

These limitations are intentional to keep the source code focused on understanding the underlying protocols.

---

## 🛡️ Defensive Perspective

Understanding ARP spoofing is also useful for understanding how to detect and mitigate it.

After understanding the attack mechanism, useful defensive topics include:

- Static ARP entries
- Dynamic ARP Inspection (DAI)
- Network segmentation
- Switch security features
- ARP monitoring
- IDS/IPS detection
- Monitoring unexpected MAC/IP changes
- Encrypted protocols such as HTTPS and SSH

The best way to understand a network attack is to understand both **how it works and how it can be detected**.

---
