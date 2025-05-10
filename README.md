# Network Scanner - ARP-Based Network Discovery Tool

A lightweight Python network scanner that uses ARP requests to discover active devices on a local network.

## Features

- 🕵️ Scan entire network ranges using CIDR notation
- 📟 List all active devices with IP and MAC addresses
- 🔍 Simple and fast network discovery
- 📊 Sorted results by IP address
- 🖥️ Cross-platform compatibility

## Requirements

- Python 3.6+
- scapy (`pip install scapy`)
- Root/Administrator privileges (for raw socket access)

## Installation

### 1. Clone the repository:
```bash
git clone https://github.com/AFT0ZERO/MAC_Address_Changer_Unix-Public
cd network-scanner
```
### 2. Install Dependencies
 ```bash
pip3 install scapy
```

## Usege
- Basic syntax:
```bash
sudo python3 scanner.py -r <network_range>
```
- Example:
  
```bash
  sudo python3 scanner.py -r 192.168.1.0/24
  ```
- Sample output:
```
[*] Scanning 192.168.1.0/24...

IP Address          MAC Address
-----------------------------------------
192.168.1.1         aa:bb:cc:dd:ee:ff
192.168.1.15        00:11:22:33:44:55
192.168.1.100       ff:ee:dd:cc:bb:aa

[*] Found 3 devices.
```
## Options
    -r	Network range to scan (CIDR format)	192.168.1.0/24

## Troubleshooting
### common Issues:
 1. Permission Denied
    ```bash
    [!] Permission denied. Try running with sudo.
    ```
    - Solution: Run with sudo or administrator privileges

2. No Devices Found
   - Ensure devices are connected and powered on

   - Check your network connection

   - Verify firewall isn't blocking ARP requests
3. Invalid Network Range
    ```bash
    [!] Invalid network range: 192.168.1.500/24
    ```
    - Use valid CIDR notation (e.g., 10.0.0.0/24)

## How It Works
### This scanner uses:

- ARP (Address Resolution Protocol) requests to identify active devices

- Ethernet broadcast to send requests to all network devices

- Scapy for packet crafting and network communication

## Legal Disclaimer
### ⚠️ Important:
Use this tool only on networks you have explicit permission to scan. Unauthorized network scanning may be illegal in many jurisdictions. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## License
MIT License - See LICENSE file