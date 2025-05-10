import scapy.all as scapy
import argparse
import sys
from ipaddress import ip_network, IPv4Address  

def get_arguments():
    parser = argparse.ArgumentParser(description='Network scanner using ARP requests')
    parser.add_argument('-r', '--range', dest='network', required=True,
                        help='Network IP range to scan (e.g., 192.168.1.0/24)')
    return parser.parse_args()

def validate_network(network):
    try:
        return ip_network(network, strict=False)
    except ValueError:
        sys.exit(f"[!] Invalid network range: {network}")

def scan(network):
    validated_net = validate_network(network)
    print(f"[*] Scanning {validated_net}...")
    
    arp_request = scapy.ARP(pdst=str(validated_net))
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    try:
        answered, _ = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)
    except PermissionError:
        sys.exit("[!] Permission denied. Try running with sudo.")
    except Exception as e:
        sys.exit(f"[!] Error occurred: {e}")

    devices = [{'ip': packet[1].psrc, 'mac': packet[1].hwsrc} 
               for packet in answered]
    return sorted(devices, key=lambda x: IPv4Address(x['ip']).packed)


def display_results(devices):
    if not devices:
        print("[*] No devices found.")
        return

    print("\nIP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")
    print(f"\n[*] Found {len(devices)} devices.")

if __name__ == "__main__":
    args = get_arguments()
    devices = scan(args.network)
    display_results(devices)