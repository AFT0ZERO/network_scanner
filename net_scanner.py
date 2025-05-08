import scapy.all as scapy

# Create A Packet
arp_request = scapy.ARP(pdst='10.0.2.1/24')
arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
arp_request_broadcast = arp_broadcast/arp_request

# Sending and Recieving Packets
answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

for ans in answered:
    print(ans[1].psrc + " " + ans[1].hwsrc)