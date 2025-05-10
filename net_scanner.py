import scapy.all as scapy
import optparse

def get_arugments():
    parser=optparse.OptionParser()
    parser.add_option('-r','--range',dest='network_ip',help='To Enter Device IP or Network Range')
    options,arugments=parser.parse_args()

    if not options.network_ip:
        parser.error('[-] Please Specify an IP Adderss , -h For help')

    return options

def scan(network_ip):
    arp_request = scapy.ARP(pdst='10.0.2.1/24')
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    device_list=[]

    for ans in answered:
        device_dict={'ip':ans[1].psrc ,'mac':ans[1].hwsrc}
        device_list.append(device_dict)

    return device_list

def display_device(devices):
    print("IP Address \t\t MAC Address")
    print("-"*45,'\n')
    for device in devices:
        print(device["ip"],'\t\t',device["mac"])

options = get_arugments()
devices=scan(options.network_ip)
display_device(devices)