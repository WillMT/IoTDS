from scapy.all import *

def get_macadd(ip):
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc


# if the packet is an ARP packet and have response, compare the mac address from sender and arp packet.
def process(packet):
    
    if packet.haslayer(ARP):
        if packet[ARP].op == 2:
            try:
                real_mac = get_macadd(packet[ARP].psrc)
                response_mac = packet[ARP].hwsrc

                if real_mac != response_mac:
                    print(f"[!] Spoofing found, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
                    
            except IndexError:
                pass

if __name__ == "__main__":
    import sys
    try:
        iface = sys.argv[1]
    except IndexError:
        iface = conf.iface
    sniff(store=False, prn=process, iface=iface)