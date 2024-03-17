from scapy.all import sniff

# dictionary to store mappings between IP addresses and MAC addresses
IP_MAC_Map = {}

def process_packet(packet):
    # extract source IP and source MAC from the ARP packet
    src_IP = packet['ARP'].psrc
    src_MAC = packet['Ether'].src

    # check if the source MAC already exists in the dictionary
    if src_MAC in IP_MAC_Map:
        # compare stored IP with current source IP
        if IP_MAC_Map[src_MAC] != src_IP:
            # ARP attack detected
            old_IP = IP_MAC_Map[src_MAC] if src_MAC in IP_MAC_Map else "unknown"
            message = (
                "\n ARP attack detected \n "
                + "Involving IP address \n "
                + str(old_IP) + " and " + str(src_IP)
                + "\n "
            )
            return message
    else:
        # add mapping of MAC address to IP address in the dictionary
        IP_MAC_Map[src_MAC] = src_IP

# sniff ARP packets and process them using the process_packet function
sniff(count=0, filter="arp", store=0, prn=process_packet)
