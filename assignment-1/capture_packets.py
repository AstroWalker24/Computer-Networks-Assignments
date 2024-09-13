from scapy.all import sniff,IP,ICMP


def packet_analyzer(packet):
    if packet.haslayer(ICMP):
        # printing out the src IP address 
        print(f"The source IP address of the captured packet is {packet[IP].src}")
        print(f"The Destination IP address of the captured packet is {packet[IP].dst}")


def packet_capturer():
    print("Starting Packet Capture!")
    sniff(filter='icmp',prn=packet_analyzer,count=10)


if __name__=="__main__":
    packet_capturer()