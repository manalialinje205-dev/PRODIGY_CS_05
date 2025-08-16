from scapy.all import sniff,IP,TCP,UDP,ICMP, Raw

#function to handle each packet
def packet_handler(PACKET):
    if IP in PACKET:
        ip=PACKET[IP]
        print("n---new packet---")
        print(f"From:{ip.src}--> To:{ip.dst}")

# TCP Packet
    if TCP in PACKET:
        print ("protocol:TCP")
        print(f"source port:{PACKET[TCP].sport}")
        print(f"destination port:{PACKET[TCP]. dport}")

#UDP Packet
    elif UDP in PACKET:
        print("protocol:UDP")
        print(f"source port:{PACKET[UDP].sport}")
        print(f"Destination port:{PACKET[UDP].dport}")

#ICMP Packet
    elif ICMP in PACKET:
        print("protocol:ICMP")
        print(f"TYPE:{PACKET[ICMP].type}")
        print(f"CODE:{PACKET[ICMP].code}")

        if Raw in PACKET:
            payload = PACKET[Raw].load
            print(f"Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")
        else:
            print("Payload: None")
        
        #starting the sniffing packet
        print("simple network packet analyzer started.....(Press Ctrl+C to stop)\n")
        sniff(filter="ip",prn=packet_handler,store=False)

