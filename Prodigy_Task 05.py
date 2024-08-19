from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    try:
        # Display basic packet information
        print(f"\nPacket: {packet.summary()}")
        
        # Display IP layer information
        if IP in packet:
            ip_layer = packet[IP]
            print(f"Source IP: {ip_layer.src}")
            print(f"Destination IP: {ip_layer.dst}")
        
        # Display TCP layer information
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")
        
        # Display UDP layer information
        if UDP in packet:
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")
                
    except Exception as e:
        print(f"Error processing packet: {e}")

def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
