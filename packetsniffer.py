from scapy.all import sniff, wrpcap, rdpcap, raw, TCP, UDP, IP, ICMP, get_if_list
import threading
import datetime

class PacketSniffer:
    def __init__(self):
        self.packet_list = []
        self.filtered_packets = []
        self.protocol_filter = "ALL"
        self.stream_sessions = {}
        self.running = False
        self.capture_thread = None
        self.iface = None

    def list_interfaces(self):
        print("Available network interfaces:")
        for i, iface in enumerate(get_if_list()):
            print(f"{i}: {iface}")

    def select_interface(self, index):
        try:
            iface = get_if_list()[index]
            self.iface = iface
            print(f"Selected interface: {iface}")
        except IndexError:
            print("Invalid interface index")
            self.iface = None

    def start_sniffing(self):
        if self.running or not self.iface:
            return
        self.running = True
        self.packet_list.clear()
        self.filtered_packets.clear()
        print(f"Starting packet capture on interface {self.iface}...")
        self.capture_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.capture_thread.start()

    def stop_sniffing(self):
        if not self.running:
            return
        print("Stopping packet capture...")
        self.running = False
        self.capture_thread.join()
        print("Capture stopped.")

    def sniff_packets(self):
        sniff(iface=self.iface, prn=self.process_packet, store=False, stop_filter=lambda x: not self.running)

    def process_packet(self, packet):
        self.packet_list.append(packet)
        if self.protocol_filter == "ALL" or packet.haslayer(self.protocol_filter):
            self.filtered_packets.append(packet)
            print(f"{datetime.datetime.now().strftime('%H:%M:%S')} - {packet.summary()}")

    def set_protocol_filter(self, protocol):
        self.protocol_filter = protocol.upper()
        self.filter_packets()

    def filter_packets(self, protocol=None):
        if protocol:
            self.protocol_filter = protocol.upper()
        self.filtered_packets.clear()
        print(f"\nFiltering packets by protocol: {self.protocol_filter}")
        for pkt in self.packet_list:
            if self.protocol_filter == "ALL" or pkt.haslayer(self.protocol_filter):
                self.filtered_packets.append(pkt)
                print(pkt.summary())

    def save_to_pcap(self, filename=None):
        if not self.filtered_packets:
            print("No packets to save.")
            return
        if not filename:
            filename = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(filename, self.filtered_packets)
        print(f"Saved {len(self.filtered_packets)} packets to {filename}")

    def load_pcap_file(self, filepath):
        try:
            self.packet_list = rdpcap(filepath)
            print(f"Loaded {len(self.packet_list)} packets from {filepath}")
            self.filter_packets()
        except Exception as e:
            print(f"Failed to load pcap: {e}")

    def list_streams(self):
        self.stream_sessions.clear()
        for pkt in self.filtered_packets:
            if IP in pkt and (TCP in pkt or UDP in pkt):
                proto = TCP if TCP in pkt else UDP
                key = (pkt[IP].src, pkt[proto].sport, pkt[IP].dst, pkt[proto].dport)
                self.stream_sessions.setdefault(key, []).append(pkt)

        if not self.stream_sessions:
            print("No TCP/UDP streams found.")
            return

        print("Available streams:")
        for i, stream in enumerate(self.stream_sessions.keys()):
            print(f"{i}: {stream}")

    def follow_stream(self, index):
        try:
            stream_id = list(self.stream_sessions.keys())[index]
        except IndexError:
            print("Invalid stream index.")
            return
        packets = self.stream_sessions[stream_id]
        print(f"Following stream: {stream_id}")
        for pkt in packets:
            try:
                proto = TCP if TCP in pkt else UDP
                payload = raw(pkt[proto]).decode(errors='ignore').strip()
                if payload:
                    print(payload)
            except Exception:
                continue


def main():
    sniffer = PacketSniffer()
    while True:
        print("\n--- PacketSniffer CLI ---")
        print("1. List interfaces")
        print("2. Select interface")
        print("3. Start capture")
        print("4. Stop capture")
        print("5. Set protocol filter (ALL, TCP, UDP, ICMP)")
        print("6. Save captured packets to PCAP")
        print("7. Load packets from PCAP file")
        print("8. List streams")
        print("9. Follow a stream")
        print("0. Exit")

        choice = input("Enter choice: ").strip()

        if choice == '1':
            sniffer.list_interfaces()
        elif choice == '2':
            idx = input("Enter interface index: ")
            if idx.isdigit():
                sniffer.select_interface(int(idx))
            else:
                print("Invalid input.")
        elif choice == '3':
            sniffer.start_sniffing()
        elif choice == '4':
            sniffer.stop_sniffing()
        elif choice == '5':
            proto = input("Enter protocol filter (ALL, TCP, UDP, ICMP): ")
            if proto.upper() in ["ALL", "TCP", "UDP", "ICMP"]:
                sniffer.set_protocol_filter(proto)
            else:
                print("Invalid protocol.")
        elif choice == '6':
            sniffer.save_to_pcap()
        elif choice == '7':
            path = input("Enter path to pcap file: ")
            sniffer.load_pcap_file(path)
        elif choice == '8':
            sniffer.list_streams()
        elif choice == '9':
            idx = input("Enter stream index to follow: ")
            if idx.isdigit():
                sniffer.follow_stream(int(idx))
            else:
                print("Invalid input.")
        elif choice == '0':
            if sniffer.running:
                sniffer.stop_sniffing()
            print("Exiting.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
