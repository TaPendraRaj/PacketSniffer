import customtkinter as ctk
from scapy.all import sniff, wrpcap, rdpcap, raw, TCP, UDP, IP, ICMP
import threading
import datetime

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

class PacketSnifferGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PacketSniffer - Advanced GUI")
        self.geometry("1200x700")

        self.packet_list = []
        self.filtered_packets = []
        self.protocol_filter = ctk.StringVar(value="ALL")
        self.stream_sessions = {}
        self.capture_thread = None
        self.running = False

        self.create_widgets()

    def create_widgets(self):
        control_frame = ctk.CTkFrame(self)
        control_frame.pack(fill='x', padx=10, pady=5)

        # Interface dropdown
        from scapy.all import get_if_list
        self.iface_menu = ctk.CTkOptionMenu(control_frame, values=get_if_list())
        self.iface_menu.pack(side='left', padx=5)

        self.start_btn = ctk.CTkButton(control_frame, text="Start Capture", command=self.start_sniffing)
        self.start_btn.pack(side='left', padx=5)

        self.stop_btn = ctk.CTkButton(control_frame, text="Stop Capture", command=self.stop_sniffing, state='disabled')
        self.stop_btn.pack(side='left', padx=5)

        self.load_pcap_btn = ctk.CTkButton(control_frame, text="Load .pcap File", command=self.load_pcap_file)
        self.load_pcap_btn.pack(side='left', padx=5)

        self.protocol_menu = ctk.CTkOptionMenu(control_frame,
                                               values=["ALL", "TCP", "UDP", "ICMP"],
                                               variable=self.protocol_filter,
                                               command=self.filter_packets)
        self.protocol_menu.pack(side='left', padx=5)

        self.save_btn = ctk.CTkButton(control_frame, text="Save to PCAP", command=self.save_to_pcap)
        self.save_btn.pack(side='left', padx=5)

        self.follow_stream_btn = ctk.CTkButton(control_frame, text="Follow Stream", command=self.open_stream_selector)
        self.follow_stream_btn.pack(side='left', padx=5)

        self.packet_box = ctk.CTkTextbox(self, width=1180, height=450)
        self.packet_box.pack(padx=10, pady=10, fill='both', expand=True)

    def start_sniffing(self):
        if self.running:
            return
        self.running = True
        self.start_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self.packet_box.delete("1.0", "end")
        self.packet_list.clear()
        self.filtered_packets.clear()
        iface = self.iface_menu.get()
        self.capture_thread = threading.Thread(target=self.sniff_packets, args=(iface,), daemon=True)
        self.capture_thread.start()

    def stop_sniffing(self):
        if not self.running:
            return
        self.running = False
        self.start_btn.configure(state='normal')
        self.stop_btn.configure(state='disabled')

    def sniff_packets(self, iface):
        try:
            sniff(iface=iface, prn=self.process_packet, store=False, stop_filter=lambda x: not self.running)
        except Exception as e:
            self.packet_box.insert("end", f"Error during sniffing: {e}\n")
            self.running = False
            self.start_btn.configure(state='normal')
            self.stop_btn.configure(state='disabled')

    def process_packet(self, packet):
        self.packet_list.append(packet)
        proto = self.protocol_filter.get()
        if proto == "ALL" or packet.haslayer(proto):
            self.filtered_packets.append(packet)
            self.packet_box.insert("end", f"{datetime.datetime.now().strftime('%H:%M:%S')} - {packet.summary()}\n")
            self.packet_box.see("end")

    def filter_packets(self, _):
        self.packet_box.delete("1.0", "end")
        self.filtered_packets.clear()
        proto = self.protocol_filter.get()
        for pkt in self.packet_list:
            if proto == "ALL" or pkt.haslayer(proto):
                self.filtered_packets.append(pkt)
                self.packet_box.insert("end", f"{pkt.summary()}\n")

    def save_to_pcap(self):
        if not self.filtered_packets:
            self.packet_box.insert("end", "[!] No packets to save.\n")
            return
        filename = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(filename, self.filtered_packets)
        self.packet_box.insert("end", f"[+] Saved {len(self.filtered_packets)} packets to {filename}\n")

    def load_pcap_file(self):
        from tkinter.filedialog import askopenfilename
        path = askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
        if not path:
            return
        try:
            self.packet_list = rdpcap(path)
            self.filter_packets(None)
            self.packet_box.insert("end", f"[+] Loaded {len(self.packet_list)} packets from {path}\n")
        except Exception as e:
            self.packet_box.insert("end", f"[!] Failed to load pcap: {e}\n")

    def open_stream_selector(self):
        self.stream_sessions.clear()
        for pkt in self.filtered_packets:
            if IP in pkt and (TCP in pkt or UDP in pkt):
                proto = TCP if TCP in pkt else UDP
                key = (pkt[IP].src, pkt[proto].sport, pkt[IP].dst, pkt[proto].dport)
                self.stream_sessions.setdefault(key, []).append(pkt)

        if not self.stream_sessions:
            self.packet_box.insert("end", "[-] No TCP/UDP streams found.\n")
            return

        stream_win = ctk.CTkToplevel(self)
        stream_win.title("Follow Stream")
        stream_win.geometry("450x400")

        label = ctk.CTkLabel(stream_win, text="Available Streams:")
        label.pack(pady=5)

        self.stream_keys = list(self.stream_sessions.keys())
        self.selected_stream_idx = ctk.StringVar()

        self.stream_list = ctk.CTkTextbox(stream_win, height=250)
        self.stream_list.pack(padx=10, pady=5, fill='both', expand=True)

        for i, stream in enumerate(self.stream_keys):
            self.stream_list.insert("end", f"{i}: {stream}\n")

        entry = ctk.CTkEntry(stream_win, textvariable=self.selected_stream_idx, placeholder_text="Enter stream index")
        entry.pack(pady=5)

        follow_btn = ctk.CTkButton(stream_win, text="Follow", command=self.show_stream_popup)
        follow_btn.pack(pady=5)

    def show_stream_popup(self):
        index = self.selected_stream_idx.get()
        try:
            idx = int(index)
            stream_id = self.stream_keys[idx]
        except (ValueError, IndexError):
            return

        packets = self.stream_sessions[stream_id]

        popup = ctk.CTkToplevel(self)
        popup.title(f"Stream: {stream_id}")
        popup.geometry("900x600")

        textbox = ctk.CTkTextbox(popup, wrap="word")
        textbox.pack(fill='both', expand=True, padx=10, pady=10)

        for pkt in packets:
            try:
                proto = TCP if TCP in pkt else UDP
                payload = raw(pkt[proto]).decode(errors='ignore')
                if payload.strip():
                    textbox.insert("end", payload + "\n")
            except Exception:
                continue

if __name__ == "__main__":
    app = PacketSnifferGUI()
    app.mainloop()
