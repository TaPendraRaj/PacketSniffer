import unittest
from unittest.mock import patch, MagicMock
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from packetsniffer import PacketSniffer  # Make sure your file is named packetsniffer.py


class TestPacketSniffer(unittest.TestCase):
    def setUp(self):
        self.sniffer = PacketSniffer()

        # Sample packets
        self.tcp_packet = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80) / Raw(load=b"TCP payload")
        self.udp_packet = IP(src="3.3.3.3", dst="4.4.4.4") / UDP(sport=53, dport=53) / Raw(load=b"UDP payload")
        self.sniffer.packet_list = [self.tcp_packet, self.udp_packet]
        self.sniffer.filtered_packets = [self.tcp_packet, self.udp_packet]

    def test_filter_packets_all(self):
        self.sniffer.filter_packets("ALL")
        self.assertEqual(len(self.sniffer.filtered_packets), 2)

    def test_filter_packets_tcp(self):
        self.sniffer.filter_packets("TCP")
        self.assertEqual(len(self.sniffer.filtered_packets), 1)
        self.assertTrue(self.sniffer.filtered_packets[0].haslayer(TCP))

    def test_filter_packets_udp(self):
        self.sniffer.filter_packets("UDP")
        self.assertEqual(len(self.sniffer.filtered_packets), 1)
        self.assertTrue(self.sniffer.filtered_packets[0].haslayer(UDP))

    def test_filter_packets_none_match(self):
        self.sniffer.filter_packets("ICMP")
        self.assertEqual(len(self.sniffer.filtered_packets), 0)

    @patch('packetsniffer.wrpcap')
    def test_save_to_pcap_with_packets(self, mock_wrpcap):
        self.sniffer.filtered_packets = [self.tcp_packet, self.udp_packet]
        self.sniffer.save_to_pcap(filename="dummy.pcap")
        mock_wrpcap.assert_called_once_with("dummy.pcap", self.sniffer.filtered_packets)

    @patch('packetsniffer.wrpcap')
    def test_save_to_pcap_no_packets(self, mock_wrpcap):
        self.sniffer.filtered_packets = []
        self.sniffer.save_to_pcap(filename="dummy.pcap")
        mock_wrpcap.assert_not_called()

    @patch('packetsniffer.rdpcap')
    def test_load_pcap_file_success(self, mock_rdpcap):
        mock_rdpcap.return_value = [self.tcp_packet, self.udp_packet]
        self.sniffer.load_pcap_file("dummy.pcap")
        mock_rdpcap.assert_called_once_with("dummy.pcap")
        self.assertEqual(len(self.sniffer.packet_list), 2)

    @patch('packetsniffer.rdpcap', side_effect=FileNotFoundError)
    def test_load_pcap_file_not_found(self, mock_rdpcap):
        self.sniffer.load_pcap_file("nonexistent.pcap")
        mock_rdpcap.assert_called_once_with("nonexistent.pcap")

if __name__ == '__main__':
    unittest.main()
