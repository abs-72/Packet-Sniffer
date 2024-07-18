import importlib

# List of required modules
required_modules = [
    'sys',
    'threading',
    'time',
    'scapy',
    'PyQt5',
    'binascii'
]

# Check if each module is installed
missing_modules = []
for mod in required_modules:
    try:
        importlib.import_module(mod)
    except ModuleNotFoundError:
        missing_modules.append(mod)

if missing_modules:
    print("The following modules are missing and need to be installed:")
    for mod in missing_modules:
        print(mod)
    
    # Prompt user to install missing modules
    install = input("Do you want to install these modules? (y/n): ").lower()
    if install == 'y':
        import subprocess
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', *missing_modules])
        print("Modules installed successfully. Running the main script...")
    else:
        print("Cannot proceed without installing required modules.")
        exit()
else:
    print("All required modules are already installed. Running the main script...")

# Main code starts here
if 'scapy' in required_modules:
    from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR
if 'PyQt5' in required_modules:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
        QVBoxLayout, QWidget, QPushButton, QLineEdit, QHBoxLayout, QTextEdit, QLabel,
        QMessageBox, QFileDialog
    )
    from PyQt5.QtCore import Qt
if 'binascii' in required_modules:
    import binascii

import sys
import threading
import time

class PacketDetailsWindow(QWidget):
    def __init__(self, packet_info, on_close_callback):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(150, 150, 600, 400)

        # Set stylesheet
        self.setStyleSheet("""
            QWidget {
                background-color: #2E2E2E;  /* Dark background */
                color: white;                /* White text */
            }
            QTextEdit {
                background-color: #1E1E1E;   /* Dark text edit background */
                color: white;                /* White text */
            }
        """)

        self.on_close_callback = on_close_callback
        layout = QVBoxLayout(self)
        self.details_text = QTextEdit(self)
        self.details_text.setReadOnly(True)
        layout.addWidget(self.details_text)
        self.set_details(packet_info)

    def set_details(self, packet_info):
        self.details_text.setPlainText(packet_info)

    def closeEvent(self, event):
        self.on_close_callback()
        event.accept()

class PacketSniffer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 800, 600)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #2E2E2E;  /* Dark background */
                color: white;                /* White text */
            }
            QTableWidget {
                background-color: #1E1E1E;  /* Darker table background */
                color: white;                /* White text */
            }
            QPushButton {
                background-color: #4CAF50;  /* Green button */
                color: white;                /* White text */
                border: none;                /* No border */
                padding: 10px;               /* Padding */
                border-radius: 5px;         /* Rounded corners */
            }
            QPushButton:hover {
                background-color: #45a049;   /* Darker green on hover */
            }
            QLineEdit {
                background-color: #3A3A3A;   /* Dark input field */
                color: white;                /* White text */
            }
            QTextEdit {
                background-color: #1E1E1E;   /* Dark text edit background */
                color: white;                /* White text */
            }
        """)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout(self.central_widget)
        self.filter_layout = QHBoxLayout()
        self.filter_label = QLineEdit(self)
        self.filter_label.setPlaceholderText("Enter filter (e.g., 'tcp or udp')")
        self.start_button = QPushButton("Start", self)
        self.stop_button = QPushButton("Stop", self)
        self.stop_button.setEnabled(False)

        self.filter_layout.addWidget(self.filter_label)
        self.filter_layout.addWidget(self.start_button)
        self.filter_layout.addWidget(self.stop_button)

        self.layout.addLayout(self.filter_layout)

        self.packet_table = QTableWidget(self)
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(["No", "Time", "Source IP", "Destination IP", "Protocol", "Length", "Info"])
        self.layout.addWidget(self.packet_table)

        self.search_layout = QHBoxLayout()
        self.search_label = QLabel("Search:", self)
        self.search_input = QLineEdit(self)
        self.search_input.setPlaceholderText("Enter search term")
        self.search_button = QPushButton("Search", self)

        self.search_layout.addWidget(self.search_label)
        self.search_layout.addWidget(self.search_input)
        self.search_layout.addWidget(self.search_button)
        self.layout.addLayout(self.search_layout)

        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.search_button.clicked.connect(self.search_packets)
        self.packet_table.cellDoubleClicked.connect(self.show_packet_details)

        self.packet_data = []
        self.stop_sniffing_event = threading.Event()

    def start_sniffing(self):
        self.stop_sniffing_event.clear()
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_sniffing(self):
        self.stop_sniffing_event.set()
        self.sniff_thread.join()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def sniff_packets(self):
        filter_str = self.filter_label.text()
        sniff(filter=filter_str, prn=self.process_packet, stop_filter=lambda x: self.stop_sniffing_event.is_set())

    def process_packet(self, packet):
        if IP in packet:
            packet_num = len(self.packet_data) + 1
            time_stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)

            # Determine the protocol
            if TCP in packet:
                tcp = packet[TCP]
                if tcp.dport == 80 or tcp.sport == 80:
                    protocol = "HTTP"
                    http_data = bytes(tcp.payload)
                    info = self.parse_http(http_data)
                elif tcp.dport == 443 or tcp.sport == 443:
                    protocol = "HTTPS"
                    info = "HTTPS traffic (encrypted data not shown)"
                else:
                    protocol = "TCP"
                    info = f'Src Port: {tcp.sport}, Dst Port: {tcp.dport}, Seq: {tcp.seq}, Ack: {tcp.ack}, Flags: {self.get_tcp_flags(tcp.flags)}'

            elif UDP in packet:
                udp = packet[UDP]
                if udp.dport == 53 or udp.sport == 53:
                    dns = packet[DNS]
                    if dns.qr == 0:  # Query
                        protocol = "DNS"
                        info = self.parse_dns_query(dns)
                    else:  # Response
                        protocol = "DNS"
                        info = self.parse_dns_response(dns)
                else:
                    protocol = "UDP"
                    info = f'Src Port: {udp.sport}, Dst Port: {udp.dport}, Length: {udp.len}'

            elif ICMP in packet:
                protocol = "ICMP"
                info = f'Type: {packet[ICMP].type}, Code: {packet[ICMP].code}'
            else:
                protocol = "Other"
                info = "Unknown protocol data"

            self.packet_data.append((packet_num, time_stamp, src_ip, dst_ip, protocol, length, info, packet))
            self.update_packet_list(packet_num, time_stamp, src_ip, dst_ip, protocol, length, info)

    def parse_http(self, http_data):
        try:
            lines = http_data.decode().splitlines()
            request_line = lines[0] if lines else "No data"
            headers = "\n".join(lines[1:])
            return f"HTTP Request:\n{request_line}\n{headers}"
        except Exception as e:
            return "Failed to parse HTTP data"

    def parse_dns_query(self, dns):
        query_info = ""
        for question in dns[DNSQR]:
            query_info += f"DNS Query:\n\tName: {question.qname.decode()}\n\tType: {question.qtype}, Class: {question.qclass}\n"
        return query_info

    def parse_dns_response(self, dns):
        response_info = "DNS Response:\n"
        if DNSRR in dns:
            for answer in dns[DNSRR]:
                response_info += f"\tName: {answer.rrname.decode()}\n\tType: {answer.type}, Class: {answer.rclass}, TTL: {answer.ttl}, Address: {answer.rdata}\n"
        return response_info

    def update_packet_list(self, packet_num, time_stamp, src_ip, dst_ip, protocol, length, info):
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)
        self.packet_table.setItem(row_position, 0, QTableWidgetItem(str(packet_num)))
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(str(time_stamp)))
        self.packet_table.setItem(row_position, 2, QTableWidgetItem(src_ip))
        self.packet_table.setItem(row_position, 3, QTableWidgetItem(dst_ip))
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(protocol))
        self.packet_table.setItem(row_position, 5, QTableWidgetItem(str(length)))
        self.packet_table.setItem(row_position, 6, QTableWidgetItem(info))

    def search_packets(self):
        search_term = self.search_input.text().lower()
        if not search_term:
            return

        filtered_packets = [pkt for pkt in self.packet_data if search_term in pkt[2].lower() or search_term in pkt[3].lower() or search_term in pkt[4].lower() or search_term in pkt[6].lower()]

        self.packet_table.setRowCount(0)
        for packet in filtered_packets:
            self.update_packet_list(*packet[:7])

    def show_packet_details(self, row, column):
        packet_info = self.packet_data[row]
        details = self.format_packet_info(packet_info)

        self.details_window = PacketDetailsWindow(details, self.on_packet_details_window_close)
        self.details_window.show()

    def on_packet_details_window_close(self):
        pass  # Do nothing when the packet details window is closed

    def format_packet_info(self, packet_info):
        packet_num, time_stamp, src_ip, dst_ip, protocol, length, info, packet = packet_info
        details = f"""
        Packet Number: {packet_num}
        Timestamp: {time_stamp}
        Source IP: {src_ip}
        Destination IP: {dst_ip}
        Protocol: {protocol}
        Length: {length}
        Info: {info}
        """
        if Ether in packet:
            details += f"Ethernet Frame:\n\tSource MAC: {packet[Ether].src}\n\tDestination MAC: {packet[Ether].dst}\n"
        if IP in packet:
            details += f"IP Packet:\n\tVersion: {packet[IP].version}\n\tHeader Length: {packet[IP].ihl}\n\tTTL: {packet[IP].ttl}\n\tChecksum: {packet[IP].chksum}\n"
        if TCP in packet:
            details += f"TCP Segment:\n\tSource Port: {packet[TCP].sport}\n\tDestination Port: {packet[TCP].dport}\n\tSequence Number: {packet[TCP].seq}\n\tAcknowledgment Number: {packet[TCP].ack}\n\tFlags: {self.get_tcp_flags(packet[TCP].flags)}\n"
        elif UDP in packet:
            details += f"UDP Datagram:\n\tSource Port: {packet[UDP].sport}\n\tDestination Port: {packet[UDP].dport}\n\tLength: {packet[UDP].len}\n\tChecksum: {packet[UDP].chksum}\n"
        elif ICMP in packet:
            details += f"ICMP Packet:\n\tType: {packet[ICMP].type}\n\tCode: {packet[ICMP].code}\n\tChecksum: {packet[ICMP].chksum}\n"

        # Displaying full packet content in hexadecimal and ASCII
        hex_data = binascii.hexlify(bytes(packet)).decode()
        ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in bytes(packet))
        details += f"\nRaw Data (Hexadecimal):\n{hex_data}\n\nRaw Data (ASCII):\n{ascii_data}\n"

        return details

    def get_tcp_flags(self, flags):
        flags_str = ""
        if flags & 0x01: flags_str += "FIN,"
        if flags & 0x02: flags_str += "SYN,"
        if flags & 0x04: flags_str += "RST,"
        if flags & 0x08: flags_str += "PSH,"
        if flags & 0x10: flags_str += "ACK,"
        if flags & 0x20: flags_str += "URG,"
        if flags & 0x40: flags_str += "ECE,"
        if flags & 0x80: flags_str += "CWR,"
        return flags_str.strip(",")

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Message',
            "Do you want to save the captured packets before exiting?", QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel, QMessageBox.Cancel)

        if reply == QMessageBox.Yes:
            file_path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "PCAP Files (*.pcap);;All Files (*)")
            if file_path:
                packets = [pkt[-1] for pkt in self.packet_data]
                wrpcap(file_path, packets)
                print(f"Packets saved to {file_path}")
                event.accept()
            else:
                event.ignore()
        elif reply == QMessageBox.No:
            event.accept()
        else:
            event.ignore()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSniffer()
    window.show()
    sys.exit(app.exec_())
