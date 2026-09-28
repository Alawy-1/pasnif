#!/usr/bin/env python3
# run:  sudo python3 monitor.py

import sys, time, threading, socket
from collections import Counter

from scapy.all import sniff, IP, TCP, UDP, ICMP
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTableWidget, QTableWidgetItem, QGroupBox, QGridLayout,
)

# ---------- packet counters (shared with UI thread) ----------
stats = {
    "total": 0, "bytes": 0,
    "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
    "src": Counter(),
    "ports": Counter(),
}
lock = threading.Lock()
start_time = time.time()

def handle(pkt):
    with lock:
        stats["total"] += 1
        stats["bytes"] += len(pkt)

        if pkt.haslayer(IP):
            stats["src"][pkt[IP].src] += 1
            if pkt.haslayer(TCP):
                stats["tcp"] += 1
                stats["ports"][pkt[TCP].dport] += 1
            elif pkt.haslayer(UDP):
                stats["udp"] += 1
                stats["ports"][pkt[UDP].dport] += 1
            elif pkt.haslayer(ICMP):
                stats["icmp"] += 1
            else:
                stats["other"] += 1
        else:
            stats["other"] += 1

def sniff_worker():
    sniff(prn=handle, store=False)

# ---------- reverse DNS helper ----------
def reverse_dns(ip):
    """Return hostname for an IP, or '' if not resolvable. Never raises."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# ---------- UI ----------
class Monitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Monitor")
        self.resize(900, 520)

        self._dns_cache = {}   # ip -> hostname

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        # ---- KPI panel ----
        kpi_box = QGroupBox("Summary")
        kpi = QGridLayout(kpi_box)
        self.lbl_total  = QLabel("0")
        self.lbl_bytes  = QLabel("0")
        self.lbl_uptime = QLabel("0 s")
        self.lbl_tcp    = QLabel("0")
        self.lbl_udp    = QLabel("0")
        self.lbl_icmp   = QLabel("0")
        self.lbl_other  = QLabel("0")

        for lbl in [self.lbl_total, self.lbl_bytes, self.lbl_uptime,
                    self.lbl_tcp, self.lbl_udp, self.lbl_icmp, self.lbl_other]:
            lbl.setStyleSheet("font-size: 18px; font-weight: 600;")

        kpi.addWidget(QLabel("Total packets"), 0, 0)
        kpi.addWidget(self.lbl_total,          1, 0)
        kpi.addWidget(QLabel("Total bytes"),   0, 1)
        kpi.addWidget(self.lbl_bytes,          1, 1)
        kpi.addWidget(QLabel("Uptime"),        0, 2)
        kpi.addWidget(self.lbl_uptime,         1, 2)

        kpi.addWidget(QLabel("TCP"),   2, 0); kpi.addWidget(self.lbl_tcp,  3, 0)
        kpi.addWidget(QLabel("UDP"),   2, 1); kpi.addWidget(self.lbl_udp,  3, 1)
        kpi.addWidget(QLabel("ICMP"),  2, 2); kpi.addWidget(self.lbl_icmp, 3, 2)
        kpi.addWidget(QLabel("Other"), 2, 3); kpi.addWidget(self.lbl_other,3, 3)

        layout.addWidget(kpi_box)

        # ---- tables side-by-side ----
        row = QHBoxLayout()

        self.src_table = QTableWidget(0, 3)
        self.src_table.setHorizontalHeaderLabels(["Source IP", "Hostname", "Packets"])
        self.src_table.horizontalHeader().setStretchLastSection(True)
        self.src_table.verticalHeader().setVisible(False)
        self.src_table.setColumnWidth(1, 220)

        self.port_table = QTableWidget(0, 2)
        self.port_table.setHorizontalHeaderLabels(["Dest port", "Packets"])
        self.port_table.horizontalHeader().setStretchLastSection(True)
        self.port_table.verticalHeader().setVisible(False)

        src_box  = QGroupBox("Top source IPs")
        QVBoxLayout(src_box).addWidget(self.src_table)

        port_box = QGroupBox("Top destination ports")
        QVBoxLayout(port_box).addWidget(self.port_table)

        row.addWidget(src_box, 2)
        row.addWidget(port_box, 1)
        layout.addLayout(row)

        # ---- start sniffing + refresh timer ----
        threading.Thread(target=sniff_worker, daemon=True).start()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)

    # ---------- helpers ----------
    def name_of(self, ip):
        """Cached reverse DNS. Empty string if none. Never blocks sniffing."""
        if ip not in self._dns_cache:
            self._dns_cache[ip] = reverse_dns(ip)
        return self._dns_cache[ip]

    def fill(self, table, rows, with_hostname=False):
        table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            if with_hostname:
                ip, count = row
                host = self.name_of(ip) or "—"
                table.setItem(i, 0, QTableWidgetItem(ip))
                table.setItem(i, 1, QTableWidgetItem(host))
                item = QTableWidgetItem(f"{count:,}")
                item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                table.setItem(i, 2, item)
            else:
                key, count = row
                table.setItem(i, 0, QTableWidgetItem(str(key)))
                item = QTableWidgetItem(f"{count:,}")
                item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                table.setItem(i, 1, item)

    # ---------- UI refresh ----------
    def refresh(self):
        with lock:
            snap = {
                "total": stats["total"], "bytes": stats["bytes"],
                "tcp": stats["tcp"], "udp": stats["udp"],
                "icmp": stats["icmp"], "other": stats["other"],
                "src": stats["src"].most_common(10),
                "ports": stats["ports"].most_common(10),
            }

        self.lbl_total.setText(f"{snap['total']:,}")
        self.lbl_bytes.setText(f"{snap['bytes']:,}")
        self.lbl_uptime.setText(f"{int(time.time() - start_time)} s")
        self.lbl_tcp.setText(f"{snap['tcp']:,}")
        self.lbl_udp.setText(f"{snap['udp']:,}")
        self.lbl_icmp.setText(f"{snap['icmp']:,}")
        self.lbl_other.setText(f"{snap['other']:,}")

        self.fill(self.src_table, snap["src"], with_hostname=True)
        self.fill(self.port_table, snap["ports"], with_hostname=False)

# ---------- main ----------
def main():
    app = QApplication(sys.argv)
    win = Monitor()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()