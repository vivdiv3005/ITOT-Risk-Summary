from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
import random

packets = []

# Helper
def mac(prefix, n): return f"{prefix}:{n:02x}:{n:02x}"

# --- OT DEVICES ---
# Siemens S7 PLC (port 102)
for i in range(20):
    p = Ether(src="00:0e:8c:11:22:01", dst="00:0a:e4:cc:01:01") / \
        IP(src="10.0.0.11", dst="10.0.2.10") / \
        TCP(sport=1024+i, dport=102, flags="PA") / \
        Raw(load=b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x09")
    packets.append(p)

# Modbus TCP (port 502) - Allen Bradley PLC
for i in range(30):
    p = Ether(src="00:00:bc:aa:bb:01", dst="00:0a:e4:cc:01:01") / \
        IP(src="10.0.0.13", dst="10.0.2.10") / \
        TCP(sport=2048+i, dport=502, flags="PA") / \
        Raw(load=b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x64\x00\x0a")
    packets.append(p)

# Modbus TCP response back
for i in range(30):
    p = Ether(src="00:0a:e4:cc:01:01", dst="00:00:bc:aa:bb:01") / \
        IP(src="10.0.2.10", dst="10.0.0.13") / \
        TCP(sport=502, dport=2048+i, flags="PA") / \
        Raw(load=b"\x00\x01\x00\x00\x00\x17\x01\x03\x14" + b"\x00\x01"*10)
    packets.append(p)

# DNP3 (port 20000) - Schneider controller
for i in range(15):
    p = Ether(src="00:1b:1b:aa:01:01", dst="00:0a:e4:cc:01:01") / \
        IP(src="10.0.1.10", dst="10.0.2.10") / \
        TCP(sport=3000+i, dport=20000, flags="PA") / \
        Raw(load=b"\x05\x64\x14\xc4\x01\x00\x03\x00\xbd\x21\xc0\xc1\x01\x3c\x02\x06\x3c\x03\x06\x3c\x04\x06")
    packets.append(p)

# EtherNet/IP (port 44818) - Rockwell
for i in range(20):
    p = Ether(src="00:00:bc:aa:bb:02", dst="00:0a:e4:cc:01:01") / \
        IP(src="10.0.0.13", dst="10.0.2.10") / \
        TCP(sport=4000+i, dport=44818, flags="PA") / \
        Raw(load=b"\x65\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00")
    packets.append(p)

# OPC-UA (port 4840) - Historian
for i in range(10):
    p = Ether(src="00:80:f4:dd:01:01", dst="00:0a:e4:cc:01:01") / \
        IP(src="10.0.2.12", dst="10.0.2.10") / \
        TCP(sport=5000+i, dport=4840, flags="PA") / \
        Raw(load=b"HEL\x46\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x01\x00\x00\x00")
    packets.append(p)

# Siemens S7 ISO-TSAP (port 102) from HMI
for i in range(12):
    p = Ether(src="00:0a:e4:cc:01:02", dst="00:0e:8c:11:22:01") / \
        IP(src="10.0.2.11", dst="10.0.0.11") / \
        TCP(sport=6000+i, dport=102, flags="PA") / \
        Raw(load=b"\x03\x00\x00\x1f\x1a\xf0\x80\x32\x01\x00\x00\x04\x00\x00\x0e\x00\x00\xf0\x00\x00\x01\x00\x01\x01\xe0")
    packets.append(p)

# --- CRITICAL: Rogue device doing Modbus from IT segment ---
for i in range(8):
    p = Ether(src="de:ad:be:ef:00:01", dst="00:0e:8c:11:22:01") / \
        IP(src="192.168.1.99", dst="10.0.0.11") / \
        TCP(sport=7000+i, dport=502, flags="PA") / \
        Raw(load=b"\x00\x01\x00\x00\x00\x06\x01\x06\x01\xf4\x00\x0a")  # write register!
    packets.append(p)

# --- IT DEVICES ---
# RDP on SCADA server
for i in range(15):
    p = Ether(src="aa:bb:cc:dd:ee:01", dst="00:0a:e4:cc:01:01") / \
        IP(src="192.168.1.10", dst="10.0.2.10") / \
        TCP(sport=8000+i, dport=3389, flags="PA") / \
        Raw(load=b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x0b\x00\x00\x00")
    packets.append(p)

# SMB on SCADA server
for i in range(10):
    p = Ether(src="aa:bb:cc:dd:ee:01", dst="00:0a:e4:cc:01:01") / \
        IP(src="192.168.1.10", dst="10.0.2.10") / \
        TCP(sport=9000+i, dport=445, flags="PA") / \
        Raw(load=b"\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\xc8\x00\x00")
    packets.append(p)

# VNC on HMI - CRITICAL
for i in range(12):
    p = Ether(src="aa:bb:cc:dd:ee:01", dst="00:0a:e4:cc:01:02") / \
        IP(src="192.168.1.10", dst="10.0.2.11") / \
        TCP(sport=10000+i, dport=5900, flags="PA") / \
        Raw(load=b"RFB 003.008\n")
    packets.append(p)

# SSH to jump server
for i in range(8):
    p = Ether(src="aa:bb:cc:dd:ee:02", dst="00:80:f4:dd:02:02") / \
        IP(src="192.168.1.11", dst="10.0.3.2") / \
        TCP(sport=11000+i, dport=22, flags="PA") / \
        Raw(load=b"SSH-2.0-OpenSSH_8.9\r\n")
    packets.append(p)

# HTTPS corporate laptop
for i in range(20):
    p = Ether(src="aa:bb:cc:dd:ee:02", dst="00:80:f4:dd:02:01") / \
        IP(src="192.168.1.11", dst="10.0.3.1") / \
        TCP(sport=12000+i, dport=443, flags="PA") / \
        Raw(load=b"\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03")
    packets.append(p)

# ARP discovery
for ip_end, mac_addr in [("11","00:0e:8c:11:22:01"),("12","00:0e:8c:11:22:02"),
                          ("13","00:00:bc:aa:bb:01"),("15","00:30:48:ee:ff:01")]:
    p = Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") / \
        ARP(op=1, hwsrc=mac_addr, psrc=f"10.0.0.{ip_end}", pdst="10.0.0.1")
    packets.append(p)

# Shuffle for realism
random.shuffle(packets)

# Write PCAP
wrpcap("/home/claude/ot_it_sample.pcap", packets)
print(f"Written {len(packets)} packets to ot_it_sample.pcap")
