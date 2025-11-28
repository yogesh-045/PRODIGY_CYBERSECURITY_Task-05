# PRODIGY_CYBERSECURITY_Task-05
# Network Packet Analyzer (Task-05)

This repository contains a simple **Network Packet Analyzer** implemented in Python using **Scapy**.  
Designed for **educational** and **ethical** use — capture only on networks where you have permission.

## Features
- Capture live network packets (with optional BPF filter)
- Display source/destination IP, protocol (TCP/UDP/ICMP/etc.)
- Parse common headers (Ether, IP, TCP, UDP, ICMP)
- Show brief payload preview (hex / ascii) — truncated for safety
- Save captured packet summary to a log file

## Requirements
- Python 3.8+
- scapy (`pip install scapy`)
- On Linux/macOS: run as root (or use sudo)
- On Windows: install npcap and run with appropriate privileges

# How to run
1. Install dependencies:
2. Run the script with sudo (or admin):

Options:
- `--interface` : network interface to sniff (default: auto)
- `--count`     : number of packets to capture (default: 0 -> unlimited until CTRL+C)
- `--filter`    : BPF filter string (optional), e.g., "tcp", "udp port 53", "icmp"

## Safety & Ethics
- Use only on networks where you have explicit permission.
- Do not capture or store sensitive personal data unnecessarily.
- This tool is for learning and demonstration only.

## Example output

[1] 2025-01-0 18:00:01 SRC=192.168.1.10:54321 DST=93.184.216.34:80 PROTO=TCP LEN=60 PAYLOAD=GET /index.html...


## File structure
packet_analyzer.py

This implementation is prepared for **PRODIGY InfoTech – Task 05** (Network Packet Analyzer). Include screenshots of running the script on your local lab/network if required.


