#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  TASK 4 — Network Intrusion Detection System | CodeAlpha Internship ║
╚══════════════════════════════════════════════════════════════════╝

Requirements:
    pip install scapy colorama

Run with admin/root privileges:
    Windows : Run terminal as Administrator → python task4_nids.py
    Linux   : sudo python3 task4_nids.py

Detection capabilities:
    ✔ Port Scan        (SYN scan — too many ports from one source)
    ✔ SYN Flood        (DoS — excessive SYN packets to one destination)
    ✔ ICMP Flood       (Ping flood — too many ICMP requests)
    ✔ Suspicious Ports (access to well-known attack vectors)
    ✔ Payload Patterns (SQL injection, shell commands, etc.)
    ✔ ARP Spoofing     (IP ↔ MAC inconsistency detection)
    ✔ DNS Anomalies    (unusually long domain names — DNS tunneling)
"""

import sys
import time
import argparse
import logging
import json
import threading
from datetime import datetime
from collections import defaultdict

# ── Graceful imports ─────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, ARP
except ImportError:
    print("\n[ERROR] scapy is not installed. Run: pip install scapy\n")
    sys.exit(1)

try:
    import colorama; colorama.init()
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
except ImportError:
    RED = GREEN = YELLOW = CYAN = BLUE = MAGENTA = BOLD = RESET = ""

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# ═══════════════════════════════════════════════════════════════════
#  CONFIGURATION — tweak thresholds here
# ═══════════════════════════════════════════════════════════════════
CONFIG = {
    # Port scan: unique destination ports from one source within window_sec
    "port_scan_threshold": 15,
    "port_scan_window_sec": 5,

    # SYN flood: SYN packets to one destination within window_sec
    "syn_flood_threshold": 50,
    "syn_flood_window_sec": 3,

    # ICMP flood: ICMP echo requests from one source within window_sec
    "icmp_flood_threshold": 30,
    "icmp_flood_window_sec": 3,

    # DNS tunneling: domain name length (labels + dots)
    "dns_tunnel_domain_len": 50,

    # Suspicious destination ports (beyond normal traffic)
    "suspicious_ports": {
        23:    "Telnet (plaintext)",
        445:   "SMB (ransomware vector)",
        1433:  "MSSQL",
        3389:  "RDP (remote desktop)",
        4444:  "Metasploit default",
        5900:  "VNC",
        6667:  "IRC (botnet C2)",
        31337: "Elite / Back Orifice",
        8080:  "Alternate HTTP proxy",
    },

    # Payload patterns to flag (regex-style strings matched via 'in')
    "payload_patterns": [
        # SQL Injection
        ("' OR '1'='1",        "SQL Injection pattern"),
        ("SELECT * FROM",       "SQL Injection — SELECT *"),
        ("UNION SELECT",        "SQL Injection — UNION"),
        ("DROP TABLE",          "SQL Injection — DROP"),
        # Command injection
        ("; /bin/sh",           "Command injection — shell"),
        ("cmd.exe",             "Command injection — cmd.exe"),
        ("powershell",          "Command injection — PowerShell"),
        # Path traversal
        ("../../../",           "Path traversal"),
        # Reverse shell indicators
        ("bash -i",             "Reverse shell attempt"),
        ("nc -e",               "Netcat reverse shell"),
        # XSS
        ("<script>",            "XSS — script tag"),
        ("javascript:",         "XSS — javascript: URI"),
    ],

    # Log file path
    "log_file": "nids_alerts.log",

    # Show dashboard every N seconds (0 = disabled)
    "dashboard_interval": 30,
}

# ═══════════════════════════════════════════════════════════════════
#  GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════
# port_scan_tracker[src_ip] = {port_set, first_seen}
port_scan_tracker: dict = defaultdict(lambda: {"ports": set(), "first_seen": 0.0})

# syn_flood_tracker[dst_ip] = {count, first_seen}
syn_flood_tracker: dict = defaultdict(lambda: {"count": 0, "first_seen": 0.0})

# icmp_flood_tracker[src_ip] = {count, first_seen}
icmp_flood_tracker: dict = defaultdict(lambda: {"count": 0, "first_seen": 0.0})

# ARP table: ip → mac
arp_table: dict = {}

# Alert counters per type
alert_counts: dict = defaultdict(int)
alert_counts_lock = threading.Lock()

total_packets = 0
start_time    = time.time()

# ═══════════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════════
file_logger = logging.getLogger("NIDS")
file_logger.setLevel(logging.INFO)

_fh = logging.FileHandler(CONFIG["log_file"])
_fh.setFormatter(logging.Formatter("%(asctime)s | %(message)s", "%Y-%m-%d %H:%M:%S"))
file_logger.addHandler(_fh)

# ═══════════════════════════════════════════════════════════════════
#  ALERT SYSTEM
# ═══════════════════════════════════════════════════════════════════
SEVERITY_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
}


def fire_alert(severity: str, alert_type: str, detail: str, packet_summary: str = ""):
    """Print a formatted alert to console and write to log file."""
    now = datetime.now().strftime("%H:%M:%S")
    color = SEVERITY_COLOR.get(severity, RESET)

    # Console
    print(f"\n{'!'*70}")
    print(f"  {color}[{severity}]{RESET}  {BOLD}{alert_type}{RESET}  @  {now}")
    print(f"  Detail  : {detail}")
    if packet_summary:
        print(f"  Packet  : {packet_summary}")
    print(f"{'!'*70}")

    # Log file
    log_line = f"[{severity}] {alert_type} | {detail}"
    if packet_summary:
        log_line += f" | PKT: {packet_summary}"
    file_logger.info(log_line)

    # Stats
    with alert_counts_lock:
        alert_counts[alert_type] += 1


# ═══════════════════════════════════════════════════════════════════
#  DETECTION ENGINES
# ═══════════════════════════════════════════════════════════════════

def detect_port_scan(src_ip: str, dst_port: int):
    now = time.time()
    entry = port_scan_tracker[src_ip]

    if now - entry["first_seen"] > CONFIG["port_scan_window_sec"]:
        entry["ports"]      = set()
        entry["first_seen"] = now

    entry["ports"].add(dst_port)

    if len(entry["ports"]) >= CONFIG["port_scan_threshold"]:
        fire_alert(
            "HIGH", "PORT SCAN DETECTED",
            f"Source {src_ip} probed {len(entry['ports'])} unique ports "
            f"in {CONFIG['port_scan_window_sec']}s",
        )
        entry["ports"]      = set()   # reset to avoid repeated alerts
        entry["first_seen"] = now


def detect_syn_flood(src_ip: str, dst_ip: str, flags: str):
    if "S" not in flags or "A" in flags:
        return
    now   = time.time()
    entry = syn_flood_tracker[dst_ip]

    if now - entry["first_seen"] > CONFIG["syn_flood_window_sec"]:
        entry["count"]      = 0
        entry["first_seen"] = now

    entry["count"] += 1

    if entry["count"] >= CONFIG["syn_flood_threshold"]:
        fire_alert(
            "CRITICAL", "SYN FLOOD (DoS) DETECTED",
            f"{src_ip} → {dst_ip}: {entry['count']} SYN packets "
            f"in {CONFIG['syn_flood_window_sec']}s",
        )
        entry["count"]      = 0
        entry["first_seen"] = now


def detect_icmp_flood(src_ip: str, icmp_type: int):
    if icmp_type != 8:   # Only Echo Requests
        return
    now   = time.time()
    entry = icmp_flood_tracker[src_ip]

    if now - entry["first_seen"] > CONFIG["icmp_flood_window_sec"]:
        entry["count"]      = 0
        entry["first_seen"] = now

    entry["count"] += 1

    if entry["count"] >= CONFIG["icmp_flood_threshold"]:
        fire_alert(
            "HIGH", "ICMP FLOOD (PING FLOOD) DETECTED",
            f"Source {src_ip}: {entry['count']} ICMP Echo Requests "
            f"in {CONFIG['icmp_flood_window_sec']}s",
        )
        entry["count"]      = 0
        entry["first_seen"] = now


def detect_suspicious_port(src_ip: str, dst_ip: str, dst_port: int):
    if dst_port in CONFIG["suspicious_ports"]:
        label = CONFIG["suspicious_ports"][dst_port]
        fire_alert(
            "MEDIUM", "SUSPICIOUS PORT ACCESS",
            f"{src_ip} → {dst_ip}:{dst_port}  ({label})",
        )


def detect_payload_patterns(src_ip: str, dst_ip: str, raw_bytes: bytes):
    try:
        payload = raw_bytes.decode("utf-8", errors="replace").lower()
    except Exception:
        return

    for pattern, description in CONFIG["payload_patterns"]:
        if pattern.lower() in payload:
            # Show a 60-char snippet around the match
            idx     = payload.find(pattern.lower())
            snippet = payload[max(0, idx-10): idx+50].replace("\n", " ")
            fire_alert(
                "CRITICAL", "MALICIOUS PAYLOAD DETECTED",
                f"{description}  |  {src_ip} → {dst_ip}",
                f"…{snippet}…",
            )
            break   # One alert per packet is enough


def detect_arp_spoofing(pkt):
    arp = pkt[ARP]
    if arp.op != 2:   # Only ARP Replies
        return
    ip_addr  = arp.psrc
    mac_addr = arp.hwsrc

    if ip_addr in arp_table:
        if arp_table[ip_addr] != mac_addr:
            fire_alert(
                "CRITICAL", "ARP SPOOFING DETECTED",
                f"IP {ip_addr} changed MAC: {arp_table[ip_addr]} → {mac_addr}",
            )
    arp_table[ip_addr] = mac_addr


def detect_dns_tunneling(pkt):
    if not pkt.haslayer(DNSQR):
        return
    try:
        qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
    except Exception:
        return

    if len(qname) > CONFIG["dns_tunnel_domain_len"]:
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
        fire_alert(
            "MEDIUM", "DNS TUNNELING SUSPICION",
            f"Unusually long domain ({len(qname)} chars) from {src_ip}",
            qname[:80],
        )


# ═══════════════════════════════════════════════════════════════════
#  MAIN PACKET PROCESSOR
# ═══════════════════════════════════════════════════════════════════

def process_packet(pkt):
    global total_packets
    total_packets += 1

    # ── ARP ──────────────────────────────────────────────────────
    if pkt.haslayer(ARP):
        detect_arp_spoofing(pkt)
        return

    # Only process IP packets from here on
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # ── DNS ──────────────────────────────────────────────────────
    if pkt.haslayer(DNS):
        detect_dns_tunneling(pkt)

    # ── TCP ──────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp      = pkt[TCP]
        dst_port = tcp.dport
        flags    = str(tcp.flags)

        detect_port_scan(src_ip, dst_port)
        detect_syn_flood(src_ip, dst_ip, flags)
        detect_suspicious_port(src_ip, dst_ip, dst_port)

        if pkt.haslayer(Raw):
            detect_payload_patterns(src_ip, dst_ip, bytes(pkt[Raw]))

    # ── UDP ──────────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        dst_port = pkt[UDP].dport
        detect_suspicious_port(src_ip, dst_ip, dst_port)

        if pkt.haslayer(Raw):
            detect_payload_patterns(src_ip, dst_ip, bytes(pkt[Raw]))

    # ── ICMP ─────────────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        detect_icmp_flood(src_ip, pkt[ICMP].type)


# ═══════════════════════════════════════════════════════════════════
#  LIVE DASHBOARD
# ═══════════════════════════════════════════════════════════════════

def print_dashboard():
    elapsed = int(time.time() - start_time)
    pps     = total_packets / elapsed if elapsed > 0 else 0

    print(f"\n\n{'═'*70}")
    print(f"  {BOLD}{CYAN}📊 NIDS LIVE DASHBOARD{RESET}  "
          f"[Uptime: {elapsed}s | {total_packets} pkts | {pps:.1f} pkt/s]")
    print(f"  {'─'*60}")
    print(f"  {'Alert Type':<35} {'Count':>6}")
    print(f"  {'─'*44}")
    with alert_counts_lock:
        if not alert_counts:
            print(f"  {'(no alerts yet)':<35}")
        for alert_type, count in sorted(alert_counts.items(), key=lambda x: -x[1]):
            print(f"  {alert_type:<35} {count:>6}")
    print(f"  {'─'*44}")
    total_alerts = sum(alert_counts.values())
    print(f"  {'TOTAL ALERTS':<35} {total_alerts:>6}")
    print(f"{'═'*70}\n")


def dashboard_loop(interval: int, stop_event: threading.Event):
    while not stop_event.wait(interval):
        print_dashboard()


# ═══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha — Python-based Network Intrusion Detection System",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-i", "--iface",  default=None, help="Network interface (default: auto)")
    parser.add_argument("-c", "--count",  type=int, default=0, help="Packet limit (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="",  help="BPF filter (e.g. 'tcp', 'host 192.168.1.1')")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable periodic dashboard")
    args = parser.parse_args()

    print(f"\n{'═'*70}")
    print(f"  {BOLD}{RED}🛡  CodeAlpha — Network Intrusion Detection System{RESET}")
    print(f"{'═'*70}")
    print(f"  Interface : {args.iface or 'auto-detect'}")
    print(f"  Filter    : {args.filter or 'all traffic'}")
    print(f"  Log file  : {CONFIG['log_file']}")
    print(f"  Dashboard : every {CONFIG['dashboard_interval']}s")
    print(f"\n  {YELLOW}Detection Rules Active:{RESET}")
    print(f"    • Port Scan  — {CONFIG['port_scan_threshold']} ports/{CONFIG['port_scan_window_sec']}s")
    print(f"    • SYN Flood  — {CONFIG['syn_flood_threshold']} SYNs/{CONFIG['syn_flood_window_sec']}s")
    print(f"    • ICMP Flood — {CONFIG['icmp_flood_threshold']} pings/{CONFIG['icmp_flood_window_sec']}s")
    print(f"    • {len(CONFIG['suspicious_ports'])} Suspicious Ports monitored")
    print(f"    • {len(CONFIG['payload_patterns'])} Payload Attack Patterns")
    print(f"    • ARP Spoofing Detection")
    print(f"    • DNS Tunneling Detection")
    print(f"\n  Press Ctrl+C to stop.\n{'═'*70}\n")

    # Start dashboard thread
    stop_event = threading.Event()
    if not args.no_dashboard and CONFIG["dashboard_interval"] > 0:
        t = threading.Thread(
            target=dashboard_loop,
            args=(CONFIG["dashboard_interval"], stop_event),
            daemon=True,
        )
        t.start()

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            count=args.count,
            prn=process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(f"\n{RED}[ERROR]{RESET} Permission denied — run as root/administrator.\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}[ERROR]{RESET} {e}\n")
        sys.exit(1)
    finally:
        stop_event.set()
        print_dashboard()
        print(f"  Alerts written to: {CONFIG['log_file']}\n")


if __name__ == "__main__":
    main()
