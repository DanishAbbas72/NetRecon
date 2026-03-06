#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║      NetRecon v1 — Advanced Port Scanner & Fingerprinter       ║
║      Author  : Danish Abbas                                      ║
║      GitHub  : github.com/DanishAbbas72                          ║
║      Version : 1.1.0 — Smart FIN/NULL/XMAS with RST validation   ║
╚══════════════════════════════════════════════════════════════════╝

KEY FIXES in v1.1:
  - FIN/NULL/XMAS now use TWO-PHASE scanning:
      Phase 1: Send probe to ALL ports, collect which respond with RST (=CLOSED)
      Phase 2: From the non-responding ones, verify via TCP connect which are truly OPEN
  - This eliminates false OPEN|FILTERED results from Linux/iptables DROP policies
  - ACK scan correctly identifies FILTERED vs UNFILTERED
  - Connect scan is the default reliable method (no root needed)
  - Source port binding with proper fallback
  - Full 0-65535 port range support with --full

FIREWALL BYPASS TECHNIQUES:
  --source-port 53/80   Bind source port to trusted port (DNS/HTTP)
  --fragmentation       Fragment TCP packets (stateless firewall bypass)
  --fin-scan            FIN probe + connect verify (Linux-aware)
  --null-scan           NULL probe + connect verify
  --xmas-scan           XMAS probe + connect verify
  --ack-scan            Map firewall rules (filtered vs unfiltered)
  --randomize           Random port order (IDS evasion)
  --delay               Slow scan (rate-limit evasion)
  --ttl                 Custom TTL value
"""

import socket
import select
import struct
import random
import time
import sys
import re
import os
import threading
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# ANSI Colors
# ─────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

    @staticmethod
    def disable():
        for a in ['RED','GREEN','YELLOW','CYAN','BLUE','MAGENTA',
                  'WHITE','GRAY','BOLD','DIM','RESET']:
            setattr(C, a, '')

# ─────────────────────────────────────────────
# Service Database
# ─────────────────────────────────────────────
SERVICE_DB = {
    21:    {"name": "FTP",           "icon": "📁", "risk": "HIGH", "note": "Check anonymous login, banner grab for version"},
    22:    {"name": "SSH",           "icon": "🔐", "risk": "LOW",  "note": "Brute-force risk if password auth enabled"},
    23:    {"name": "Telnet",        "icon": "⚠️ ", "risk": "CRIT","note": "Unencrypted — credentials in plaintext"},
    25:    {"name": "SMTP",          "icon": "📧", "risk": "MED",  "note": "Open relay, user enumeration (VRFY/EXPN)"},
    53:    {"name": "DNS",           "icon": "🌐", "risk": "MED",  "note": "Zone transfer (AXFR), cache poisoning"},
    80:    {"name": "HTTP",          "icon": "🌍", "risk": "MED",  "note": "Web app — run full web vulnerability scan"},
    110:   {"name": "POP3",          "icon": "📬", "risk": "MED",  "note": "Email retrieval — check for cleartext auth"},
    111:   {"name": "RPC",           "icon": "⚙️ ", "risk": "HIGH","note": "Remote Procedure Call — pivot point"},
    135:   {"name": "MSRPC",         "icon": "⚙️ ", "risk": "HIGH","note": "Microsoft RPC — common attack surface"},
    139:   {"name": "NetBIOS",       "icon": "🖥️ ", "risk": "HIGH","note": "Null sessions, SMB enumeration"},
    143:   {"name": "IMAP",          "icon": "📭", "risk": "MED",  "note": "Email — check for cleartext auth"},
    161:   {"name": "SNMP",          "icon": "📡", "risk": "HIGH", "note": "Default community strings (public/private)"},
    389:   {"name": "LDAP",          "icon": "🗂️ ", "risk": "HIGH","note": "Directory service — anonymous bind check"},
    443:   {"name": "HTTPS",         "icon": "🔒", "risk": "LOW",  "note": "TLS web app — check cert + web vulns"},
    445:   {"name": "SMB",           "icon": "📂", "risk": "CRIT", "note": "EternalBlue/MS17-010 — check patch level"},
    512:   {"name": "RSH",           "icon": "⚠️ ", "risk": "CRIT","note": "Remote Shell — no authentication"},
    513:   {"name": "rlogin",        "icon": "⚠️ ", "risk": "CRIT","note": "Legacy remote login — highly insecure"},
    514:   {"name": "Syslog",        "icon": "📋", "risk": "MED",  "note": "Log aggregation — may leak sensitive info"},
    587:   {"name": "SMTP/TLS",      "icon": "📧", "risk": "LOW",  "note": "Submission port — auth requirements"},
    631:   {"name": "IPP",           "icon": "🖨️ ", "risk": "MED", "note": "Printer service — info disclosure"},
    993:   {"name": "IMAPS",         "icon": "📭", "risk": "LOW",  "note": "IMAP over SSL"},
    995:   {"name": "POP3S",         "icon": "📬", "risk": "LOW",  "note": "POP3 over SSL"},
    1080:  {"name": "SOCKS",         "icon": "🔀", "risk": "HIGH", "note": "Proxy — check for open proxy"},
    1433:  {"name": "MSSQL",         "icon": "🗄️ ", "risk": "HIGH","note": "SQL Server — default creds sa/blank"},
    1521:  {"name": "Oracle DB",     "icon": "🗄️ ", "risk": "HIGH","note": "Oracle — default SIDs and credentials"},
    2049:  {"name": "NFS",           "icon": "💾", "risk": "HIGH", "note": "NFS shares — check for world-readable"},
    2181:  {"name": "ZooKeeper",     "icon": "🐘", "risk": "HIGH", "note": "Unauthenticated access often possible"},
    3000:  {"name": "Node/Grafana",  "icon": "📊", "risk": "MED",  "note": "Dev port — Grafana default admin:admin"},
    3306:  {"name": "MySQL",         "icon": "🗄️ ", "risk": "HIGH","note": "MySQL — remote root access check"},
    3389:  {"name": "RDP",           "icon": "🖥️ ", "risk": "HIGH","note": "BlueKeep CVE-2019-0708 — brute-force"},
    4369:  {"name": "RabbitMQ",      "icon": "🐇", "risk": "MED",  "note": "Default creds guest:guest"},
    5432:  {"name": "PostgreSQL",    "icon": "🗄️ ", "risk": "HIGH","note": "PostgreSQL — remote access check"},
    5601:  {"name": "Kibana",        "icon": "📊", "risk": "HIGH", "note": "Unauthenticated dashboard access"},
    5900:  {"name": "VNC",           "icon": "🖥️ ", "risk": "CRIT","note": "VNC — weak or no authentication"},
    5984:  {"name": "CouchDB",       "icon": "🗄️ ", "risk": "HIGH","note": "Unauthenticated Futon/Fauxton"},
    6379:  {"name": "Redis",         "icon": "🔴", "risk": "CRIT", "note": "No auth by default — full RCE risk"},
    6443:  {"name": "Kubernetes",    "icon": "☸️ ", "risk": "CRIT","note": "K8s API — unauthenticated access"},
    7001:  {"name": "WebLogic",      "icon": "☕", "risk": "HIGH", "note": "Deserialization CVEs (CVE-2020-14882)"},
    8080:  {"name": "HTTP-Alt",      "icon": "🌍", "risk": "MED",  "note": "Tomcat/Jenkins/proxy — web scan needed"},
    8443:  {"name": "HTTPS-Alt",     "icon": "🔒", "risk": "MED",  "note": "Alternative HTTPS — web scan needed"},
    8888:  {"name": "Jupyter",       "icon": "📓", "risk": "CRIT", "note": "No auth — arbitrary code execution"},
    9000:  {"name": "PHP-FPM",       "icon": "🐘", "risk": "HIGH", "note": "PHP FastCGI — CVE-2019-11043 RCE"},
    9200:  {"name": "Elasticsearch", "icon": "🔍", "risk": "CRIT", "note": "No auth default — full data access"},
    9300:  {"name": "ES Cluster",    "icon": "🔍", "risk": "HIGH", "note": "Elasticsearch cluster comms"},
    27017: {"name": "MongoDB",       "icon": "🍃", "risk": "CRIT", "note": "No auth default — full DB access"},
    27018: {"name": "MongoDB Shard", "icon": "🍃", "risk": "HIGH", "note": "MongoDB shard — check auth"},
}

TOP_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,
    512,513,514,587,631,993,995,1080,1433,1521,2049,2181,
    3000,3306,3389,4369,5432,5601,5900,5984,6379,6443,7001,
    8080,8443,8888,9000,9200,9300,27017,27018,
    20,69,79,88,102,113,119,123,137,138,179,194,311,383,
    464,500,515,548,554,563,636,646,860,873,902,989,990,
    992,1194,1352,1723,1812,2000,2222,2375,2376,4444,4848,
    5000,5001,5005,5006,5007,5008,5009,5010,8000,8001,8008,
    8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,
    9001,9002,9003,9090,9091,9092,9093,9094,9095,9100,
    10000,10001,10080,49152,49153,49154,49155,49156,49157,
]

RISK_COLORS = {
    "CRIT": C.RED + C.BOLD,
    "HIGH": C.RED,
    "MED":  C.YELLOW,
    "LOW":  C.GREEN,
    "INFO": C.CYAN,
}

# ─────────────────────────────────────────────
# Raw Packet Builder
# ─────────────────────────────────────────────
def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def build_tcp_packet(src_ip, dst_ip, src_port, dst_port, flags,
                     seq=0, ack=0, ttl=64, fragment=False):
    flag_map = {
        'SYN':    0x002,
        'ACK':    0x010,
        'FIN':    0x001,
        'RST':    0x004,
        'NULL':   0x000,
        'XMAS':   0x029,   # FIN+PSH+URG
        'WINDOW': 0x010,
    }
    tcp_flags  = flag_map.get(flags.upper(), 0x002)
    ip_ihl_ver = (4 << 4) + 5
    ip_id      = random.randint(1, 65535)
    ip_frag    = 0x2000 if fragment else 0
    ip_saddr   = socket.inet_aton(src_ip)
    ip_daddr   = socket.inet_aton(dst_ip)

    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        ip_ihl_ver, 0, 0, ip_id, ip_frag, ttl,
        socket.IPPROTO_TCP, 0, ip_saddr, ip_daddr)

    tcp_seq    = seq or random.randint(0, 2**32-1)
    tcp_offset = (5 << 4)
    tcp_win    = socket.htons(64240)

    tcp_hdr = struct.pack('!HHLLBBHHH',
        src_port, dst_port, tcp_seq, ack,
        tcp_offset, tcp_flags, tcp_win, 0, 0)

    pseudo  = struct.pack('!4s4sBBH',
        ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_hdr))
    tcp_chk = checksum(pseudo + tcp_hdr)

    tcp_hdr = struct.pack('!HHLLBBHHH',
        src_port, dst_port, tcp_seq, ack,
        tcp_offset, tcp_flags, tcp_win, tcp_chk, 0)

    return ip_hdr + tcp_hdr


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ─────────────────────────────────────────────
# iptables helper — suppress kernel RST replies
# Required for FIN/NULL/XMAS scans on Linux
# ─────────────────────────────────────────────
import subprocess as _sub

def _iptables_block_rst(src_ports):
    """Block kernel from auto-sending RST for our probe source ports."""
    rules_added = []
    for sp in src_ports:
        try:
            _sub.run(
                ['iptables', '-A', 'OUTPUT', '-p', 'tcp',
                 '--sport', str(sp), '--tcp-flags', 'RST', 'RST',
                 '-j', 'DROP'],
                check=True, capture_output=True
            )
            rules_added.append(sp)
        except Exception:
            pass
    return rules_added


def _iptables_unblock_rst(src_ports):
    """Remove the RST-blocking iptables rules after scan."""
    for sp in src_ports:
        try:
            _sub.run(
                ['iptables', '-D', 'OUTPUT', '-p', 'tcp',
                 '--sport', str(sp), '--tcp-flags', 'RST', 'RST',
                 '-j', 'DROP'],
                capture_output=True
            )
        except Exception:
            pass


# ─────────────────────────────────────────────
# Phase 1: Raw Probe — collect RST responses
# Tells us which ports are DEFINITELY CLOSED
# ─────────────────────────────────────────────
def raw_probe_batch(dst_ip, ports, technique, ttl=64,
                    fragment=False, timeout=4.0):
    """
    Send raw TCP probes to all ports simultaneously.
    Collect RST responses to identify CLOSED ports.
    Ports that do NOT send RST = OPEN or FILTERED.

    KEY FIX: Uses iptables to block the Linux kernel from auto-sending
    RST replies, which would interfere with raw socket responses.
    Without this, all ports appear as no-response (OPEN|FILTERED).

    Returns: set of ports confirmed CLOSED (sent RST back)
    """
    src_ip   = get_local_ip()
    closed   = set()
    port_set = set(ports)

    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.settimeout(0.1)
    except PermissionError:
        return None   # No root — caller handles fallback

    # Use a fixed high source port range so we can block RST easily
    base_src = 60000
    probe_map   = {}   # src_port → dst_port
    src_ports   = []

    for i, dst_port in enumerate(ports):
        src_port = base_src + (i % 4000)
        probe_map[src_port] = dst_port
        src_ports.append(src_port)

    # Block kernel from auto-RST'ing our probe source ports
    # This prevents kernel interference with raw socket responses
    unique_src = list(set(src_ports))
    blocked = _iptables_block_rst(unique_src)

    try:
        # Send all probes
        for i, dst_port in enumerate(ports):
            src_port = src_ports[i]
            pkt = build_tcp_packet(
                src_ip, dst_ip, src_port, dst_port,
                technique, ttl=ttl, fragment=fragment
            )
            try:
                raw.sendto(pkt, (dst_ip, 0))
            except Exception:
                pass

        # Listen for RST responses (closed ports reply with RST)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                raw.settimeout(min(remaining, 0.5))
                data, addr = raw.recvfrom(4096)

                if addr[0] != dst_ip or len(data) < 40:
                    continue

                tcp = data[20:40]
                if len(tcp) < 20:
                    continue

                fields   = struct.unpack('!HHLLBBHHH', tcp)
                resp_src = fields[0]   # sport in response = dst port of our probe
                resp_dst = fields[1]   # dport in response = src port of our probe
                flags    = fields[5]

                RST = (flags & 0x004) != 0

                # RST back to one of our source ports = that dst port is CLOSED
                if resp_dst in probe_map and RST:
                    closed.add(probe_map[resp_dst])

            except socket.timeout:
                continue
            except Exception:
                continue

    finally:
        # Always restore iptables rules
        _iptables_unblock_rst(blocked)
        raw.close()

    return closed


# ─────────────────────────────────────────────
# Phase 2: TCP Connect verify
# Confirms whether a non-RST port is truly OPEN
# ─────────────────────────────────────────────
def tcp_connect_verify(host, port, timeout=2.0):
    """Quick TCP connect to confirm if port is truly open."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex((host, port))
        _, writable, _ = select.select([], [sock], [sock], timeout)
        if not writable:
            return False
        so_err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        return so_err == 0
    except Exception:
        return False
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


# ─────────────────────────────────────────────
# Smart FIN/NULL/XMAS Scanner (Two-Phase)
# ─────────────────────────────────────────────
def smart_stealth_scan(host, ports, technique, ttl=64,
                       fragment=False, timeout=4.0,
                       grab=True, threads=200):
    """
    Two-phase stealth scan:
      Phase 1 — Raw probe: identify CLOSED ports (RST response)
      Phase 2 — TCP connect: verify remaining ports are truly OPEN
                             (eliminates false OPEN|FILTERED from DROP policies)

    This correctly handles Linux/iptables which DROPs packets for
    filtered ports — causing FIN/NULL/XMAS to show everything as
    OPEN|FILTERED when it should show only actually open ports.
    """
    print(f"\n  {C.GRAY}Phase 1: Sending {technique.upper()} probes to {len(ports)} ports...{C.RESET}")
    closed_ports = raw_probe_batch(host, ports, technique,
                                   ttl=ttl, fragment=fragment,
                                   timeout=timeout)

    if closed_ports is None:
        # No root — fall back to connect scan
        print(f"  {C.YELLOW}[!] Raw socket failed — falling back to TCP Connect scan{C.RESET}")
        return None

    not_closed = [p for p in ports if p not in closed_ports]

    print(f"  {C.GRAY}Phase 1 result: {len(closed_ports)} CLOSED | "
          f"{len(not_closed)} need verification{C.RESET}")
    print(f"  {C.GRAY}Phase 2: TCP connect verification on {len(not_closed)} ports...{C.RESET}\n")

    results = []
    lock    = threading.Lock()

    def verify_port(port):
        is_open = tcp_connect_verify(host, port, timeout=min(timeout, 2.5))
        if is_open:
            banner  = grab_banner(host, port, timeout=2.0) if grab else None
            version = fingerprint_service(port, banner)
            svc     = SERVICE_DB.get(port, {})
            r = {
                "port":      port,
                "state":     "OPEN",
                "technique": f"{technique.upper()} + Verify",
                "service":   svc.get("name", "Unknown"),
                "icon":      svc.get("icon", "🔌"),
                "risk":      svc.get("risk", "INFO"),
                "note":      svc.get("note", ""),
                "banner":    banner,
                "version":   version,
            }
            with lock:
                results.append(r)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(verify_port, not_closed))

    return results


# ─────────────────────────────────────────────
# ACK Scan — maps firewall rules
# ─────────────────────────────────────────────
def ack_scan_batch(host, ports, ttl=64, timeout=4.0, threads=200):
    """
    ACK scan: RST response = UNFILTERED (firewall passes it)
              No response  = FILTERED (firewall drops it)
    Useful for mapping which ports the firewall passes, NOT for
    finding open ports.
    """
    src_ip   = get_local_ip()
    unfiltered = set()
    lock     = threading.Lock()

    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        return None

    probe_map = {}
    for dst_port in ports:
        src_port = random.randint(49152, 65534)
        probe_map[src_port] = dst_port
        pkt = build_tcp_packet(src_ip, host, src_port, dst_port,
                               'ACK', ttl=ttl)
        try:
            raw.sendto(pkt, (host, 0))
        except Exception:
            pass

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw.settimeout(min(deadline - time.time(), 0.5))
            data, addr = raw.recvfrom(4096)
            if addr[0] != host or len(data) < 40:
                continue
            tcp    = data[20:40]
            fields = struct.unpack('!HHLLBBHHH', tcp)
            resp_src, resp_dst = fields[0], fields[1]
            flags  = fields[5]
            RST    = (flags & 0x004) != 0
            if RST and resp_dst in probe_map:
                with lock:
                    unfiltered.add(probe_map[resp_dst])
        except socket.timeout:
            continue
        except Exception:
            continue

    raw.close()

    results = []
    for port in unfiltered:
        svc = SERVICE_DB.get(port, {})
        results.append({
            "port":      port,
            "state":     "UNFILTERED",
            "technique": "ACK Scan",
            "service":   svc.get("name", "Unknown"),
            "icon":      svc.get("icon", "🔌"),
            "risk":      svc.get("risk", "INFO"),
            "note":      f"ACK scan: firewall passes this port. {svc.get('note','')}",
            "banner":    None,
            "version":   None,
        })
    return results


# ─────────────────────────────────────────────
# Banner Grabber & Fingerprinter
# ─────────────────────────────────────────────
BANNER_PROBES = {
    21:   b"",
    22:   b"",
    25:   b"EHLO netrecon\r\n",
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: NetRecon/2.1\r\n\r\n",
    110:  b"",
    143:  b"",
    6379: b"INFO\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
}

def grab_banner(host, port, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        probe = BANNER_PROBES.get(port, b"")
        if probe:
            sock.send(probe)
        banner = sock.recv(2048).decode("utf-8", errors="ignore").strip()
        sock.close()
        return " ".join(banner.split())[:150] or None
    except Exception:
        return None


def fingerprint_service(port, banner):
    if not banner:
        return None
    patterns = [
        r"OpenSSH[_\s]([\w.p-]+)",
        r"Apache/([\d.]+)",
        r"nginx/([\d.]+)",
        r"Microsoft-IIS/([\d.]+)",
        r"vsftpd\s([\d.]+)",
        r"MySQL\s([\d.]+)",
        r"MariaDB\s([\d.]+)",
        r"Redis\s([\d.]+)",
        r"MongoDB\s([\d.]+)",
        r"PHP/([\d.]+)",
    ]
    for p in patterns:
        m = re.search(p, banner, re.IGNORECASE)
        if m:
            return m.group(0)
    return banner.split()[0][:40] if banner else None


# ─────────────────────────────────────────────
# Standard Connect Scan (no root needed)
# ─────────────────────────────────────────────
def connect_scan_port(host, port, timeout=3.0, grab=True,
                      delay=0, src_port=None):
    if delay > 0:
        time.sleep(delay)

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if src_port:
            try:
                sock.bind(('', src_port))
            except OSError:
                sock.bind(('', src_port + random.randint(1, 200)))

        sock.setblocking(False)
        sock.connect_ex((host, port))

        _, writable, _ = select.select([], [sock], [sock], timeout)
        if not writable:
            return None

        so_error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if so_error != 0:
            return None

        sock.close()
        sock = None

        banner  = grab_banner(host, port, timeout=min(timeout, 2.0)) if grab else None
        version = fingerprint_service(port, banner)
        svc     = SERVICE_DB.get(port, {})

        tech = "TCP Connect"
        if src_port:
            tech = f"TCP Connect (src:{src_port})"

        return {
            "port":      port,
            "state":     "OPEN",
            "technique": tech,
            "service":   svc.get("name", "Unknown"),
            "icon":      svc.get("icon", "🔌"),
            "risk":      svc.get("risk", "INFO"),
            "note":      svc.get("note", ""),
            "banner":    banner,
            "version":   version,
        }
    except Exception:
        return None
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def parse_ports(port_str):
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            s, e = part.split("-", 1)
            ports.extend(range(int(s), int(e) + 1))
        else:
            ports.append(int(part))
    return sorted(set(p for p in ports if 0 <= p <= 65535))


def resolve_host(target):
    """
    Robust DNS resolver with 6 fallback methods.
    Works under sudo even when environment DNS is stripped.
    """
    import re as _re
    import subprocess as _sub
    import struct as _struct

    # 1. Already a valid IP — return directly (no DNS needed)
    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        pass

    # 2. Standard Python DNS (works in normal mode)
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        pass

    # 3. Raw DNS UDP query to nameserver from /etc/resolv.conf
    try:
        nameservers = []
        with open('/etc/resolv.conf') as f:
            for line in f:
                line = line.strip()
                if line.startswith('nameserver'):
                    nameservers.append(line.split()[1])
        for ns in nameservers:
            try:
                txid  = random.randint(0, 65535)
                q     = target.rstrip('.') + '.'
                qname = b''
                for label in q.split('.'):
                    if label:
                        qname += bytes([len(label)]) + label.encode()
                header = _struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
                query  = header + qname + _struct.pack('!HH', 1, 1)
                sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3.0)
                sock.sendto(query, (ns, 53))
                data, _ = sock.recvfrom(512)
                sock.close()
                # Skip header (12 bytes) + question section
                i = 12
                while i < len(data) and data[i] != 0:
                    i += 1 + data[i]
                i += 5  # null byte + qtype + qclass
                # Parse first answer record
                if i + 2 <= len(data):
                    if data[i] & 0xc0 == 0xc0:  # compressed name ptr
                        i += 2
                    else:
                        while i < len(data) and data[i] != 0:
                            i += 1 + data[i]
                        i += 1
                if i + 10 <= len(data):
                    rtype, _, _, rdlen = _struct.unpack('!HHIH', data[i:i+10])
                    i += 10
                    if rtype == 1 and rdlen == 4 and i + 4 <= len(data):
                        return '.'.join(str(b) for b in data[i:i+4])
            except Exception:
                continue
    except Exception:
        pass

    # 4. getent hosts (works under sudo on Linux)
    try:
        out = _sub.check_output(
            ['getent', 'hosts', target],
            timeout=3, stderr=_sub.DEVNULL
        ).decode().strip()
        if out:
            return out.split()[0]
    except Exception:
        pass

    # 5. dig +short fallback
    try:
        out = _sub.check_output(
            ['dig', '+short', '+time=2', target],
            timeout=4, stderr=_sub.DEVNULL
        ).decode()
        ips = [l.strip() for l in out.strip().splitlines()
               if _re.match(r'\d+\.\d+\.\d+\.\d+', l.strip())]
        if ips:
            return ips[-1]
    except Exception:
        pass

    # 6. host command fallback
    try:
        out = _sub.check_output(
            ['host', target],
            timeout=3, stderr=_sub.DEVNULL
        ).decode()
        m = _re.search(r'has address (\d+\.\d+\.\d+\.\d+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass

    return None


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def check_root():
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


# ─────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────
BANNER_ART = """
{cyan}{bold} ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{reset}
{gray}                Port Scanner & Service Fingerprinter v1.1
                      Author: Danish Abbas | github.com/DanishAbbas72{reset}
"""

def print_banner():
    print(BANNER_ART.format(cyan=C.CYAN, bold=C.BOLD,
                             reset=C.RESET, gray=C.GRAY))


def print_host_info(target, ip, hostname, start_time, technique, args):
    is_root = check_root()
    print(f"\n{C.BOLD}{'─'*68}{C.RESET}")
    print(f"  {C.CYAN}Target     {C.RESET}: {C.WHITE}{target}{C.RESET}")
    if ip != target:
        print(f"  {C.CYAN}IP         {C.RESET}: {C.WHITE}{ip}{C.RESET}")
    if hostname and hostname != ip and hostname != target:
        print(f"  {C.CYAN}Hostname   {C.RESET}: {C.WHITE}{hostname}{C.RESET}")
    print(f"  {C.CYAN}Scan Time  {C.RESET}: {C.WHITE}{start_time.strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"  {C.CYAN}Technique  {C.RESET}: {C.YELLOW}{technique.upper()}{C.RESET}")
    if args.source_port:
        print(f"  {C.CYAN}Source Port{C.RESET}: {C.YELLOW}{args.source_port} (bypass){C.RESET}")
    if args.fragmentation:
        print(f"  {C.CYAN}Fragments  {C.RESET}: {C.YELLOW}ENABLED{C.RESET}")
    if args.randomize:
        print(f"  {C.CYAN}Port Order {C.RESET}: {C.YELLOW}RANDOMIZED (IDS evasion){C.RESET}")
    if args.delay > 0:
        print(f"  {C.CYAN}Delay      {C.RESET}: {C.YELLOW}{args.delay}s (rate-limit evasion){C.RESET}")
    root_str = (f"{C.GREEN}YES — raw scans available{C.RESET}" if is_root
                else f"{C.YELLOW}NO  — using TCP connect fallback{C.RESET}")
    print(f"  {C.CYAN}Root       {C.RESET}: {root_str}")
    print(f"{C.BOLD}{'─'*68}{C.RESET}\n")


def print_result(r):
    state      = r["state"]
    risk_color = RISK_COLORS.get(r["risk"], C.WHITE)
    risk_label = f"{risk_color}[{r['risk']:4}]{C.RESET}"
    port_str   = f"{C.BOLD}{C.WHITE}{r['port']:5}{C.RESET}"

    if state == "OPEN":
        state_str = f"{C.GREEN}OPEN          {C.RESET}"
    elif state == "UNFILTERED":
        state_str = f"{C.CYAN}UNFILTERED    {C.RESET}"
    else:
        state_str = f"{C.YELLOW}{state:<14}{C.RESET}"

    svc_str = f"{C.CYAN}{r['icon']} {r['service']:<18}{C.RESET}"
    ver_str = f"{C.GRAY}← {r['version'][:45]}{C.RESET}" if r.get("version") else ""

    print(f"  {port_str}  {state_str} {svc_str} {risk_label}  {ver_str}")

    if r.get("note"):
        print(f"         {C.DIM}{C.GRAY}↳ {r['note']}{C.RESET}")
    if r.get("banner") and r.get("banner") != r.get("version"):
        print(f"         {C.DIM}{C.MAGENTA}  Banner: {r['banner'][:90]}{C.RESET}")


def print_summary(results, elapsed, total_scanned, technique):
    open_ports = [r for r in results if r["state"] == "OPEN"]
    crit = sum(1 for r in open_ports if r["risk"] == "CRIT")
    high = sum(1 for r in open_ports if r["risk"] == "HIGH")
    med  = sum(1 for r in open_ports if r["risk"] == "MED")
    low  = sum(1 for r in open_ports if r["risk"] in ("LOW","INFO"))

    print(f"\n{C.BOLD}{'─'*68}{C.RESET}")
    print(f"  {C.BOLD}SCAN SUMMARY{C.RESET}")
    print(f"{'─'*68}")
    print(f"  Ports Scanned  : {C.WHITE}{total_scanned:,}{C.RESET}")
    print(f"  Open Ports     : {C.GREEN}{C.BOLD}{len(open_ports)}{C.RESET}")
    print(f"  Scan Technique : {C.YELLOW}{technique.upper()}{C.RESET}")
    print(f"  Scan Duration  : {C.WHITE}{elapsed:.2f}s{C.RESET}")
    print(f"\n  Risk Breakdown :")
    print(f"    {C.RED}{C.BOLD}CRITICAL  {C.RESET}: {crit}")
    print(f"    {C.RED}HIGH      {C.RESET}: {high}")
    print(f"    {C.YELLOW}MEDIUM    {C.RESET}: {med}")
    print(f"    {C.GREEN}LOW       {C.RESET}: {low}")
    if crit > 0 or high > 0:
        print(f"\n  {C.RED}{C.BOLD}⚠  HIGH RISK SERVICES DETECTED{C.RESET}")
    print(f"{C.BOLD}{'─'*68}{C.RESET}\n")


def print_technique_guide():
    print(f"\n  {C.BOLD}{C.CYAN}FIREWALL BYPASS TECHNIQUES{C.RESET}")
    print(f"  {'─'*60}")
    tips = [
        ("--source-port 53",  "Bind to DNS source port — bypasses firewall rules trusting DNS"),
        ("--source-port 80",  "Bind to HTTP source port — bypasses rules trusting web traffic"),
        ("--fragmentation",   "Fragment packets — bypasses stateless/legacy firewalls [root]"),
        ("--fin-scan",        "FIN + TCP verify (Linux-aware) — bypasses stateless filters [root]"),
        ("--null-scan",       "NULL + TCP verify — bypasses some packet filters [root]"),
        ("--xmas-scan",       "XMAS + TCP verify — bypasses BSD-based filters [root]"),
        ("--ack-scan",        "ACK probe — maps which ports firewall passes [root]"),
        ("--randomize",       "Random port order — evades pattern-based IDS/IPS"),
        ("--delay 0.1",       "Slow scan — evades rate-limit triggered alerting"),
        ("--ttl 128",         "Custom TTL — evades some TTL-based filtering rules"),
        ("--full",            "Scan all 65,535 ports — finds non-standard service ports"),
    ]
    for flag, desc in tips:
        print(f"  {C.YELLOW}{flag:<22}{C.RESET}  {desc}")
    print(f"\n  {C.GRAY}Note: [root] techniques auto-fallback to TCP connect without sudo{C.RESET}\n")


def save_report(results, target, ip, output_file, technique):
    lines = [
        "=" * 68,
        "  NetRecon v1.1 — Port Scanner & Service Fingerprinter",
        "  Author: Danish Abbas | github.com/DanishAbbas72",
        "=" * 68,
        f"  Target     : {target}",
        f"  IP         : {ip}",
        f"  Technique  : {technique.upper()}",
        f"  Scan Date  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Open Ports : {sum(1 for r in results if r['state']=='OPEN')}",
        "=" * 68, "",
        f"{'PORT':<8} {'STATE':<16} {'SERVICE':<22} {'RISK':<8} VERSION",
        "-" * 68,
    ]
    for r in sorted(results, key=lambda x: x["port"]):
        ver = r.get("version") or ""
        lines.append(f"{r['port']:<8} {r['state']:<16} {r['service']:<22} {r['risk']:<8} {ver}")
        if r.get("note"):
            lines.append(f"         Note   : {r['note']}")
        if r.get("banner"):
            lines.append(f"         Banner : {r['banner'][:90]}")
        lines.append("")
    with open(output_file, "w") as f:
        f.write("\n".join(lines))
    print(f"  {C.GREEN}✓ Report saved: {output_file}{C.RESET}\n")


# ─────────────────────────────────────────────
# Progress Bar
# ─────────────────────────────────────────────
class Progress:
    def __init__(self, total):
        self.total   = total
        self.current = 0
        self.found   = 0
        self.lock    = threading.Lock()

    def update(self, found=False):
        with self.lock:
            self.current += 1
            if found:
                self.found += 1
            pct  = (self.current / self.total) * 100
            done = int(pct / 2)
            bar  = f"{C.GREEN}{'█'*done}{C.GRAY}{'░'*(50-done)}{C.RESET}"
            sys.stdout.write(
                f"\r  [{bar}] {C.WHITE}{pct:5.1f}%{C.RESET}  "
                f"{self.current:,}/{self.total:,}  "
                f"{C.GREEN}Open: {self.found}{C.RESET}   "
            )
            sys.stdout.flush()

    def finish(self):
        sys.stdout.write("\n")
        sys.stdout.flush()


# ─────────────────────────────────────────────
# Main Scan Engine
# ─────────────────────────────────────────────
def run_scan(target, ports, args, technique="connect"):
    print_banner()

    ip = resolve_host(target)
    if not ip:
        print(f"\n  {C.RED}[ERROR] Cannot resolve host: {target}{C.RESET}")
        print(f"  {C.GRAY}Tip: If using sudo, try: sudo -E python netrecon.py ..{C.RESET}\n")
        sys.exit(1)

    hostname   = reverse_dns(ip)
    start_time = datetime.now()

    print_host_info(target, ip, hostname, start_time, technique, args)

    scan_ports = list(ports)
    if args.randomize:
        random.shuffle(scan_ports)

    total = len(scan_ports)
    t_start = time.time()

    # ── Stealth scans use two-phase approach ──
    if technique in ("fin", "null", "xmas"):
        print(f"  {C.GRAY}Scanning {total:,} ports | technique={technique.upper()} + TCP verify "
              f"| timeout={args.timeout}s{C.RESET}")

        results = smart_stealth_scan(
            ip, scan_ports, technique,
            ttl=args.ttl, fragment=args.fragmentation,
            timeout=args.timeout, grab=not args.no_banner,
            threads=args.threads
        )

        if results is None:
            # Fallback to connect
            technique = "connect"
            print(f"  {C.GRAY}Falling back to TCP Connect scan...{C.RESET}\n")
        else:
            elapsed = time.time() - t_start
            results.sort(key=lambda x: x["port"])
            if results:
                print(f"\n  {C.BOLD}{'PORT':<7} {'STATE':<16} {'SERVICE':<20} {'RISK':<10} VERSION{C.RESET}")
                print(f"  {'─'*65}")
                for r in results:
                    print_result(r)
            else:
                print(f"\n  {C.YELLOW}No open ports found with {technique.upper()} scan.{C.RESET}")
                print(f"  {C.GRAY}Target may use DROP policy — try: --source-port 53 or --full{C.RESET}")
            print_summary(results, elapsed, total, technique)
            if args.output:
                save_report(results, target, ip, args.output, technique)
            return results

    # ── ACK scan ──
    if technique == "ack":
        print(f"  {C.GRAY}ACK scan: mapping firewall rules on {total:,} ports...{C.RESET}")
        results = ack_scan_batch(ip, scan_ports, ttl=args.ttl,
                                 timeout=args.timeout, threads=args.threads)
        if results is None:
            technique = "connect"
            print(f"  {C.YELLOW}[!] ACK scan needs root — falling back to connect scan{C.RESET}\n")
        else:
            elapsed = time.time() - t_start
            results.sort(key=lambda x: x["port"])
            print(f"\n  {C.BOLD}ACK SCAN RESULTS (UNFILTERED = firewall allows this port):{C.RESET}")
            print(f"  {C.BOLD}{'PORT':<7} {'STATE':<16} {'SERVICE':<20} {'RISK':<10}{C.RESET}")
            print(f"  {'─'*55}")
            for r in results:
                print_result(r)
            if not results:
                print(f"  {C.YELLOW}All ports appear FILTERED — firewall drops all ACK probes{C.RESET}")
            print_summary(results, elapsed, total, technique)
            if args.output:
                save_report(results, target, ip, args.output, technique)
            return results

    # ── Standard TCP Connect Scan ──
    print(f"  {C.GRAY}Scanning {total:,} ports | threads={args.threads} | timeout={args.timeout}s{C.RESET}\n")

    results  = []
    lock     = threading.Lock()
    progress = Progress(total)

    def do_scan(port):
        r = connect_scan_port(
            ip, port,
            timeout  = args.timeout,
            grab     = not args.no_banner,
            delay    = args.delay,
            src_port = args.source_port,
        )
        progress.update(found=bool(r))
        return r

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(do_scan, p) for p in scan_ports]
        for future in as_completed(futures):
            r = future.result()
            if r:
                with lock:
                    results.append(r)

    progress.finish()
    elapsed = time.time() - t_start
    results.sort(key=lambda x: x["port"])

    if results:
        print(f"\n  {C.BOLD}{'PORT':<7} {'STATE':<16} {'SERVICE':<20} {'RISK':<10} VERSION{C.RESET}")
        print(f"  {'─'*65}")
        for r in results:
            print_result(r)
    else:
        print(f"\n  {C.YELLOW}No open ports found.{C.RESET}")
        print(f"  {C.GRAY}Try: --timeout 5  |  --source-port 53  |  sudo --fin-scan{C.RESET}")

    print_summary(results, elapsed, total, technique)

    if args.output:
        save_report(results, target, ip, args.output, technique)

    return results


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="NetRecon v1.1 — Advanced Port Scanner & Firewall Bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python netrecon.py -t 192.168.1.1 --top
  python netrecon.py -t scanme.nmap.org --full
  python netrecon.py -t target.com --top --source-port 53
  sudo python netrecon.py -t target.com --top --fin-scan
  sudo python netrecon.py -t target.com --top --null-scan --randomize
  sudo python netrecon.py -t target.com --top --ack-scan
  python netrecon.py -t target.com --full --timeout 2 --threads 1000 --no-banner
  python netrecon.py -t target.com --top --randomize --delay 0.05 -o report.txt
  python netrecon.py -t target.com --techniques
        """
    )

    parser.add_argument("-t","--target",    required=True,
                        help="Target IP, hostname, or CIDR")

    pg = parser.add_mutually_exclusive_group()
    pg.add_argument("-p","--ports",   default=None,
                    help="Custom ports: '80,443' or '1-10000'")
    pg.add_argument("--top",          action="store_true",
                    help="Scan top ~120 common ports")
    pg.add_argument("--full",         action="store_true",
                    help="Full scan: all 65,535 ports")

    tg = parser.add_mutually_exclusive_group()
    tg.add_argument("--fin-scan",     action="store_true",
                    help="FIN scan + TCP verify — accurate on Linux [root]")
    tg.add_argument("--null-scan",    action="store_true",
                    help="NULL scan + TCP verify [root]")
    tg.add_argument("--xmas-scan",    action="store_true",
                    help="XMAS scan + TCP verify [root]")
    tg.add_argument("--ack-scan",     action="store_true",
                    help="ACK scan — maps firewall rules [root]")

    parser.add_argument("--source-port", type=int,   default=None, metavar="PORT",
                        help="Spoof source port (53/80) to bypass firewall rules")
    parser.add_argument("--fragmentation", action="store_true",
                        help="Fragment TCP packets [root]")
    parser.add_argument("--ttl",         type=int,   default=64,
                        help="Custom IP TTL (default: 64)")
    parser.add_argument("--randomize",   action="store_true",
                        help="Randomize port order (IDS evasion)")
    parser.add_argument("--delay",       type=float, default=0,
                        help="Delay between probes in seconds (e.g. 0.05)")
    parser.add_argument("--threads",     type=int,   default=500,
                        help="Thread count (default: 500)")
    parser.add_argument("--timeout",     type=float, default=3.0,
                        help="Timeout per port in seconds (default: 3.0)")
    parser.add_argument("--no-banner",   action="store_true",
                        help="Skip banner grabbing (faster)")
    parser.add_argument("-o","--output", default=None,
                        help="Save report to text file")
    parser.add_argument("--no-color",    action="store_true",
                        help="Disable colors")
    parser.add_argument("--techniques",  action="store_true",
                        help="Show bypass technique guide")

    args = parser.parse_args()

    if args.no_color:
        C.disable()

    if args.techniques:
        print_banner()
        print_technique_guide()
        sys.exit(0)

    # Determine technique
    if args.fin_scan:
        technique = "fin"
    elif args.null_scan:
        technique = "null"
    elif args.xmas_scan:
        technique = "xmas"
    elif args.ack_scan:
        technique = "ack"
    elif args.source_port:
        technique = "source-port"
    else:
        technique = "connect"

    # Determine ports
    if args.full:
        ports = list(range(0, 65536))
    elif args.top:
        ports = TOP_PORTS
    elif args.ports:
        try:
            ports = parse_ports(args.ports)
        except Exception:
            print(f"\n  {C.RED}[ERROR] Invalid port format. Use '80,443' or '1-1000'{C.RESET}\n")
            sys.exit(1)
    else:
        ports = list(range(1, 1025))

    run_scan(args.target, ports, args, technique=technique)


if __name__ == "__main__":
    main()
