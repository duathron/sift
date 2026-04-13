#!/usr/bin/env python3
"""Generate a realistic brute-force attack scenario log for sift testing.

Simulates a mid-sized company (200 employees) over 1 week.
Normal authentication traffic is mixed with a multi-phase brute-force attack
(SSH, RDP, Web Login) that eventually succeeds and leads to lateral movement.

Usage:
    python generate_brute_force.py [--output brute_force_scenario.json] [--seed 42]
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────

SEED = 42
START_DATE = datetime(2026, 3, 22, 0, 0, 0, tzinfo=timezone.utc)
END_DATE = datetime(2026, 3, 28, 23, 59, 59, tzinfo=timezone.utc)

# Attacker IPs (rotating through these)
ATTACKER_IPS = [
    "185.220.101.47",   # Tor exit node
    "193.42.33.18",     # Bulletproof hosting
    "45.155.205.99",    # VPS provider
    "91.240.118.204",   # Known scanner
]

# Internal network
DOMAIN = "musterag.local"
INTERNAL_SUBNET = "10.10"
DMZ_SUBNET = "10.20"

# Target servers
TARGETS = {
    "ssh": [
        {"ip": "10.10.1.5", "host": "SRV-DC01", "desc": "Domain Controller"},
        {"ip": "10.10.1.6", "host": "SRV-DC02", "desc": "Backup DC"},
        {"ip": "10.10.2.10", "host": "SRV-FILE01", "desc": "File Server"},
        {"ip": "10.10.2.11", "host": "SRV-DB01", "desc": "Database Server"},
        {"ip": "10.20.1.3", "host": "SRV-WEB01", "desc": "Web Server"},
    ],
    "rdp": [
        {"ip": "10.10.1.5", "host": "SRV-DC01", "desc": "Domain Controller"},
        {"ip": "10.10.2.10", "host": "SRV-FILE01", "desc": "File Server"},
        {"ip": "10.10.3.5", "host": "SRV-APP01", "desc": "Application Server"},
        {"ip": "10.10.3.6", "host": "SRV-CITRIX01", "desc": "Citrix Server"},
    ],
    "web": [
        {"ip": "10.20.1.3", "host": "SRV-WEB01", "desc": "Corporate Portal"},
        {"ip": "10.20.1.4", "host": "SRV-OWA01", "desc": "Outlook Web Access"},
    ],
}

# Common brute-force usernames
BRUTE_USERNAMES = [
    "admin", "administrator", "root", "test", "user", "guest",
    "service", "backup", "sa", "oracle", "postgres", "mysql",
    "ftp", "www-data", "info", "support", "helpdesk",
    "svc_backup", "svc_sql", "svc_web", "deploy", "jenkins",
]

# ── Employee Generation ────────────────────────────────────────────────────

FIRST_NAMES_DE = [
    "Anna", "Ben", "Clara", "David", "Elena", "Felix", "Greta", "Hans",
    "Ida", "Jan", "Katrin", "Lukas", "Marie", "Nico", "Olivia", "Paul",
    "Rita", "Stefan", "Tanja", "Uwe", "Vera", "Werner", "Xenia", "Yusuf",
    "Zara", "Andreas", "Birgit", "Christian", "Daniela", "Erik",
    "Franziska", "Georg", "Hanna", "Igor", "Julia", "Karl", "Lisa",
    "Markus", "Nadine", "Otto", "Petra", "Robert", "Sabine", "Thomas",
    "Ursula", "Viktor", "Waltraud", "Alexander", "Barbara", "Carsten",
    "Doris", "Emil", "Fatima", "Gustav", "Helena", "Ibrahim", "Johanna",
    "Klaus", "Lena", "Matthias", "Nina", "Olaf", "Patricia", "Ralf",
    "Silke", "Thorsten", "Ulrike", "Volker", "Yvonne", "Maximilian",
    "Sophie", "Leon", "Mia", "Finn", "Emma", "Noah", "Lina", "Elias",
    "Emilia", "Jonas", "Charlotte", "Luis", "Amelie", "Henry", "Lea",
    "Moritz", "Maja", "Oskar", "Laura", "Philipp", "Sarah", "Tim",
    "Hannah", "Tobias", "Sophia", "Florian", "Nele", "Sebastian", "Klara",
]

LAST_NAMES_DE = [
    "Mueller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer",
    "Wagner", "Becker", "Schulz", "Hoffmann", "Koch", "Richter",
    "Wolf", "Schroeder", "Neumann", "Schwarz", "Zimmermann", "Braun",
    "Krueger", "Hofmann", "Hartmann", "Lange", "Schmitt", "Werner",
    "Krause", "Meier", "Lehmann", "Schmid", "Schulze", "Maier",
    "Koehler", "Herrmann", "Koenig", "Walter", "Mayer", "Huber",
    "Kaiser", "Fuchs", "Peters", "Lang", "Scholz", "Moeller",
    "Weiss", "Jung", "Hahn", "Schubert", "Vogel", "Friedrich",
    "Keller", "Guenther", "Frank", "Berger", "Winkler", "Roth",
    "Beck", "Lorenz", "Baumann", "Franke", "Albrecht", "Schuster",
    "Simon", "Ludwig", "Boehm", "Winter", "Kraus", "Martin",
    "Schumacher", "Vogt", "Jansen", "Otto", "Stein", "Gross",
    "Sommer", "Haas", "Graf", "Heinrich", "Seidel", "Brandt",
    "Schreiber", "Dietrich", "Engel", "Kuhn", "Pohl", "Horn",
    "Busch", "Bergmann", "Pfeiffer", "Voigt", "Sauer", "Arnold",
]

DEPARTMENTS = [
    "IT", "HR", "Finance", "Sales", "Marketing", "Engineering",
    "Legal", "Operations", "Support", "Management",
]


def generate_employees(rng: random.Random, count: int = 200) -> list[dict]:
    """Generate employee profiles with consistent workstation assignments."""
    employees = []
    used_names = set()
    for i in range(count):
        while True:
            first = rng.choice(FIRST_NAMES_DE)
            last = rng.choice(LAST_NAMES_DE)
            username = f"{first[0].lower()}.{last.lower()}"
            if username not in used_names:
                used_names.add(username)
                break

        dept = rng.choice(DEPARTMENTS)
        subnet_octet = rng.randint(50, 250)
        host_octet = rng.randint(10, 250)
        ip = f"{INTERNAL_SUBNET}.{subnet_octet}.{host_octet}"

        prefix = rng.choice(["WS", "LAPTOP", "DESKTOP", "NB"])
        host = f"{prefix}-{first[0].upper()}{last[:3].upper()}{rng.randint(1, 9):02d}"

        employees.append({
            "username": username,
            "first": first,
            "last": last,
            "department": dept,
            "ip": ip,
            "host": host,
            "is_admin": dept == "IT" and rng.random() < 0.3,
            "is_remote": rng.random() < 0.15,
        })
    return employees


# ── Event Generators ───────────────────────────────────────────────────────

EVENT_COUNTER = 0


def next_id() -> str:
    global EVENT_COUNTER
    EVENT_COUNTER += 1
    return f"evt-{EVENT_COUNTER:05d}"


def ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def random_time_in_window(
    rng: random.Random,
    day_offset: int,
    hour_start: int,
    hour_end: int,
) -> datetime:
    """Random timestamp within a time window on a given day."""
    day = START_DATE + timedelta(days=day_offset)
    hour = rng.randint(hour_start, hour_end - 1)
    minute = rng.randint(0, 59)
    second = rng.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=second)


def business_hours_time(rng: random.Random, day_offset: int) -> datetime:
    """Random timestamp during business hours (07:00-19:00)."""
    return random_time_in_window(rng, day_offset, 7, 19)


# ── Normal Traffic Generators ─────────────────────────────────────────────


def gen_ad_login(rng: random.Random, emp: dict, day: int) -> dict:
    t = business_hours_time(rng, day)
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "INFO",
        "title": "Active Directory Login Success",
        "description": (
            f"User '{emp['username']}' authenticated via Kerberos "
            f"from {emp['ip']} ({emp['host']}). "
            f"Logon Type 10 (Interactive). Session ID: {rng.randint(10000, 99999)}."
        ),
        "source": "Windows Security Event Log (4624)",
        "source_ip": emp["ip"],
        "dest_ip": "10.10.1.5",
        "user": emp["username"],
        "host": emp["host"],
        "category": "Authentication",
    }


def gen_vpn_connect(rng: random.Random, emp: dict, day: int) -> dict:
    t = business_hours_time(rng, day)
    ext_ip = f"{rng.randint(80, 220)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "INFO",
        "title": "VPN Connection Established",
        "description": (
            f"User '{emp['username']}' connected via SSL VPN. "
            f"External IP: {ext_ip}. Assigned internal IP: {emp['ip']}. "
            f"Client: GlobalProtect 6.1."
        ),
        "source": "Palo Alto GlobalProtect",
        "source_ip": ext_ip,
        "dest_ip": "10.10.0.1",
        "user": emp["username"],
        "host": emp["host"],
        "category": "VPN",
    }


def gen_email_auth(rng: random.Random, emp: dict, day: int) -> dict:
    t = business_hours_time(rng, day)
    proto = rng.choice(["IMAP", "EWS", "ActiveSync", "OWA"])
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "INFO",
        "title": f"Email Authentication ({proto})",
        "description": (
            f"Successful {proto} authentication for '{emp['username']}@{DOMAIN}' "
            f"from {emp['ip']}. Mail client: {rng.choice(['Outlook 365', 'Thunderbird', 'Apple Mail'])}."
        ),
        "source": "Microsoft Exchange / M365",
        "source_ip": emp["ip"],
        "dest_ip": "10.20.1.4",
        "user": emp["username"],
        "host": emp["host"],
        "category": "Authentication",
    }


def gen_file_access(rng: random.Random, emp: dict, day: int) -> dict:
    t = business_hours_time(rng, day)
    share = rng.choice(["finance$", "hr$", "projects$", "shared$", "engineering$"])
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "INFO",
        "title": "Network Share Access",
        "description": (
            f"User '{emp['username']}' accessed \\\\SRV-FILE01\\{share}. "
            f"Operation: {rng.choice(['Read', 'Write', 'List'])}. "
            f"Files accessed: {rng.randint(1, 45)}."
        ),
        "source": "Windows Security Event Log (5140)",
        "source_ip": emp["ip"],
        "dest_ip": "10.10.2.10",
        "user": emp["username"],
        "host": emp["host"],
        "category": "File Access",
    }


def gen_password_change(rng: random.Random, emp: dict, day: int) -> dict:
    t = business_hours_time(rng, day)
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "LOW",
        "title": "Password Change",
        "description": (
            f"User '{emp['username']}' changed their domain password "
            f"from {emp['host']} ({emp['ip']}). Password policy compliant."
        ),
        "source": "Windows Security Event Log (4723)",
        "source_ip": emp["ip"],
        "dest_ip": "10.10.1.5",
        "user": emp["username"],
        "host": emp["host"],
        "category": "Authentication",
    }


def gen_account_lockout(rng: random.Random, emp: dict, day: int) -> dict:
    t = business_hours_time(rng, day)
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "MEDIUM",
        "title": "User Account Lockout",
        "description": (
            f"Account '{emp['username']}' locked out after {rng.choice([3, 5])} "
            f"failed login attempts from {emp['ip']} ({emp['host']}). "
            f"Likely forgotten password — user contacted helpdesk."
        ),
        "source": "Windows Security Event Log (4740)",
        "source_ip": emp["ip"],
        "dest_ip": "10.10.1.5",
        "user": emp["username"],
        "host": emp["host"],
        "category": "Failed Login",
    }


def gen_badge_access(rng: random.Random, emp: dict, day: int) -> dict:
    t = business_hours_time(rng, day)
    door = rng.choice([
        "Main Entrance", "Server Room", "Parking Garage",
        f"Floor {rng.randint(1, 5)} - {rng.choice(['North', 'South'])}",
    ])
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "INFO",
        "title": "Physical Badge Access",
        "description": (
            f"Badge scan for '{emp['username']}' at {door}. "
            f"Access: Granted. Badge ID: B-{rng.randint(10000, 99999)}."
        ),
        "source": "Physical Access Control (Lenel)",
        "source_ip": None,
        "dest_ip": None,
        "user": emp["username"],
        "host": None,
        "category": "Physical Access",
    }


def gen_scheduled_scan(rng: random.Random, day: int) -> dict:
    t = random_time_in_window(rng, day, 2, 5)
    scanner = rng.choice(["Nessus", "Qualys", "OpenVAS"])
    scanner_ip = rng.choice(["10.10.0.5", "10.10.0.6"])
    target_subnet = f"10.{rng.choice([10, 20, 30])}.{rng.randint(0, 5)}.0/24"
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "INFO",
        "title": "Scheduled Vulnerability Scan",
        "description": (
            f"{scanner} scanner ({scanner_ip}) performing scheduled scan "
            f"against {target_subnet}. Change record: CHG-{rng.randint(20260301, 20260328):08d}."
        ),
        "source": "Snort IDS",
        "source_ip": scanner_ip,
        "dest_ip": target_subnet.replace("/24", "1"),
        "user": None,
        "host": f"VULN-SCANNER-{rng.randint(1, 2):02d}",
        "category": "Network Scan",
    }


# ── Attack Traffic Generators ─────────────────────────────────────────────


def gen_port_scan(rng: random.Random, day: int, attacker_ip: str) -> dict:
    t = random_time_in_window(rng, day, 0, 5)
    target = rng.choice(TARGETS["ssh"] + TARGETS["rdp"])
    ports = rng.choice(["22,80,443,3389,8080", "22,445,3389,5985", "22,3389,1433,3306"])
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "LOW",
        "title": "External Port Scan Detected",
        "description": (
            f"SYN scan from {attacker_ip} targeting {target['ip']} "
            f"({target['host']}). Ports probed: {ports}. "
            f"Rate: {rng.randint(50, 300)} packets/sec."
        ),
        "source": "Palo Alto Firewall",
        "source_ip": attacker_ip,
        "dest_ip": target["ip"],
        "user": None,
        "host": "FW-EDGE01",
        "category": "Network Scan",
    }


def gen_ssh_brute(
    rng: random.Random,
    base_time: datetime,
    attacker_ip: str,
    target: dict,
    username: str,
    offset_seconds: int,
) -> dict:
    t = base_time + timedelta(seconds=offset_seconds)
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "HIGH",
        "title": "SSH Login Failed",
        "description": (
            f"Failed SSH authentication from {attacker_ip} to "
            f"{target['ip']} ({target['host']}). "
            f"Username: '{username}'. Method: password. "
            f"Attempt blocked after invalid credentials."
        ),
        "source": "SSH Daemon / Fail2Ban",
        "source_ip": attacker_ip,
        "dest_ip": target["ip"],
        "user": username,
        "host": target["host"],
        "category": "Brute Force",
    }


def gen_rdp_brute(
    rng: random.Random,
    base_time: datetime,
    attacker_ip: str,
    target: dict,
    username: str,
    offset_seconds: int,
) -> dict:
    t = base_time + timedelta(seconds=offset_seconds)
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "HIGH",
        "title": "RDP Login Failed",
        "description": (
            f"Failed RDP authentication from {attacker_ip} to "
            f"{target['ip']} ({target['host']}). "
            f"Username: '{username}'. NLA pre-authentication rejected. "
            f"Event ID 4625, Logon Type 10."
        ),
        "source": "Windows Security Event Log (4625)",
        "source_ip": attacker_ip,
        "dest_ip": target["ip"],
        "user": username,
        "host": target["host"],
        "category": "Brute Force",
    }


def gen_web_brute(
    rng: random.Random,
    base_time: datetime,
    attacker_ip: str,
    target: dict,
    username: str,
    offset_seconds: int,
) -> dict:
    t = base_time + timedelta(seconds=offset_seconds)
    path = rng.choice(["/login", "/auth/signin", "/api/v1/auth", "/owa/auth"])
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "MEDIUM",
        "title": "Web Login Failed",
        "description": (
            f"Failed web authentication from {attacker_ip} to "
            f"{target['ip']} ({target['host']}). "
            f"Path: {path}. Username: '{username}'. "
            f"HTTP 401 Unauthorized. User-Agent: python-requests/2.31."
        ),
        "source": "WAF / ModSecurity",
        "source_ip": attacker_ip,
        "dest_ip": target["ip"],
        "user": username,
        "host": target["host"],
        "category": "Brute Force",
    }


def gen_firewall_block(rng: random.Random, t: datetime, attacker_ip: str) -> dict:
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "MEDIUM",
        "title": "IP Blocked by Firewall",
        "description": (
            f"Source IP {attacker_ip} blocked by automated threat response rule "
            f"after exceeding failed login threshold (>50 attempts in 10 min). "
            f"Block duration: 30 minutes."
        ),
        "source": "Palo Alto Firewall",
        "source_ip": attacker_ip,
        "dest_ip": None,
        "user": None,
        "host": "FW-EDGE01",
        "category": "Firewall",
    }


def gen_ids_alert(rng: random.Random, t: datetime, attacker_ip: str, attack_type: str) -> dict:
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "HIGH",
        "title": f"IDS Alert: {attack_type} Brute Force Detected",
        "description": (
            f"Suricata rule SID:{rng.randint(2000000, 2999999)} triggered. "
            f"Multiple failed {attack_type} authentication attempts from "
            f"{attacker_ip}. Pattern matches known brute-force tool signature."
        ),
        "source": "Suricata IDS",
        "source_ip": attacker_ip,
        "dest_ip": None,
        "user": None,
        "host": "IDS-SENSOR01",
        "category": "Intrusion Detection",
    }


# ── Post-Exploitation Events ──────────────────────────────────────────────


def gen_compromise_success(t: datetime, attacker_ip: str, target: dict, username: str) -> dict:
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "CRITICAL",
        "title": "Successful Login After Brute Force",
        "description": (
            f"ALERT: Successful web login for '{username}' from {attacker_ip} "
            f"to {target['ip']} ({target['host']}) after 847 prior failed attempts "
            f"across multiple protocols. Account '{username}' compromised. "
            f"Immediate investigation required."
        ),
        "source": "SIEM Correlation Rule",
        "source_ip": attacker_ip,
        "dest_ip": target["ip"],
        "user": username,
        "host": target["host"],
        "category": "Account Compromise",
    }


def gen_lateral_movement(
    rng: random.Random,
    t: datetime,
    username: str,
    src_ip: str,
    dest: dict,
    method: str,
) -> dict:
    descriptions = {
        "PsExec": (
            f"Remote service creation via PsExec from {src_ip} to "
            f"{dest['ip']} ({dest['host']}). User: '{username}'. "
            f"Service: PSEXESVC. Suspicious: account normally does not "
            f"access this system."
        ),
        "WMI": (
            f"WMI remote process creation from {src_ip} to "
            f"{dest['ip']} ({dest['host']}). User: '{username}'. "
            f"Process: cmd.exe /c whoami & ipconfig. "
            f"Reconnaissance commands detected."
        ),
        "RDP": (
            f"RDP session established from {src_ip} to "
            f"{dest['ip']} ({dest['host']}). User: '{username}'. "
            f"First-time access to this host from this account. "
            f"Logon Type 10, Event ID 4624."
        ),
        "SMB": (
            f"Admin share access (C$) from {src_ip} to "
            f"{dest['ip']} ({dest['host']}). User: '{username}'. "
            f"File operations detected on \\\\{dest['host']}\\C$\\Windows\\Temp\\."
        ),
    }
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "CRITICAL",
        "title": f"Lateral Movement via {method}",
        "description": descriptions[method],
        "source": "Microsoft Defender for Endpoint",
        "source_ip": src_ip,
        "dest_ip": dest["ip"],
        "user": username,
        "host": dest["host"],
        "category": "Lateral Movement",
    }


def gen_data_staging(rng: random.Random, t: datetime, username: str, host: dict) -> dict:
    size_gb = round(rng.uniform(0.5, 4.2), 1)
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "CRITICAL",
        "title": "Suspicious Data Staging",
        "description": (
            f"Large volume file copy on {host['host']} ({host['ip']}). "
            f"User '{username}' staged {size_gb} GB to C:\\Windows\\Temp\\svc\\. "
            f"Sources: mapped network drives, Documents, Desktop. "
            f"Tool: robocopy.exe with /MIR flag."
        ),
        "source": "Microsoft Defender for Endpoint",
        "source_ip": host["ip"],
        "dest_ip": None,
        "user": username,
        "host": host["host"],
        "category": "Data Exfiltration",
    }


def gen_credential_dump(t: datetime, username: str, host: dict) -> dict:
    return {
        "id": next_id(),
        "timestamp": ts(t),
        "severity": "CRITICAL",
        "title": "Credential Dumping Detected",
        "description": (
            f"LSASS memory access detected on {host['host']} ({host['ip']}). "
            f"Process: rundll32.exe accessing lsass.exe (PID 688). "
            f"User: '{username}'. Technique: T1003.001 (OS Credential Dumping). "
            f"Mimikatz-like behavior detected."
        ),
        "source": "Microsoft Defender for Endpoint",
        "source_ip": host["ip"],
        "dest_ip": None,
        "user": username,
        "host": host["host"],
        "category": "Credential Access",
    }


# ── Main Generator ─────────────────────────────────────────────────────────


def generate_log(seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    employees = generate_employees(rng)
    events: list[dict] = []

    # ── Phase 0: Normal traffic (all 7 days) ───────────────────────────
    normal_generators = [
        (gen_ad_login, 0.35),
        (gen_email_auth, 0.20),
        (gen_file_access, 0.15),
        (gen_badge_access, 0.12),
        (gen_vpn_connect, 0.08),
        (gen_password_change, 0.03),
        (gen_account_lockout, 0.02),
    ]

    for day in range(7):
        # Each employee generates 1-4 events per day (weekdays more active)
        is_weekend = day >= 5
        active_employees = employees if not is_weekend else rng.sample(employees, 30)

        for emp in active_employees:
            num_events = rng.randint(1, 2) if is_weekend else rng.randint(1, 4)
            for _ in range(num_events):
                gen_func, _ = rng.choices(
                    normal_generators,
                    weights=[w for _, w in normal_generators],
                )[0]
                events.append(gen_func(rng, emp, day))

        # Scheduled vulnerability scans (1-2 per night)
        for _ in range(rng.randint(1, 2)):
            events.append(gen_scheduled_scan(rng, day))

    # ── Phase 1: Reconnaissance (Day 1-2, nighttime) ──────────────────
    for day in range(2):
        attacker_ip = rng.choice(ATTACKER_IPS[:2])
        for _ in range(rng.randint(8, 15)):
            events.append(gen_port_scan(rng, day, attacker_ip))

    # ── Phase 2: SSH Brute Force (Day 3, 02:00-06:00) ─────────────────
    ssh_base = START_DATE + timedelta(days=2, hours=2)
    attacker_ip = ATTACKER_IPS[0]
    offset = 0
    ssh_targets = TARGETS["ssh"]

    for burst in range(4):  # 4 bursts with IP rotation
        if burst == 2:
            # IP gets blocked, switch
            events.append(gen_firewall_block(rng, ssh_base + timedelta(seconds=offset), attacker_ip))
            events.append(gen_ids_alert(rng, ssh_base + timedelta(seconds=offset + 5), attacker_ip, "SSH"))
            attacker_ip = ATTACKER_IPS[1]
            offset += 120  # 2 min pause

        target = rng.choice(ssh_targets)
        for username in rng.sample(BRUTE_USERNAMES, rng.randint(8, 15)):
            for _ in range(rng.randint(3, 8)):
                events.append(gen_ssh_brute(rng, ssh_base, attacker_ip, target, username, offset))
                offset += rng.randint(1, 4)

    events.append(gen_firewall_block(rng, ssh_base + timedelta(seconds=offset), attacker_ip))
    events.append(gen_ids_alert(rng, ssh_base + timedelta(seconds=offset + 5), attacker_ip, "SSH"))

    # ── Phase 3: RDP Brute Force (Day 4, 01:00-05:00) ─────────────────
    rdp_base = START_DATE + timedelta(days=3, hours=1)
    attacker_ip = ATTACKER_IPS[2]
    offset = 0
    rdp_targets = TARGETS["rdp"]

    for burst in range(3):
        if burst == 1:
            events.append(gen_firewall_block(rng, rdp_base + timedelta(seconds=offset), attacker_ip))
            events.append(gen_ids_alert(rng, rdp_base + timedelta(seconds=offset + 5), attacker_ip, "RDP"))
            attacker_ip = ATTACKER_IPS[3]
            offset += 180

        target = rng.choice(rdp_targets)
        for username in rng.sample(BRUTE_USERNAMES, rng.randint(6, 12)):
            for _ in range(rng.randint(3, 6)):
                events.append(gen_rdp_brute(rng, rdp_base, attacker_ip, target, username, offset))
                offset += rng.randint(2, 5)

    events.append(gen_firewall_block(rng, rdp_base + timedelta(seconds=offset), attacker_ip))
    events.append(gen_ids_alert(rng, rdp_base + timedelta(seconds=offset + 5), attacker_ip, "RDP"))

    # ── Phase 4: Web Login Password Spray (Day 5-6) ───────────────────
    # Slower, distributed — harder to detect
    web_targets = TARGETS["web"]

    # Collect some real employee usernames for the spray
    spray_usernames = [e["username"] for e in rng.sample(employees, 40)]
    spray_usernames.extend(["admin", "administrator", "helpdesk", "service"])

    for day_offset in [4, 5]:
        attacker_ip = rng.choice(ATTACKER_IPS)
        web_base = START_DATE + timedelta(days=day_offset, hours=rng.randint(8, 16))
        offset = 0

        for username in rng.sample(spray_usernames, min(25, len(spray_usernames))):
            target = rng.choice(web_targets)
            for _ in range(rng.randint(2, 5)):
                events.append(gen_web_brute(rng, web_base, attacker_ip, target, username, offset))
                offset += rng.randint(15, 90)  # slower — evading detection

    # ── Phase 5: Successful Compromise (Day 6, 14:30) ─────────────────
    compromised_user = "t.mueller"  # A real-looking employee username
    compromise_time = START_DATE + timedelta(days=5, hours=14, minutes=30)
    target_owa = TARGETS["web"][1]  # OWA
    attacker_ip = ATTACKER_IPS[2]

    events.append(gen_compromise_success(
        compromise_time, attacker_ip, target_owa, compromised_user,
    ))

    # ── Phase 6: Post-Exploitation (Day 6-7) ──────────────────────────
    post_base = compromise_time + timedelta(minutes=15)
    first_host = {"ip": "10.10.3.5", "host": "SRV-APP01"}

    # Credential dump on first accessed server
    events.append(gen_credential_dump(
        post_base, compromised_user, first_host,
    ))

    # Lateral movement to multiple servers
    lateral_targets = [
        ({"ip": "10.10.1.5", "host": "SRV-DC01"}, "PsExec", 25),
        ({"ip": "10.10.2.10", "host": "SRV-FILE01"}, "SMB", 40),
        ({"ip": "10.10.2.11", "host": "SRV-DB01"}, "WMI", 55),
        ({"ip": "10.10.3.6", "host": "SRV-CITRIX01"}, "RDP", 70),
    ]

    for dest, method, minutes_offset in lateral_targets:
        t = post_base + timedelta(minutes=minutes_offset)
        events.append(gen_lateral_movement(
            rng, t, compromised_user, first_host["ip"], dest, method,
        ))

    # Data staging on file server
    events.append(gen_data_staging(
        rng,
        post_base + timedelta(minutes=90),
        compromised_user,
        {"ip": "10.10.2.10", "host": "SRV-FILE01"},
    ))

    # Sort all events by timestamp
    events.sort(key=lambda e: e["timestamp"])

    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate brute-force scenario log for sift")
    parser.add_argument(
        "-o", "--output",
        default=str(Path(__file__).parent / "brute_force_scenario.json"),
        help="Output file path (default: brute_force_scenario.json in fixtures dir)",
    )
    parser.add_argument("--seed", type=int, default=SEED, help="Random seed (default: 42)")
    args = parser.parse_args()

    events = generate_log(seed=args.seed)

    output_path = Path(args.output)
    output_path.write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")

    # Stats
    categories = {}
    severities = {}
    for e in events:
        cat = e.get("category", "Unknown")
        sev = e.get("severity", "Unknown")
        categories[cat] = categories.get(cat, 0) + 1
        severities[sev] = severities.get(sev, 0) + 1

    print(f"Generated {len(events)} events → {output_path}")
    print(f"File size: {output_path.stat().st_size / 1024:.1f} KB")
    print(f"\nSeverity distribution:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in severities:
            print(f"  {sev:10s}: {severities[sev]:5d}")
    print(f"\nCategory distribution:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {cat:25s}: {count:5d}")


if __name__ == "__main__":
    main()
