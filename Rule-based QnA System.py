"""
PCAP Anomaly Detection Report + Q&A
====================================

Parses a pcap, runs a few concrete heuristic detectors (port scanning,
large data transfers, TLS on non-standard ports), and renders a report
in a fixed, human-readable format. A templated Q&A layer then lets you
ask questions about the findings ("which are high risk", "why is
finding #2 high risk", etc.) with answers grounded in the actual
detected evidence.

WHAT THIS IS / ISN'T
---------------------
- IS: transparent, rule-based network triage. Every severity and every
  answer traces back to a concrete number (ports touched, bytes moved,
  port a TLS handshake used).
- ISN'T: malware identification. Nothing here can name a trojan family
  or confirm malicious intent — that needs signature/IOC matching
  (YARA, Suricata/Snort, threat-intel feeds) or a sandbox. The Q&A
  layer will say so rather than invent an answer if you ask it that.

Thresholds below are illustrative starting points, not tuned for any
particular environment — adjust them for your traffic baseline.

Usage:
    pip install scapy
    python pcap_report.py --pcap capture.pcap
    python pcap_report.py --pcap capture.pcap --ask "which findings are high risk"
    python pcap_report.py --pcap capture.pcap            # no --ask -> interactive Q&A loop
"""

import argparse
import ipaddress
import re
from collections import defaultdict
from datetime import datetime

from scapy.all import rdpcap, IP, TCP, UDP

# -------------------------------------------------------------------
# Thresholds (tune these for your environment)
# -------------------------------------------------------------------
PORT_SCAN_MEDIUM = 8        # unique ports from one source -> MEDIUM
PORT_SCAN_HIGH = 20         # unique ports from one source -> HIGH
TRANSFER_MEDIUM_BYTES = 100_000       # ~100 KB
TRANSFER_HIGH_BYTES = 1_000_000       # ~1 MB
STANDARD_TLS_PORTS = {443, 8443}

SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# -------------------------------------------------------------------
# 1. Parse the pcap into a flat list of per-packet records
# -------------------------------------------------------------------
def parse_capture(pcap_path):
    packets = rdpcap(pcap_path)
    records = []
    for pkt in packets:
        if IP not in pkt:
            continue
        rec = {
            "time": float(pkt.time),
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "length": len(pkt),
            "sport": None,
            "dport": None,
            "payload": b"",
        }
        if TCP in pkt:
            rec["sport"] = pkt[TCP].sport
            rec["dport"] = pkt[TCP].dport
            rec["payload"] = bytes(pkt[TCP].payload)
        elif UDP in pkt:
            rec["sport"] = pkt[UDP].sport
            rec["dport"] = pkt[UDP].dport
            rec["payload"] = bytes(pkt[UDP].payload)
        records.append(rec)
    return packets, records


def is_internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def format_bytes(n):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

# -------------------------------------------------------------------
# 2. Capture-level summary
# -------------------------------------------------------------------
def capture_summary(pcap_path, packets, records):
    times = [r["time"] for r in records]
    start, end = min(times), max(times)
    total_bytes = sum(r["length"] for r in records)

    all_ips = set()
    for r in records:
        all_ips.add(r["src"])
        all_ips.add(r["dst"])
    internal = {ip for ip in all_ips if is_internal(ip)}
    external = all_ips - internal

    return {
        "pcap_path": pcap_path,
        "start": datetime.fromtimestamp(start),
        "end": datetime.fromtimestamp(end),
        "duration": end - start,
        "total_packets": len(records),
        "total_bytes": total_bytes,
        "internal_ips": len(internal),
        "external_ips": len(external),
    }

# -------------------------------------------------------------------
# 3. Detectors — each returns a list of finding dicts
# -------------------------------------------------------------------
def detect_port_scans(records):
    findings = []
    by_source = defaultdict(lambda: {"ports": set(), "targets": set()})

    for r in records:
        if r["dport"] is None:
            continue
        by_source[r["src"]]["ports"].add(r["dport"])
        by_source[r["src"]]["targets"].add(r["dst"])

    for src, info in by_source.items():
        n_ports = len(info["ports"])
        if n_ports >= PORT_SCAN_HIGH:
            severity = "HIGH"
        elif n_ports >= PORT_SCAN_MEDIUM:
            severity = "MEDIUM"
        else:
            continue

        sample_ports = sorted(info["ports"])[:20]
        findings.append({
            "severity": severity,
            "category": "Port Scan Detected",
            "description": f"{src} contacted {n_ports} unique ports across "
                            f"{len(info['targets'])} host(s).",
            "fields": {
                "Source IP": src,
                "Unique Ports": n_ports,
                "Targets": ", ".join(sorted(info["targets"])),
                "Sample Ports": ", ".join(str(p) for p in sample_ports),
            },
            "rationale": (
                "Contacting many distinct ports on a short window is characteristic "
                "of port scanning / service enumeration — reconnaissance that often "
                "precedes an exploitation attempt."
            ),
        })
    return findings


def detect_large_transfers(records):
    findings = []
    by_pair = defaultdict(int)
    for r in records:
        by_pair[(r["src"], r["dst"])] += r["length"]

    seen_pairs = set()
    for (src, dst), total in by_pair.items():
        pair_key = frozenset([src, dst])
        reverse_total = by_pair.get((dst, src), 0)
        combined = total  # report each directed flow separately

        if combined >= TRANSFER_HIGH_BYTES:
            severity = "HIGH"
        elif combined >= TRANSFER_MEDIUM_BYTES:
            severity = "MEDIUM"
        else:
            continue

        if is_internal(src) and not is_internal(dst):
            direction = "OUTBOUND"
        elif not is_internal(src) and is_internal(dst):
            direction = "INBOUND"
        else:
            direction = "INTERNAL"

        findings.append({
            "severity": severity,
            "category": "Large Data Transfer",
            "description": f"{format_bytes(combined)} transferred: {src} -> {dst} ({direction})",
            "fields": {
                "Source": src,
                "Destination": dst,
                "Total Bytes": format_bytes(combined),
                "Direction": direction,
            },
            "rationale": (
                "Large outbound transfers to an external host can indicate data "
                "exfiltration; large inbound transfers can indicate payload staging. "
                "Volume alone isn't proof of either — context (what's on that host, "
                "whether the transfer was expected) matters."
            ),
        })
    return findings


def detect_tls_nonstandard_port(records):
    findings = []
    by_group = defaultdict(int)
    order = []

    for r in records:
        if r["dport"] is None or r["dport"] in STANDARD_TLS_PORTS:
            continue
        payload = r["payload"]
        if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
            key = (r["src"], r["dst"], r["dport"])
            if key not in by_group:
                order.append(key)
            by_group[key] += 1

    for (src, dst, port) in order:
        count = by_group[(src, dst, port)]
        findings.append({
            "severity": "MEDIUM",
            "category": "TLS on Non-Standard Port",
            "description": f"TLS handshake on port {port}: {src} -> {dst}",
            "fields": {
                "Source": src,
                "Destination": f"{dst}:{port}",
                "Packets": count,
            },
            "rationale": (
                "Standard TLS traffic uses port 443. TLS handshakes on unusual "
                "ports aren't automatically malicious (some legitimate services do "
                "this), but it's a pattern also used by malware command-and-control "
                "channels to blend in while avoiding port-based filtering."
            ),
        })
    return findings

# -------------------------------------------------------------------
# 4. Run all detectors, assemble + sort findings
# -------------------------------------------------------------------
def run_detectors(records):
    findings = []
    findings += detect_port_scans(records)
    findings += detect_large_transfers(records)
    findings += detect_tls_nonstandard_port(records)
    findings.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 99))
    for i, f in enumerate(findings, 1):
        f["id"] = i
    return findings

# -------------------------------------------------------------------
# 5. Report formatting (matches the fixed report layout)
# -------------------------------------------------------------------
def format_report(summary, findings):
    lines = []
    lines.append("=" * 80)
    lines.append("PCAP ANOMALY DETECTION REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"PCAP File: {summary['pcap_path']}")
    lines.append("=" * 80)
    lines.append("")
    lines.append("CAPTURE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Start Time:     {summary['start'].strftime('%Y-%m-%d %H:%M:%S.%f')}")
    lines.append(f"End Time:       {summary['end'].strftime('%Y-%m-%d %H:%M:%S.%f')}")
    lines.append(f"Duration:       {summary['duration']:.1f}s")
    lines.append(f"Total Packets:  {summary['total_packets']:,}")
    lines.append(f"Total Data:     {format_bytes(summary['total_bytes'])}")
    lines.append(f"Internal IPs:   {summary['internal_ips']}")
    lines.append(f"External IPs:   {summary['external_ips']}")
    lines.append("")
    lines.append(f"FINDINGS ({len(findings)} total)")
    lines.append("=" * 80)

    for f in findings:
        lines.append("")
        lines.append(f"Finding #{f['id']}")
        lines.append(f"  Severity:    {f['severity']}")
        lines.append(f"  Category:    {f['category']}")
        lines.append(f"  Description: {f['description']}")
        for key, val in f["fields"].items():
            lines.append(f"  {key}: {val}")

    return "\n".join(lines)

# -------------------------------------------------------------------
# 6. Q&A layer — grounded strictly in the findings list above
# -------------------------------------------------------------------
def format_finding_short(f):
    return f"  #{f['id']} [{f['severity']}] {f['category']}: {f['description']}"


def answer_query(query, findings):
    q = query.lower()

    # --- "why is finding #N ..." / "explain finding #N" / "tell me about #N" ---
    m = re.search(r"#?(\d+)", q)
    if m and any(w in q for w in ["why", "explain", "tell me about", "detail", "describe"]):
        fid = int(m.group(1))
        match = next((f for f in findings if f["id"] == fid), None)
        if not match:
            return f"There's no finding #{fid} in this report (there are {len(findings)})."
        out = [
            f"Finding #{fid} ({match['category']}, {match['severity']}):",
            f"  {match['description']}",
            "",
            f"Why it's flagged: {match['rationale']}",
            "",
            "Details:",
        ]
        for key, val in match["fields"].items():
            out.append(f"  {key}: {val}")
        return "\n".join(out)

    # --- "show finding #N" / "finding 3" ---
    if m and any(w in q for w in ["show", "finding", "what is"]):
        fid = int(m.group(1))
        match = next((f for f in findings if f["id"] == fid), None)
        if not match:
            return f"There's no finding #{fid} in this report (there are {len(findings)})."
        out = [
            f"Finding #{fid} [{match['severity']}] {match['category']}:",
            f"  {match['description']}",
        ]
        for key, val in match["fields"].items():
            out.append(f"  {key}: {val}")
        return "\n".join(out)

    # --- "what type of attacks" / "what attacks" / "what happened" ---
    attack_keywords = ["attack", "threat", "type of attack", "types of attack",
                        "attack type", "threat type", "what happened",
                        "what was detected", "what did you find", "what did you detect"]
    if any(kw in q for kw in attack_keywords):
        categories = defaultdict(list)
        for f in findings:
            categories[f["category"]].append(f)

        attack_descriptions = {
            "Port Scan Detected": (
                "PORT SCANNING: An IP probed many distinct ports on a target, "
                "which is typically reconnaissance to find open services before "
                "an exploitation attempt."
            ),
            "Large Data Transfer": (
                "LARGE DATA TRANSFER: Unusually large volumes of data moved "
                "between hosts. Outbound transfers to external IPs can indicate "
                "data exfiltration; large inbound transfers may indicate payload "
                "delivery or staging."
            ),
            "TLS on Non-Standard Port": (
                "TLS ON NON-STANDARD PORT: Encrypted (TLS) handshakes on ports "
                "other than 443/8443. While some legitimate services do this, it is "
                "also a technique used by malware C2 channels to evade port-based "
                "filtering."
            ),
        }

        out = [f"Attack/anomaly types detected ({len(categories)} categories):", ""]
        for cat, cat_findings in categories.items():
            sevs = [f["severity"] for f in cat_findings]
            high_count = sevs.count("HIGH")
            med_count = sevs.count("MEDIUM")
            sev_summary = []
            if high_count:
                sev_summary.append(f"{high_count} HIGH")
            if med_count:
                sev_summary.append(f"{med_count} MEDIUM")
            out.append(f"  {len(cat_findings)}x {cat} ({', '.join(sev_summary)})")
            if cat in attack_descriptions:
                out.append(f"     {attack_descriptions[cat]}")
            out.append("")
        return "\n".join(out)

    # --- "who is attacking" / "attackers" / "sources" / "suspicious IPs" ---
    if any(w in q for w in ["who is attacking", "attacker", "source ip", "sources",
                             "suspicious ip", "suspicious host", "who attacked",
                             "where did the attack come from", "origin"]):
        ip_findings = defaultdict(list)
        for f in findings:
            src = f["fields"].get("Source IP") or f["fields"].get("Source")
            if src:
                ip_findings[src].append(f)

        out = ["Source IPs involved in findings:", ""]
        for ip, fs in sorted(ip_findings.items(),
                              key=lambda x: min(SEVERITY_RANK.get(ff["severity"], 99) for ff in x[1])):
            worst = min(SEVERITY_RANK.get(ff["severity"], 99) for ff in fs)
            worst_label = {0: "HIGH", 1: "MEDIUM", 2: "LOW"}.get(worst, "?")
            cats = set(ff["category"] for ff in fs)
            internal_tag = " (internal)" if is_internal(ip) else " (external)"
            out.append(f"  {ip}{internal_tag} -- {len(fs)} finding(s), "
                         f"worst severity: {worst_label}")
            out.append(f"    Categories: {', '.join(cats)}")
        return "\n".join(out)

    # --- "what is targeted" / "targets" / "victims" / "destination" ---
    if any(w in q for w in ["target", "victim", "destination", "who was attacked",
                             "what was targeted", "what got hit"]):
        ip_findings = defaultdict(list)
        for f in findings:
            dst = f["fields"].get("Destination") or f["fields"].get("Targets")
            if dst:
                dst_ip = dst.split(":")[0].strip()
                ip_findings[dst_ip].append(f)

        out = ["Targeted IPs/hosts:", ""]
        for ip, fs in sorted(ip_findings.items(), key=lambda x: -len(x[1])):
            cats = set(ff["category"] for ff in fs)
            out.append(f"  {ip} -- {len(fs)} finding(s)")
            out.append(f"    Categories: {', '.join(cats)}")
        return "\n".join(out)

    # --- "recommendations" / "what should I do" / "next steps" ---
    if any(w in q for w in ["recommend", "what should i do", "next step", "action",
                             "how to respond", "remediat", "mitigat", "how to fix",
                             "what do i do", "advice"]):
        out = ["Recommended next steps based on the findings:", ""]

        if any(f["category"] == "Port Scan Detected" for f in findings):
            out.append("  1. PORT SCANS: Check firewall logs for the scanning source IPs.")
            out.append("     Block them if they are not authorized scanners.")
            out.append("     Review which ports actually responded -- those are your exposed services.")
            out.append("")

        if any(f["category"] == "Large Data Transfer" for f in findings):
            outbound = [f for f in findings
                        if f["category"] == "Large Data Transfer"
                        and f["fields"].get("Direction") == "OUTBOUND"]
            if outbound:
                out.append("  2. OUTBOUND DATA TRANSFERS: These are the highest priority.")
                out.append("     Verify the destination IPs against threat intelligence feeds.")
                out.append("     Check what data was sent -- could indicate exfiltration.")
                for f in outbound:
                    out.append(f"     - {f['fields']['Source']} -> {f['fields']['Destination']}"
                                 f" ({f['fields']['Total Bytes']})")
                out.append("")

            inbound = [f for f in findings
                       if f["category"] == "Large Data Transfer"
                       and f["fields"].get("Direction") == "INBOUND"]
            if inbound:
                out.append("  3. INBOUND DATA TRANSFERS: Could be payload delivery.")
                out.append("     Check what was downloaded -- scan with AV/YARA rules.")
                out.append("")

        if any(f["category"] == "TLS on Non-Standard Port" for f in findings):
            out.append("  4. TLS ON ODD PORTS: Investigate the destination IPs.")
            out.append("     If not known legitimate services, this could be C2 traffic.")
            out.append("     Consider blocking or monitoring these connections.")
            out.append("")

        out.append("  GENERAL:")
        out.append("  - Run flagged IPs through VirusTotal, AbuseIPDB, or your threat-intel platform.")
        out.append("  - Check endpoint logs on targeted internal hosts for signs of compromise.")
        out.append("  - Correlate timestamps with other security tool alerts (SIEM, EDR).")
        return "\n".join(out)

    # --- "most dangerous" / "worst" / "biggest threat" / "critical" ---
    if any(w in q for w in ["most dangerous", "worst", "biggest threat", "top finding",
                             "critical", "most severe", "most important", "priority",
                             "most serious"]):
        top = sorted(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 99))[:5]
        out = [f"Top {len(top)} most severe findings:", ""]
        for f in top:
            out.append(format_finding_short(f))
            out.append(f"    Reason: {f['rationale'][:120]}...")
            out.append("")
        return "\n".join(out)

    # --- "summary" / "overview" / "brief" ---
    if any(w in q for w in ["summary", "overview", "brief", "rundown", "recap"]):
        counts = defaultdict(int)
        cat_counts = defaultdict(int)
        for f in findings:
            counts[f["severity"]] += 1
            cat_counts[f["category"]] += 1

        out = [
            f"Report Summary: {len(findings)} findings detected",
            "",
            "By severity:",
        ]
        for sev in ["HIGH", "MEDIUM", "LOW"]:
            if counts.get(sev, 0) > 0:
                out.append(f"  {sev}: {counts[sev]}")
        out.append("")
        out.append("By category:")
        for cat, count in cat_counts.items():
            out.append(f"  {cat}: {count}")
        return "\n".join(out)

    # --- severity filters ---
    for sev in ["high", "medium", "low"]:
        if sev in q and ("risk" in q or "severity" in q or "show" in q or "list" in q
                         or "which" in q or sev == q.strip()):
            rows = [f for f in findings if f["severity"].lower() == sev]
            if not rows:
                return f"No {sev.upper()} severity findings in this report."
            header = f"{sev.upper()}-severity findings ({len(rows)}):"
            return header + "\n" + "\n".join(format_finding_short(f) for f in rows)

    # --- category filters ---
    category_map = {
        "port scan": "Port Scan Detected",
        "scanning": "Port Scan Detected",
        "reconnaissance": "Port Scan Detected",
        "recon": "Port Scan Detected",
        "data transfer": "Large Data Transfer",
        "exfiltration": "Large Data Transfer",
        "data leak": "Large Data Transfer",
        "large transfer": "Large Data Transfer",
        "download": "Large Data Transfer",
        "upload": "Large Data Transfer",
        "tls": "TLS on Non-Standard Port",
        "encrypted": "TLS on Non-Standard Port",
        "ssl": "TLS on Non-Standard Port",
        "c2": "TLS on Non-Standard Port",
        "command and control": "TLS on Non-Standard Port",
    }
    for keyword, category in category_map.items():
        if keyword in q:
            rows = [f for f in findings if f["category"] == category]
            if not rows:
                return f"No '{category}' findings in this report."
            return f"'{category}' findings ({len(rows)}):\n" + \
                   "\n".join(format_finding_short(f) for f in rows)

    # --- "how many" / "count" ---
    if any(w in q for w in ["how many", "count", "total"]):
        counts = defaultdict(int)
        for f in findings:
            counts[f["severity"]] += 1
        return (
            f"Total findings: {len(findings)}\n"
            f"  HIGH: {counts.get('HIGH', 0)}\n"
            f"  MEDIUM: {counts.get('MEDIUM', 0)}\n"
            f"  LOW: {counts.get('LOW', 0)}"
        )

    # --- direction filters ---
    if any(w in q for w in ["outbound", "external traffic", "leaving the network",
                             "data going out", "sent out"]):
        rows = [f for f in findings if f["fields"].get("Direction") == "OUTBOUND"]
        if not rows:
            return "No outbound transfer findings in this report."
        return f"Outbound transfer findings ({len(rows)}):\n" + \
               "\n".join(format_finding_short(f) for f in rows)

    if any(w in q for w in ["inbound", "incoming", "coming in", "received"]):
        rows = [f for f in findings if f["fields"].get("Direction") == "INBOUND"]
        if not rows:
            return "No inbound transfer findings in this report."
        return f"Inbound transfer findings ({len(rows)}):\n" + \
               "\n".join(format_finding_short(f) for f in rows)

    # --- identification-style questions ---
    if any(w in q for w in ["trojan", "malware", "virus", "ransomware", "which malicious",
                             "what malware", "name of the attack", "apt", "threat actor",
                             "who is behind", "what exploit", "cve"]):
        top = sorted(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 99))[:5]
        return (
            "This report cannot name a specific malware family, threat actor, or CVE -- "
            "it only flags suspicious traffic patterns (port scanning, large transfers, "
            "TLS on odd ports). For identification, run the flagged hosts/payloads "
            "through signature-based tools (YARA/Suricata) or a threat-intel lookup "
            "(VirusTotal, AbuseIPDB).\n\n"
            "Highest-severity findings worth prioritizing for that follow-up:\n" +
            "\n".join(format_finding_short(f) for f in top)
        )

    # --- "help" / "what can I ask" ---
    if any(w in q for w in ["help", "what can i ask", "commands", "options", "menu",
                             "what can you do", "how to use"]):
        return (
            "You can ask questions like:\n"
            "  - 'What type of attacks were used?'\n"
            "  - 'Which are high risk?'\n"
            "  - 'Why is finding #1 high risk?'\n"
            "  - 'Who is attacking?'\n"
            "  - 'What was targeted?'\n"
            "  - 'Show me the most dangerous findings'\n"
            "  - 'What should I do?' / 'Recommendations'\n"
            "  - 'Give me a summary'\n"
            "  - 'Show port scan findings'\n"
            "  - 'Show TLS findings'\n"
            "  - 'Show outbound transfers'\n"
            "  - 'Show inbound transfers'\n"
            "  - 'How many findings?'\n"
            "  - 'Explain finding #3'\n"
            "  - 'Is there any malware?'\n"
            "  - 'help'\n"
        )

    # --- fallback ---
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1
    return (
        f"{len(findings)} findings total -- "
        + ", ".join(f"{sev}: {counts.get(sev, 0)}" for sev in ["HIGH", "MEDIUM", "LOW"])
        + ".\n\nTry asking things like:\n"
          "  'What type of attacks were used?'\n"
          "  'Which are high risk?'\n"
          "  'Why is finding #1 high risk?'\n"
          "  'Who is attacking?'\n"
          "  'What should I do?'\n"
          "  'Give me a summary'\n"
          "  Type 'help' for more options."
    )

# -------------------------------------------------------------------
# 7. CLI
# -------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="PCAP anomaly report + Q&A")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--ask", help="One-shot question. Omit to enter interactive mode.")
    args = parser.parse_args()

    packets, records = parse_capture(args.pcap)
    summary = capture_summary(args.pcap, packets, records)
    findings = run_detectors(records)

    print(format_report(summary, findings))

    if args.ask:
        print("\n" + "-" * 80)
        print(f"Q: {args.ask}")
        print(answer_query(args.ask, findings))
    else:
        print("\n" + "-" * 80)
        print("Ask questions about these findings (e.g. 'which are high risk', "
              "'why is finding #1 high risk'). Type 'exit' to quit.")
        while True:
            try:
                q = input("\n> ")
            except (EOFError, KeyboardInterrupt):
                break
            if q.strip().lower() in {"exit", "quit"}:
                break
            print(answer_query(q, findings))


if __name__ == "__main__":
    main()