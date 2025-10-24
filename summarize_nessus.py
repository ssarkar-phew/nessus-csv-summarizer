#!/usr/bin/env python3
"""
Nessus CSV → Aggregated CSV (no pandas)
"""

import sys
import csv
import re

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)

def extract_cves(cell):
    if cell is None:
        return []
    text = str(cell)
    found, seen = [], set()
    for piece in re.split(r"[;,]", text):
        for m in CVE_PATTERN.findall(piece):
            up = m.upper()
            if up not in seen:
                seen.add(up)
                found.append(up)
    return found

def clean_risk(cell):
    if cell is None:
        return None
    s = str(cell).strip()
    if not s or s.lower() == "none":
        return None
    return s

def to_int_port(val):
    try:
        p = int(float(str(val).strip()))
        return p
    except Exception:
        return None

def dedup_preserve_order(items):
    seen, out = set(), []
    for x in items:
        if not x:
            continue
        x = str(x).strip()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out

def main(in_path, out_path):
    with open(in_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            sys.exit("Error: Input CSV has no header row.")

        header_map = {h.lower().strip(): h for h in reader.fieldnames}
        for req in ("host", "port", "protocol"):
            if req not in header_map:
                sys.exit(f"Error: Required column '{req}' not found. Found: {reader.fieldnames}")

        host_col = header_map["host"]
        port_col = header_map["port"]
        proto_col = header_map["protocol"]
        cve_col = header_map.get("cve")
        risk_col = header_map.get("risk")

        per_host_ports, per_host_cves, per_host_risks = {}, {}, {}

        for row in reader:
            host = (row.get(host_col) or "").strip()

            port_val = to_int_port(row.get(port_col))
            proto_val = (row.get(proto_col) or "").strip()
            if port_val and proto_val:
                per_host_ports.setdefault(host, []).append(f"{proto_val} {port_val}")

            if cve_col:
                cves_here = extract_cves(row.get(cve_col))
                if cves_here:
                    per_host_cves.setdefault(host, []).extend(cves_here)

            if risk_col:
                risk = clean_risk(row.get(risk_col))
                if risk:
                    per_host_risks.setdefault(host, []).append(risk)

    # FIXED: merge keys correctly
    all_hosts = set(per_host_ports.keys()) | set(per_host_cves.keys()) | set(per_host_risks.keys())
    hosts = sorted(all_hosts, key=lambda x: (x is None, str(x)))

    with open(out_path, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=["Hosts", "Ports", "Main service", "Notes"])
        writer.writeheader()

        for h in hosts:
            ports_joined = ", ".join(dedup_preserve_order(per_host_ports.get(h, [])))

            notes_parts = []
            cves = dedup_preserve_order(per_host_cves.get(h, []))
            if cves:
                notes_parts.append(f"CVEs: {', '.join(cves)}")
            risks = dedup_preserve_order(per_host_risks.get(h, []))
            if risks:
                notes_parts.append(f"Risks: {', '.join(risks)}")

            writer.writerow({
                "Hosts": h or "",
                "Ports": ports_joined,
                "Main service": "",
                "Notes": " | ".join(notes_parts)
            })

    print(f"✅ Written: {out_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python summarize_nessus.py <input.csv> <output.csv>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
