#!/usr/bin/env python3
# Version: 1.2-firewall
"""
Firewall Usage Report (PAN-OS) + Tier-3 Shadowed Rule Detection
---------------------------------------------------------------
Connects to a PAN-OS firewall, obtains an API key, downloads the
configuration for a chosen VSYS, and performs:
  • Used vs unused address/service objects
  • Shadowed / redundant rule detection (zone + service + IP containment)

Conservative assumptions:
  • If negate-source/destination is present on either rule, we DO NOT claim coverage.
  • Dynamic address-groups are not expanded; if seen, we DO NOT claim coverage.
  • 'application-default' only covers another 'application-default' (we don't
    evaluate App-ID → ports here). 'any' covers everything.

Exports:
  firewall_reports/
    - usage_shadow_report_<vsys>.json
    - usage_shadow_summary_<vsys>.csv

Run:
  python3 firewall_usage_report_v1.2.py
"""

from __future__ import annotations
import sys, json, csv, getpass, ipaddress
from pathlib import Path
from typing import Dict, List, Tuple, Set

import requests, urllib3
from defusedxml import ElementTree as ET
from rich.console import Console
from rich.table import Table

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================
# API helpers
# =========================
def get_api_key(host: str, user: str, pw: str, verify: bool) -> str:
    url = f"{host.rstrip('/')}/api/"
    r = requests.get(url, params={"type":"keygen","user":user,"password":pw}, verify=verify, timeout=20)
    r.raise_for_status()
    root = ET.fromstring(r.text)
    key = root.findtext(".//key")
    if not key:
        msg = root.findtext(".//msg") or r.text
        raise RuntimeError(f"Login failed: {msg}")
    return key

def api_get(host: str, key: str, xpath: str, verify: bool):
    url = f"{host.rstrip('/')}/api/"
    r = requests.get(url, params={"type":"config","action":"get","xpath":xpath,"key":key}, verify=verify, timeout=30)
    r.raise_for_status()
    return ET.fromstring(r.text)

def detect_device_entry(host: str, key: str, verify: bool) -> str:
    root = api_get(host, key, "/config/devices", verify)
    names = [e.get("name") for e in root.findall(".//entry")]
    return names[0] if names else "localhost.localdomain"

# =========================
# XPaths
# =========================
def rules_xpath(dev, vsys):      return f"/config/devices/entry[@name='{dev}']/vsys/entry[@name='{vsys}']/rulebase/security/rules"
def addr_xpath(dev, vsys):       return f"/config/devices/entry[@name='{dev}']/vsys/entry[@name='{vsys}']/address"
def addrgrp_xpath(dev, vsys):    return f"/config/devices/entry[@name='{dev}']/vsys/entry[@name='{vsys}']/address-group"
def svc_xpath(dev, vsys):        return f"/config/devices/entry[@name='{dev}']/vsys/entry[@name='{vsys}']/service"
def svcgrp_xpath(dev, vsys):     return f"/config/devices/entry[@name='{dev}']/vsys/entry[@name='{vsys}']/service-group"
def shared_addr_xpath():         return "/config/shared/address"
def shared_addrgrp_xpath():      return "/config/shared/address-group"
def shared_svc_xpath():          return "/config/shared/service"
def shared_svcgrp_xpath():       return "/config/shared/service-group"

# =========================
# XML helpers
# =========================
def xml_entries(root) -> List[ET.Element]: return root.findall(".//entry")

def members(e: ET.Element, tag: str) -> List[str]:
    node = e.find(tag)
    if node is None: return ["any"] if tag in ("source","destination","application","service","from","to") else []
    vals = [m.text for m in node.findall("member") if m is not None and m.text]
    if node.find("any") is not None or "any" in vals: return ["any"]
    return vals or (["any"] if tag in ("source","destination","application","service","from","to") else [])

# =========================
# Model extraction
# =========================
def load_rules(root: ET.Element) -> List[dict]:
    rules = []
    for i, e in enumerate(xml_entries(root)):
        rules.append({
            "name": e.get("name",""),
            "index": i,
            "disabled": (e.findtext("disabled") == "yes"),
            "from": members(e,"from"),
            "to": members(e,"to"),
            "src": members(e,"source"),
            "dst": members(e,"destination"),
            "app": members(e,"application"),
            "svc": members(e,"service"),
            "action": e.findtext("action","allow"),
            "neg_src": (e.findtext("negate-source") == "yes"),
            "neg_dst": (e.findtext("negate-destination") == "yes"),
        })
    return rules

def load_address_objects(addr_xml: ET.Element) -> Dict[str, Tuple[str,str]]:
    """
    Returns {name: (type, value)} where type in {"ip-netmask","ip-range","fqdn"}.
    """
    out = {}
    for e in xml_entries(addr_xml):
        name = e.get("name"); 
        if not name: continue
        if e.find("ip-netmask") is not None:
            out[name] = ("ip-netmask", e.findtext("ip-netmask"))
        elif e.find("ip-range") is not None:
            out[name] = ("ip-range", e.findtext("ip-range"))
        elif e.find("fqdn") is not None:
            out[name] = ("fqdn", e.findtext("fqdn"))
    return out

def load_address_groups(ag_xml: ET.Element) -> Dict[str, dict]:
    """
    Returns {name: {"static":[...], "dynamic":filter or None}}
    """
    out = {}
    for e in xml_entries(ag_xml):
        name = e.get("name"); 
        if not name: continue
        stat = [m.text for m in e.findall("./static/member") if m.text]
        dyn = e.findtext("./dynamic/filter")
        out[name] = {"static": stat, "dynamic": dyn}
    return out

def load_service_objects(svc_xml: ET.Element) -> Dict[str, dict]:
    """
    Returns {name: {"proto": "tcp"/"udp", "ports": [(start,end),...]}}
    """
    out = {}
    for e in xml_entries(svc_xml):
        name = e.get("name"); 
        if not name: continue
        node_tcp = e.find("protocol/tcp/port")
        node_udp = e.find("protocol/udp/port")
        if node_tcp is not None and (node_tcp.text or "").strip():
            out[name] = {"proto": "tcp", "ports": parse_port_ranges(node_tcp.text)}
        elif node_udp is not None and (node_udp.text or "").strip():
            out[name] = {"proto": "udp", "ports": parse_port_ranges(node_udp.text)}
    return out

def load_service_groups(svcgrp_xml: ET.Element) -> Dict[str, List[str]]:
    """
    Returns {group_name: [member service or group names]}.
    """
    out = {}
    for e in xml_entries(svcgrp_xml):
        name = e.get("name"); 
        if not name: continue
        members_ = [m.text for m in e.findall("./members/member") if m.text]
        out[name] = members_
    return out

# =========================
# Port parsing / coverage
# =========================
def parse_port_ranges(spec: str) -> List[Tuple[int,int]]:
    """
    "80,443,8080-8082" -> [(80,80),(443,443),(8080,8082)]
    """
    ranges = []
    for token in (spec or "").split(","):
        t = token.strip()
        if not t: continue
        if "-" in t:
            a,b = t.split("-",1)
            ranges.append((int(a), int(b)))
        else:
            n = int(t)
            ranges.append((n,n))
    return ranges

def ranges_cover(big: List[Tuple[int,int]], small: List[Tuple[int,int]]) -> bool:
    """
    True if for every (s1,s2) in small, there exists (b1,b2) in big with b1<=s1 and b2>=s2
    """
    for s1,s2 in small:
        ok = False
        for b1,b2 in big:
            if b1 <= s1 and b2 >= s2:
                ok = True; break
        if not ok: return False
    return True

def service_set(name: str,
                svc_map: Dict[str,dict],
                svcgrp_map: Dict[str,List[str]],
                visited: Set[str]|None=None) -> List[Tuple[str,List[Tuple[int,int]]]]:
    """
    Expand a service or service-group name to a list of (proto, ranges).
    """
    if visited is None: visited=set()
    if name in visited: return []
    visited.add(name)

    if name in svc_map:
        item = svc_map[name]
        return [(item["proto"], item["ports"])]

    if name in svcgrp_map:
        out=[]
        for m in svcgrp_map[name]:
            out.extend(service_set(m, svc_map, svcgrp_map, visited))
        return out

    # unknown (could be 'any' or 'application-default' handled outside)
    return []

def services_cover(a_list: List[str],
                   b_list: List[str],
                   svc_map: Dict[str,dict],
                   svcgrp_map: Dict[str,List[str]]) -> bool:
    """
    Service coverage with semantics:
      - "any" covers everything
      - "application-default" only covers "application-default"
      - Otherwise, compare port ranges per proto after expanding groups
    """
    if "any" in a_list: return True
    if "any" in b_list: return False

    if "application-default" in a_list:
        # conservative: only cover if B is also app-default
        return b_list == ["application-default"]
    if "application-default" in b_list:
        # A doesn't imply app-default; not guaranteed to cover
        return False

    # Build proto -> ranges coverage for A and B
    def proto_ranges(names: List[str]) -> Dict[str, List[Tuple[int,int]]]:
        pr: Dict[str, List[Tuple[int,int]]] = {}
        for n in names:
            for proto, rngs in service_set(n, svc_map, svcgrp_map):
                pr.setdefault(proto, []).extend(rngs)
        # merge ranges (simple normalization)
        for p in pr:
            pr[p] = merge_ranges(pr[p])
        return pr

    A = proto_ranges(a_list)
    B = proto_ranges(b_list)

    # If B has no resolvable services (e.g., unknown names), be conservative
    if not B and b_list: 
        return False

    # For each proto in B, ensure A has ranges that cover B's
    for proto, br in B.items():
        ar = A.get(proto, [])
        if not ar:
            return False
        if not ranges_cover(ar, br):
            return False
    return True

def merge_ranges(ranges: List[Tuple[int,int]]) -> List[Tuple[int,int]]:
    if not ranges: return []
    rs = sorted(ranges, key=lambda x: (x[0], x[1]))
    merged = [rs[0]]
    for s,e in rs[1:]:
        ms,me = merged[-1]
        if s <= me+1:
            merged[-1] = (ms, max(me, e))
        else:
            merged.append((s,e))
    return merged

# =========================
# Address expansion / coverage
# =========================
def expand_addr_names(names: List[str],
                      addr_map: Dict[str, Tuple[str,str]],
                      ag_map: Dict[str, dict],
                      visited: Set[str]|None=None) -> Set[str]:
    """
    Expand static address-groups recursively to their member object names.
    Returns raw object names (address objects), NOT CIDRs yet.
    Dynamic groups are considered unknown → not expanded.
    """
    if visited is None: visited=set()
    out:set[str] = set()
    for n in names:
        if n == "any":
            out.add("any")
            continue
        if n in visited: 
            continue
        visited.add(n)
        if n in addr_map:
            out.add(n)
        elif n in ag_map:
            if ag_map[n].get("dynamic"):
                # unknown scope; skip (conservative)
                continue
            stat = ag_map[n].get("static") or []
            out |= expand_addr_names(stat, addr_map, ag_map, visited)
        else:
            # unknown symbol; skip (conservative)
            continue
    return out

def netset_from_object_names(obj_names: Set[str],
                             addr_map: Dict[str, Tuple[str,str]]) -> Tuple[Set[ipaddress._BaseNetwork], Set[str]]:
    """
    Convert address object names into IP networks. Returns (networks, fqdn_or_unknown_names)
    """
    nets:set[ipaddress._BaseNetwork] = set()
    leftovers:set[str] = set()
    for n in obj_names:
        if n == "any":
            return {"any"}, set()
        t,v = addr_map.get(n, (None,None))
        if t == "ip-netmask":
            try:
                nets.add(ipaddress.ip_network(v, strict=False))
            except Exception:
                leftovers.add(n)
        elif t == "ip-range":
            # convert a-b into two /32 nets for endpoints + note: coarse approx by covering entire range with supernets
            try:
                start,end = v.split("-",1)
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
                # summarize via collapse_addresses over full range
                rng = list(ipaddress.summarize_address_range(start_ip, end_ip))
                nets |= set(rng)
            except Exception:
                leftovers.add(n)
        elif t == "fqdn":
            leftovers.add(n)  # cannot reason here
        else:
            leftovers.add(n)  # unknown
    return nets, leftovers

def nets_cover(big: Set[ipaddress._BaseNetwork], small: Set[ipaddress._BaseNetwork]) -> bool:
    for s in small:
        if not any((s.subnet_of(b)) for b in big):
            return False
    return True

def addresses_cover(a_list: List[str],
                    b_list: List[str],
                    addr_map: Dict[str, Tuple[str,str]],
                    ag_map: Dict[str, dict]) -> bool:
    if "any" in a_list: return True
    if "any" in b_list: return False

    # Expand groups to underlying address object names
    a_objs = expand_addr_names(a_list, addr_map, ag_map)
    b_objs = expand_addr_names(b_list, addr_map, ag_map)

    if "any" in a_objs: return True
    if "any" in b_objs: return False

    a_nets, a_left = netset_from_object_names(a_objs, addr_map)
    b_nets, b_left = netset_from_object_names(b_objs, addr_map)

    # If B contains non-IP-resolvable items (FQDN/dynamic/unknown), be conservative
    if b_left:
        return False
    if a_nets == {"any"}:
        return True
    if not a_nets:
        return False
    return nets_cover(a_nets, b_nets)

def zones_cover(a: List[str], b: List[str]) -> bool:
    if "any" in a: return True
    if "any" in b: return False
    return set(b).issubset(set(a))

# =========================
# Shadow detection
# =========================
def rule_covers(a: dict, b: dict,
                addr_map: Dict[str,Tuple[str,str]],
                ag_map: Dict[str,dict],
                svc_map: Dict[str,dict],
                svcgrp_map: Dict[str,List[str]]) -> bool:
    if b.get("disabled"): return False
    if a.get("neg_src") or a.get("neg_dst") or b.get("neg_src") or b.get("neg_dst"):
        return False  # conservative: negation requires packet-space math

    # Zones
    if not zones_cover(a["from"], b["from"]): return False
    if not zones_cover(a["to"],   b["to"]):   return False

    # Addresses
    if not addresses_cover(a["src"], b["src"], addr_map, ag_map): return False
    if not addresses_cover(a["dst"], b["dst"], addr_map, ag_map): return False

    # Applications (coarse)
    if "any" in a["app"]:
        pass
    elif "any" in b["app"]:
        return False
    else:
        # require subset by names (no App-ID inference here)
        if not set(b["app"]).issubset(set(a["app"])):
            return False

    # Services
    if not services_cover(a["svc"], b["svc"], svc_map, svcgrp_map): return False

    return True

def find_shadowed(rules: List[dict],
                  addr_map, ag_map, svc_map, svcgrp_map) -> List[Tuple[str,str,str]]:
    """
    Returns list of (shadowing_rule, shadowed_rule, reason)
    """
    shadows: List[Tuple[str,str,str]] = []
    seen: List[dict] = []
    for r in rules:
        for prev in seen:
            if rule_covers(prev, r, addr_map, ag_map, svc_map, svcgrp_map):
                reason = "deny-before-allow" if prev["action"]!="allow" and r["action"]=="allow" else "redundant"
                shadows.append((prev["name"], r["name"], reason))
                break
        seen.append(r)
    return shadows

# =========================
# Usage analysis (unchanged core)
# =========================
def extract_names(root: ET.Element) -> List[str]:
    return [e.get("name") for e in xml_entries(root) if e.get("name")]

def analyze_usage(rules: List[dict],
                  addr_xml, ag_xml, svc_xml,
                  shared_addr, shared_ag, shared_svc,
                  include_shared: bool) -> dict:
    used_addr:set[str]=set(); used_svc:set[str]=set()
    for r in rules:
        for tag in ("src","dst"):
            for v in r[tag]:
                if v!="any": used_addr.add(v)
        for s in r["svc"]:
            if s not in ("any","application-default"): used_svc.add(s)

    all_addr = extract_names(addr_xml) + (extract_names(shared_addr) if include_shared else [])
    all_ag   = extract_names(ag_xml)   + (extract_names(shared_ag)   if include_shared else [])
    all_svc  = extract_names(svc_xml)  + (extract_names(shared_svc)  if include_shared else [])

    all_addr, all_ag, all_svc = map(lambda x: sorted(set(x)), (all_addr, all_ag, all_svc))

    unused_addr = sorted(set(all_addr) - used_addr)
    unused_ag   = sorted(set(all_ag)   - used_addr)  # group considered "used" if group name appears in rules
    unused_svc  = sorted(set(all_svc)  - used_svc)

    return {
        "used_addr": sorted(list(used_addr)),
        "used_svc":  sorted(list(used_svc)),
        "unused_addr": unused_addr,
        "unused_ag":   unused_ag,
        "unused_svc":  unused_svc,
        "counts": {
            "addresses": len(all_addr),
            "address_groups": len(all_ag),
            "services": len(all_svc),
        }
    }

# =========================
# Reporting
# =========================
def report_table(host, vsys, usage, shadows):
    t = Table(title=f"Firewall: {host}  VSYS: {vsys}")
    t.add_column("Type"); t.add_column("Total"); t.add_column("Unused"); t.add_column("Examples", overflow="fold")
    t.add_row("Addresses", str(usage["counts"]["addresses"]), str(len(usage["unused_addr"])), ", ".join(usage["unused_addr"][:6]) or "-")
    t.add_row("Address-Groups", str(usage["counts"]["address_groups"]), str(len(usage["unused_ag"])), ", ".join(usage["unused_ag"][:6]) or "-")
    t.add_row("Services", str(usage["counts"]["services"]), str(len(usage["unused_svc"])), ", ".join(usage["unused_svc"][:6]) or "-")
    console.print(t)

    if shadows:
        st = Table(title="Shadowed / Redundant Rules (tier-3)")
        st.add_column("Shadowing Rule"); st.add_column("Shadowed Rule"); st.add_column("Reason")
        for a,b,r in shadows:
            st.add_row(a,b,r)
        console.print(st)
    else:
        console.print("[green]No shadowed rules detected (under current conservative assumptions).[/green]")

# =========================
# Main
# =========================
def main():
    console.print("[bold cyan]=== PAN-OS Firewall Usage Report + Shadow Check (v1.2) ===[/bold cyan]\n")
    host = console.input("Firewall URL (e.g. https://192.168.0.190): ").strip()
    if not host.startswith("http"): host = "https://" + host
    user = console.input("Username: ").strip()
    pw = getpass.getpass("Password: ")
    vsys = console.input("VSYS (default: vsys1): ").strip() or "vsys1"
    include_shared = console.input("Include shared objects? (y/N): ").lower().startswith("y")
    skip_verify = console.input("Skip SSL verification? (y/N): ").lower().startswith("y")
    verify = not skip_verify
    if skip_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    console.print("\n[bold]Authenticating...[/bold]")
    key = get_api_key(host, user, pw, verify)
    console.print("[green]Login successful.[/green]")
    dev = detect_device_entry(host, key, verify)
    console.print(f"[green]Detected device entry:[/green] {dev}")

    console.print("[cyan]Fetching rules...[/cyan]")
    r_xml = api_get(host, key, rules_xpath(dev, vsys), verify)
    rules = load_rules(r_xml)
    console.print(f"[green]Loaded {len(rules)} rules.[/green]")

    console.print("[cyan]Fetching objects...[/cyan]")
    addr_xml   = api_get(host, key, addr_xpath(dev, vsys), verify)
    ag_xml     = api_get(host, key, addrgrp_xpath(dev, vsys), verify)
    svc_xml    = api_get(host, key, svc_xpath(dev, vsys), verify)
    svcgrp_xml = api_get(host, key, svcgrp_xpath(dev, vsys), verify)

    if include_shared:
        shared_addr   = api_get(host, key, shared_addr_xpath(), verify)
        shared_ag     = api_get(host, key, shared_addrgrp_xpath(), verify)
        shared_svc    = api_get(host, key, shared_svc_xpath(), verify)
        shared_svcgrp = api_get(host, key, shared_svcgrp_xpath(), verify)
    else:
        shared_addr = ET.Element("empty"); shared_ag = ET.Element("empty")
        shared_svc = ET.Element("empty");  shared_svcgrp = ET.Element("empty")

    # Build maps
    addr_map = load_address_objects(addr_xml)
    ag_map   = load_address_groups(ag_xml)
    svc_map  = load_service_objects(svc_xml)
    svcgrp_map = load_service_groups(svcgrp_xml)

    if include_shared:
        # merge shared into local maps (local VSYS takes precedence if name clashing)
        for n,v in load_address_objects(shared_addr).items():
            addr_map.setdefault(n, v)
        for n,v in load_address_groups(shared_ag).items():
            ag_map.setdefault(n, v)
        for n,v in load_service_objects(shared_svc).items():
            svc_map.setdefault(n, v)
        for n,v in load_service_groups(shared_svcgrp).items():
            svcgrp_map.setdefault(n, v)

    usage = analyze_usage(rules, addr_xml, ag_xml, svc_xml, shared_addr, shared_ag, shared_svc, include_shared)
    shadows = find_shadowed(rules, addr_map, ag_map, svc_map, svcgrp_map)

    report_table(host, vsys, usage, shadows)

    # Exports
    outdir = Path("firewall_reports"); outdir.mkdir(exist_ok=True)
    json_path = outdir / f"usage_shadow_report_{vsys}.json"
    csv_path  = outdir / f"usage_shadow_summary_{vsys}.csv"

    data = {
        "firewall": host,
        "vsys": vsys,
        "usage": usage,
        "shadowed_rules": shadows
    }
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["shadowing_rule","shadowed_rule","reason"])
        w.writerows(shadows)

    console.print(f"[green]✅ Completed. Reports saved to {outdir.resolve()}[/green]")

if __name__ == "__main__":
    main()
