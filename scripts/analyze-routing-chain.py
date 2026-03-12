#!/usr/bin/env python3
"""
Phase 2: Routing-Chain Analysis for Public Endpoints

Determines the actual internet attack surface by following:
  Internet Gateway → Route Table → Public Subnet → Resource → Security Group

Pure analysis script — reads JSON from data directory, outputs markdown to stdout.
No AWS API calls.

Usage:
  python3 scripts/analyze-routing-chain.py --data-dir /tmp/ref-docs
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def load_json(data_dir: Path, filename: str) -> list:
    """Load a JSON file, return empty list if missing or empty."""
    path = data_dir / filename
    if not path.exists():
        print(f"⚠ Missing {filename}, skipping", file=sys.stderr)
        return []
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError) as e:
        print(f"⚠ Error reading {filename}: {e}", file=sys.stderr)
        return []


def build_igw_vpc_map(igws: list) -> dict:
    """Build {account: {vpc_id: igw_id}} from InternetGateway data."""
    igw_map = defaultdict(dict)
    for igw in igws:
        account = igw.get("accountId", "")
        igw_id = igw.get("resourceId", "")
        config = igw.get("configuration", {})
        attachments = config.get("attachments", [])
        for att in attachments:
            vpc_id = att.get("vpcId", "")
            if vpc_id:
                igw_map[account][vpc_id] = igw_id
    return dict(igw_map)


def find_public_route_tables(route_tables: list, igw_map: dict) -> dict:
    """Find route tables with 0.0.0.0/0 → IGW routes.
    Returns {account: {route_table_id: {"igw_id": ..., "subnet_ids": [...]}}}
    """
    public_rtbs = defaultdict(dict)
    for rtb in route_tables:
        account = rtb.get("accountId", "")
        rtb_id = rtb.get("resourceId", "")
        config = rtb.get("configuration", {})

        # Check routes for 0.0.0.0/0 → igw-*
        routes = config.get("routes", [])
        igw_id = None
        for route in routes:
            dest = route.get("destinationCidrBlock", "")
            gw = route.get("gatewayId", "")
            if dest == "0.0.0.0/0" and gw.startswith("igw-"):
                igw_id = gw
                break

        if not igw_id:
            continue

        # Extract associated subnet IDs
        associations = config.get("associations", [])
        subnet_ids = []
        for assoc in associations:
            sid = assoc.get("subnetId", "")
            if sid:
                subnet_ids.append(sid)

        public_rtbs[account][rtb_id] = {
            "igw_id": igw_id,
            "subnet_ids": subnet_ids,
        }

    return dict(public_rtbs)


def identify_public_subnets(subnets: list, public_rtbs: dict) -> dict:
    """Identify public subnets based on route table associations.
    Returns {account: {subnet_id: {"rtb_id": ..., "igw_id": ..., "cidr": ...}}}
    """
    # Build lookup: which subnets are in public route tables
    public_subnet_set = defaultdict(dict)
    for account, rtbs in public_rtbs.items():
        for rtb_id, info in rtbs.items():
            for subnet_id in info["subnet_ids"]:
                public_subnet_set[account][subnet_id] = {
                    "rtb_id": rtb_id,
                    "igw_id": info["igw_id"],
                }

    # Enrich with CIDR from subnet data
    result = defaultdict(dict)
    for subnet in subnets:
        account = subnet.get("accountId", "")
        subnet_id = subnet.get("resourceId", "")
        config = subnet.get("configuration", {})
        cidr = config.get("cidrBlock", "")

        if account in public_subnet_set and subnet_id in public_subnet_set[account]:
            entry = public_subnet_set[account][subnet_id].copy()
            entry["cidr"] = cidr
            entry["map_public_ip"] = config.get("mapPublicIpOnLaunch", False)
            result[account][subnet_id] = entry

    return dict(result)


def find_open_security_groups(security_groups: list) -> dict:
    """Find SGs with inbound 0.0.0.0/0 or ::/0.
    Returns {account: {sg_id: [open_ports]}}
    """
    open_sgs = defaultdict(dict)
    for sg in security_groups:
        account = sg.get("accountId", "")
        sg_id = sg.get("resourceId", "")
        config = sg.get("configuration", {})
        ip_permissions = config.get("ipPermissions", [])

        open_ports = []
        for perm in ip_permissions:
            from_port = perm.get("fromPort", -1)
            to_port = perm.get("toPort", -1)
            is_open = False

            # Check IPv4 ranges
            for ip_range in perm.get("ipRanges", []):
                cidr = ip_range.get("cidrIp", "")
                if cidr == "0.0.0.0/0":
                    is_open = True
                    break

            # Check IPv6 ranges
            if not is_open:
                for ip_range in perm.get("ipv6Ranges", []):
                    cidr = ip_range.get("cidrIpv6", "")
                    if cidr == "::/0":
                        is_open = True
                        break

            if is_open:
                if from_port == -1 and to_port == -1:
                    open_ports.append("all")
                elif from_port == to_port:
                    open_ports.append(str(from_port))
                else:
                    open_ports.append(f"{from_port}-{to_port}")

        if open_ports:
            open_sgs[account][sg_id] = open_ports

    return dict(open_sgs)


def analyze_resources(data_dir: Path, public_subnets: dict, open_sgs: dict) -> list:
    """Cross-reference resources with public subnets and open SGs.
    Returns list of confirmed internet-reachable resources.
    """
    reachable = []

    # EC2 Instances
    instances = load_json(data_dir, "instances_raw.json")
    for inst in instances:
        account = inst.get("accountId", "")
        instance_id = inst.get("resourceId", "")
        config = inst.get("configuration", {})
        subnet_id = config.get("subnetId", "")
        public_ip = config.get("publicIpAddress", "")

        if not public_ip:
            continue

        # Check if in public subnet
        if account not in public_subnets or subnet_id not in public_subnets[account]:
            continue

        subnet_info = public_subnets[account][subnet_id]

        # Check security groups
        sg_ids = [sg.get("groupId", "") for sg in config.get("securityGroups", [])]
        resource_open_ports = []
        matched_sg = ""
        for sg_id in sg_ids:
            if account in open_sgs and sg_id in open_sgs[account]:
                resource_open_ports.extend(open_sgs[account][sg_id])
                matched_sg = sg_id

        if not resource_open_ports:
            continue

        reachable.append({
            "account": account,
            "resource": instance_id,
            "type": "EC2",
            "address": public_ip,
            "ports": ", ".join(sorted(set(resource_open_ports))),
            "path": f"{subnet_info['igw_id']} → {subnet_info['rtb_id']} → {subnet_id} → {matched_sg}",
        })

    # Internet-facing ALBs
    albs = load_json(data_dir, "albs.json")
    for alb in albs:
        account = alb.get("accountId", "")
        name = alb.get("resourceName", alb.get("resourceId", ""))
        config = alb.get("configuration", {})
        dns_name = config.get("dNSName", "")
        alb_type = config.get("type", "")

        # ALBs with internet-facing scheme are already filtered in Phase 1 query
        # Check if any AZ subnet is in a public subnet
        azs = config.get("availabilityZones", [])
        alb_subnet_ids = [az.get("subnetId", "") for az in azs]

        subnet_info = None
        for sid in alb_subnet_ids:
            if account in public_subnets and sid in public_subnets[account]:
                subnet_info = public_subnets[account][sid]
                break

        # Check security groups
        sg_ids = config.get("securityGroups", [])
        resource_open_ports = []
        matched_sg = ""
        for sg_id in sg_ids:
            if account in open_sgs and sg_id in open_sgs[account]:
                resource_open_ports.extend(open_sgs[account][sg_id])
                matched_sg = sg_id

        path = "internet-facing"
        if subnet_info:
            path = f"{subnet_info['igw_id']} → {subnet_info['rtb_id']} → {matched_sg or 'n/a'}"

        reachable.append({
            "account": account,
            "resource": name,
            "type": f"ALB ({alb_type})",
            "address": dns_name,
            "ports": ", ".join(sorted(set(resource_open_ports))) if resource_open_ports else "SG check n/a",
            "path": path,
        })

    # EIPs
    eips = load_json(data_dir, "eips.json")
    for eip in eips:
        account = eip.get("accountId", "")
        config = eip.get("configuration", {})
        public_ip = config.get("publicIp", "")
        instance_id = config.get("instanceId", "")
        eni_id = config.get("networkInterfaceId", "")

        # EIPs are always publicly routable, but we still want SG info
        target = instance_id or eni_id or "unattached"
        reachable.append({
            "account": account,
            "resource": target,
            "type": "EIP",
            "address": public_ip,
            "ports": "see attached resource",
            "path": "EIP (always public)",
        })

    return reachable


def analyze_edge_services(data_dir: Path) -> list:
    """Identify edge services that are always internet-facing."""
    edge = []

    # CloudFront
    for dist in load_json(data_dir, "cloudfront.json"):
        edge.append({
            "account": dist.get("accountId", ""),
            "resource": dist.get("resourceId", ""),
            "type": "CloudFront",
            "endpoint": dist.get("configuration", {}).get("domainName", "-"),
        })

    # API Gateway REST
    for api in load_json(data_dir, "apigw_rest.json"):
        edge.append({
            "account": api.get("accountId", ""),
            "resource": api.get("resourceName", api.get("resourceId", "")),
            "type": "API Gateway (REST)",
            "endpoint": f"{api.get('resourceId', '')}.execute-api.eu-west-1.amazonaws.com",
        })

    # API Gateway V2
    for api in load_json(data_dir, "apigw_v2.json"):
        edge.append({
            "account": api.get("accountId", ""),
            "resource": api.get("resourceName", api.get("resourceId", "")),
            "type": "API Gateway (HTTP)",
            "endpoint": api.get("configuration", {}).get("apiEndpoint", "-"),
        })

    return edge


def output_markdown(reachable: list, edge_services: list, blind_spots: int):
    """Output Phase 2 markdown to stdout."""

    total = len(reachable) + len(edge_services)
    print(f"## Internet Attack Surface — {total} confirmed reachable")
    print()

    if blind_spots > 0:
        print(f"{{: .warning }}")
        print(f"> {blind_spots} accounts have `config_level: iam_only` — network resources not monitored, excluded from analysis.")
        print()

    # Confirmed reachable VPC resources
    print("### Confirmed Internet-Reachable Resources")
    print()
    if reachable:
        print("| Account | Resource | Type | Public Address | Open Ports | Path |")
        print("|:--------|:---------|:-----|:---------------|:-----------|:-----|")
        for r in sorted(reachable, key=lambda x: (x["account"], x["type"])):
            print(f"| `{r['account']}` | {r['resource']} | {r['type']} | {r['address']} | {r['ports']} | {r['path']} |")
    else:
        print("*No confirmed internet-reachable VPC resources found.*")
    print()

    # Edge services
    print("### Edge Services (always public)")
    print()
    if edge_services:
        print("| Account | Resource | Type | Endpoint |")
        print("|:--------|:---------|:-----|:---------|")
        for e in sorted(edge_services, key=lambda x: (x["account"], x["type"])):
            print(f"| `{e['account']}` | {e['resource']} | {e['type']} | {e['endpoint']} |")
    else:
        print("*No edge services found.*")
    print()


def main():
    parser = argparse.ArgumentParser(description="Phase 2: Routing-chain analysis")
    parser.add_argument("--data-dir", required=True, help="Directory containing JSON data files")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"Error: data directory {data_dir} does not exist", file=sys.stderr)
        sys.exit(1)

    # Load routing-chain data
    igws = load_json(data_dir, "igws.json")
    route_tables = load_json(data_dir, "route_tables.json")
    subnets = load_json(data_dir, "subnets.json")
    security_groups = load_json(data_dir, "security_groups.json")

    print(f"Loaded: {len(igws)} IGWs, {len(route_tables)} route tables, "
          f"{len(subnets)} subnets, {len(security_groups)} security groups", file=sys.stderr)

    # Build routing chain
    igw_map = build_igw_vpc_map(igws)
    public_rtbs = find_public_route_tables(route_tables, igw_map)
    public_subnets = identify_public_subnets(subnets, public_rtbs)
    open_sgs = find_open_security_groups(security_groups)

    total_public_subnets = sum(len(s) for s in public_subnets.values())
    total_open_sgs = sum(len(s) for s in open_sgs.values())
    print(f"Found: {total_public_subnets} public subnets, {total_open_sgs} open security groups", file=sys.stderr)

    # Analyze resources
    reachable = analyze_resources(data_dir, public_subnets, open_sgs)
    edge_services = analyze_edge_services(data_dir)

    print(f"Result: {len(reachable)} reachable VPC resources, {len(edge_services)} edge services", file=sys.stderr)

    # Output markdown
    output_markdown(reachable, edge_services, blind_spots=0)


if __name__ == "__main__":
    main()
