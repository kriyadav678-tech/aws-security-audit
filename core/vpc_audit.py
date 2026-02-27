# core/vpc_audit.py

import boto3
from botocore.exceptions import ClientError
from core.models import create_finding

SERVICE_NAME = "VPC"

RISKY_PORTS = [22, 3389, 3306, 5432]


def run_vpc_audit():
    findings = []

    try:
        ec2_global = boto3.client("ec2")
        regions = [r["RegionName"] for r in ec2_global.describe_regions()["Regions"]]

        for region in regions:
            ec2 = boto3.client("ec2", region_name=region)

            # ======================================================
            # 1️⃣ Public Subnets (Route to IGW)
            # ======================================================
            try:
                route_tables = ec2.describe_route_tables()["RouteTables"]

                for rt in route_tables:
                    for route in rt.get("Routes", []):
                        if route.get("GatewayId", "").startswith("igw-"):
                            for assoc in rt.get("Associations", []):
                                subnet_id = assoc.get("SubnetId")
                                if subnet_id:
                                    findings.append(
                                        create_finding(
                                            SERVICE_NAME,
                                            "VPC-NET-001",
                                            subnet_id,
                                            "HIGH",
                                            "Subnet has route to Internet Gateway",
                                            region=region
                                        )
                                    )
            except ClientError:
                pass

            # ======================================================
            # 2️⃣ Risky Security Groups (0.0.0.0/0)
            # ======================================================
            try:
                sgs = ec2.describe_security_groups()["SecurityGroups"]

                for sg in sgs:
                    for perm in sg.get("IpPermissions", []):
                        from_port = perm.get("FromPort")
                        ip_ranges = perm.get("IpRanges", [])

                        for ip in ip_ranges:
                            if ip.get("CidrIp") == "0.0.0.0/0":
                                if from_port in RISKY_PORTS:
                                    findings.append(
                                        create_finding(
                                            SERVICE_NAME,
                                            "VPC-NET-002",
                                            sg["GroupId"],
                                            "CRITICAL",
                                            f"Security Group allows 0.0.0.0/0 on port {from_port}",
                                            region=region
                                        )
                                    )
            except ClientError:
                pass

            # ======================================================
            # 3️⃣ Overly Permissive NACL
            # ======================================================
            try:
                nacls = ec2.describe_network_acls()["NetworkAcls"]

                for nacl in nacls:
                    for entry in nacl.get("Entries", []):
                        if (
                            entry.get("CidrBlock") == "0.0.0.0/0"
                            and entry.get("RuleAction") == "allow"
                            and not entry.get("Egress")
                        ):
                            findings.append(
                                create_finding(
                                    SERVICE_NAME,
                                    "VPC-NET-003",
                                    nacl["NetworkAclId"],
                                    "HIGH",
                                    "NACL allows inbound 0.0.0.0/0",
                                    region=region
                                )
                            )
            except ClientError:
                pass

            # ======================================================
            # 4️⃣ Flow Logs Check
            # ======================================================
            try:
                flow_logs = ec2.describe_flow_logs()["FlowLogs"]

                if not flow_logs:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "VPC-LOG-001",
                            "ACCOUNT",
                            "HIGH",
                            "No VPC Flow Logs enabled",
                            region=region
                        )
                    )
            except ClientError:
                pass

            # ======================================================
            # 5️⃣ VPC DNS Hostnames
            # ======================================================
            try:
                vpcs = ec2.describe_vpcs()["Vpcs"]

                for vpc in vpcs:
                    vpc_id = vpc["VpcId"]

                    attr = ec2.describe_vpc_attribute(
                        VpcId=vpc_id,
                        Attribute="enableDnsHostnames"
                    )

                    if not attr["EnableDnsHostnames"]["Value"]:
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "VPC-DNS-001",
                                vpc_id,
                                "MEDIUM",
                                "VPC DNS hostnames not enabled",
                                region=region
                            )
                        )
            except ClientError:
                pass

            # ======================================================
            # 6️⃣ Default VPC
            # ======================================================
            try:
                vpcs = ec2.describe_vpcs()["Vpcs"]

                for vpc in vpcs:
                    if vpc.get("IsDefault"):
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "VPC-CONFIG-001",
                                vpc["VpcId"],
                                "MEDIUM",
                                "Default VPC is active",
                                region=region
                            )
                        )
            except ClientError:
                pass

            # ======================================================
            # 7️⃣ Unused Elastic IPs
            # ======================================================
            try:
                addresses = ec2.describe_addresses()["Addresses"]

                for addr in addresses:
                    if "InstanceId" not in addr:
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "VPC-IP-001",
                                addr.get("PublicIp"),
                                "MEDIUM",
                                "Elastic IP not associated",
                                region=region
                            )
                        )
            except ClientError:
                pass

            # ======================================================
            # 8️⃣ NAT Gateway State
            # ======================================================
            try:
                nat_gateways = ec2.describe_nat_gateways()["NatGateways"]

                for nat in nat_gateways:
                    if nat["State"] != "available":
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "VPC-NAT-001",
                                nat["NatGatewayId"],
                                "LOW",
                                "NAT Gateway not in available state",
                                region=region
                            )
                        )
            except ClientError:
                pass

    except ClientError as e:
        findings.append(
            create_finding(
                SERVICE_NAME,
                "VPC-ERROR-001",
                "ACCOUNT",
                "LOW",
                f"VPC audit failed: {str(e)}"
            )
        )

    return findings