# core/ec2_audit.py

import boto3
from botocore.exceptions import ClientError
from core.models import create_finding

SERVICE_NAME = "EC2"

# Sensitive ports to monitor
SENSITIVE_PORTS = [22, 3389, 3306, 5432, 27017, 6379, 9200]


def run_ec2_audit():
    findings = []

    try:
        ec2 = boto3.client("ec2")

        # Get all regions
        regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]

        for region in regions:
            regional_ec2 = boto3.client("ec2", region_name=region)

            # ======================================================
            # 1️⃣ Open Security Groups Check
            # ======================================================
            try:
                security_groups = regional_ec2.describe_security_groups()["SecurityGroups"]

                for sg in security_groups:
                    for permission in sg.get("IpPermissions", []):
                        from_port = permission.get("FromPort")
                        to_port = permission.get("ToPort")

                        for ip_range in permission.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                if (
                                    from_port in SENSITIVE_PORTS
                                    or to_port in SENSITIVE_PORTS
                                ):
                                    findings.append(
                                        create_finding(
                                            SERVICE_NAME,
                                            "EC2-NET-001",
                                            sg["GroupId"],
                                            "CRITICAL",
                                            f"Security group open to world on port {from_port}-{to_port}",
                                            region=region
                                        )
                                    )
            except ClientError:
                pass

            # ======================================================
            # 2️⃣ Public IP Exposure
            # ======================================================
            try:
                reservations = regional_ec2.describe_instances()["Reservations"]

                for reservation in reservations:
                    for instance in reservation["Instances"]:
                        public_ip = instance.get("PublicIpAddress")

                        if public_ip:
                            findings.append(
                                create_finding(
                                    SERVICE_NAME,
                                    "EC2-NET-002",
                                    instance["InstanceId"],
                                    "CRITICAL",
                                    f"Instance has public IP: {public_ip}",
                                    region=region
                                )
                            )
            except ClientError:
                pass

            # ======================================================
            # 3️⃣ IAM Role Attached
            # ======================================================
            try:
                reservations = regional_ec2.describe_instances()["Reservations"]

                for reservation in reservations:
                    for instance in reservation["Instances"]:
                        if "IamInstanceProfile" not in instance:
                            findings.append(
                                create_finding(
                                    SERVICE_NAME,
                                    "EC2-IAM-001",
                                    instance["InstanceId"],
                                    "HIGH",
                                    "Instance has no IAM role attached",
                                    region=region
                                )
                            )
            except ClientError:
                pass

            # ======================================================
            # 4️⃣ EBS Encryption Check
            # ======================================================
            try:
                volumes = regional_ec2.describe_volumes()["Volumes"]

                for volume in volumes:
                    if not volume.get("Encrypted"):
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "EC2-ENC-001",
                                volume["VolumeId"],
                                "MEDIUM",
                                "EBS volume not encrypted",
                                region=region
                            )
                        )
            except ClientError:
                pass

            # ======================================================
            # 5️⃣ IMDS Version Check
            # ======================================================
            try:
                reservations = regional_ec2.describe_instances()["Reservations"]

                for reservation in reservations:
                    for instance in reservation["Instances"]:
                        metadata_options = instance.get("MetadataOptions", {})
                        if metadata_options.get("HttpTokens") != "required":
                            findings.append(
                                create_finding(
                                    SERVICE_NAME,
                                    "EC2-IMDS-001",
                                    instance["InstanceId"],
                                    "MEDIUM",
                                    "Instance allows IMDSv1 (HttpTokens not required)",
                                    region=region
                                )
                            )
            except ClientError:
                pass

            # ======================================================
            # 6️⃣ Default Security Group Usage
            # ======================================================
            try:
                reservations = regional_ec2.describe_instances()["Reservations"]

                for reservation in reservations:
                    for instance in reservation["Instances"]:
                        for sg in instance.get("SecurityGroups", []):
                            if sg["GroupName"] == "default":
                                findings.append(
                                    create_finding(
                                        SERVICE_NAME,
                                        "EC2-NET-003",
                                        instance["InstanceId"],
                                        "HIGH",
                                        "Instance using default security group",
                                        region=region
                                    )
                                )
            except ClientError:
                pass

            # ======================================================
            # 7️⃣ Detailed Monitoring Check
            # ======================================================
            try:
                reservations = regional_ec2.describe_instances()["Reservations"]

                for reservation in reservations:
                    for instance in reservation["Instances"]:
                        monitoring_state = instance.get("Monitoring", {}).get("State")

                        if monitoring_state != "enabled":
                            findings.append(
                                create_finding(
                                    SERVICE_NAME,
                                    "EC2-MON-001",
                                    instance["InstanceId"],
                                    "LOW",
                                    "Detailed monitoring not enabled",
                                    region=region
                                )
                            )
            except ClientError:
                pass

    except ClientError as e:
        findings.append(
            create_finding(
                SERVICE_NAME,
                "EC2-ERROR-001",
                "ACCOUNT",
                "LOW",
                f"EC2 audit failed: {str(e)}"
            )
        )

    return findings