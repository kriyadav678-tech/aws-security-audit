# core/rds_audit.py

import boto3
from botocore.exceptions import ClientError
from core.models import create_finding

SERVICE_NAME = "RDS"
DB_PORTS = [3306, 5432, 1433, 1521, 27017]


def run_rds_audit():
    findings = []

    try:
        ec2_global = boto3.client("ec2")
        regions = [r["RegionName"] for r in ec2_global.describe_regions()["Regions"]]

        for region in regions:
            rds = boto3.client("rds", region_name=region)
            ec2 = boto3.client("ec2", region_name=region)

            try:
                instances = rds.describe_db_instances()["DBInstances"]
            except ClientError:
                continue

            for db_instance in instances:
                db_id = db_instance["DBInstanceIdentifier"]

                # ======================================================
                # 1️⃣ Publicly Accessible
                # ======================================================
                if db_instance.get("PubliclyAccessible"):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "RDS-NET-001",
                            db_id,
                            "CRITICAL",
                            "RDS instance is publicly accessible",
                            region=region
                        )
                    )

                # ======================================================
                # 2️⃣ Open DB Port to World
                # ======================================================
                for vpc_sg in db_instance.get("VpcSecurityGroups", []):
                    sg_id = vpc_sg["VpcSecurityGroupId"]

                    try:
                        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]

                        for permission in sg.get("IpPermissions", []):
                            from_port = permission.get("FromPort")
                            to_port = permission.get("ToPort")

                            for ip_range in permission.get("IpRanges", []):
                                if ip_range.get("CidrIp") == "0.0.0.0/0":
                                    if (
                                        from_port in DB_PORTS
                                        or to_port in DB_PORTS
                                    ):
                                        findings.append(
                                            create_finding(
                                                SERVICE_NAME,
                                                "RDS-NET-002",
                                                db_id,
                                                "CRITICAL",
                                                f"Security group {sg_id} allows public DB port {from_port}-{to_port}",
                                                region=region
                                            )
                                        )
                    except ClientError:
                        pass

                # ======================================================
                # 3️⃣ Storage Encryption
                # ======================================================
                if not db_instance.get("StorageEncrypted"):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "RDS-ENC-001",
                            db_id,
                            "HIGH",
                            "RDS storage is not encrypted",
                            region=region
                        )
                    )

                # ======================================================
                # 4️⃣ Backup Retention
                # ======================================================
                if db_instance.get("BackupRetentionPeriod", 0) == 0:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "RDS-BACKUP-001",
                            db_id,
                            "HIGH",
                            "Backup retention is disabled",
                            region=region
                        )
                    )

                # ======================================================
                # 5️⃣ IAM DB Authentication
                # ======================================================
                if not db_instance.get("IAMDatabaseAuthenticationEnabled"):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "RDS-IAM-001",
                            db_id,
                            "HIGH",
                            "IAM database authentication disabled",
                            region=region
                        )
                    )

                # ======================================================
                # 6️⃣ Enhanced Monitoring
                # ======================================================
                if db_instance.get("MonitoringInterval", 0) == 0:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "RDS-MON-001",
                            db_id,
                            "MEDIUM",
                            "Enhanced monitoring disabled",
                            region=region
                        )
                    )

                # ======================================================
                # 7️⃣ Deletion Protection
                # ======================================================
                if not db_instance.get("DeletionProtection"):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "RDS-PROT-001",
                            db_id,
                            "MEDIUM",
                            "Deletion protection disabled",
                            region=region
                        )
                    )

                # ======================================================
                # 8️⃣ Multi-AZ Deployment
                # ======================================================
                if not db_instance.get("MultiAZ"):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "RDS-HA-001",
                            db_id,
                            "MEDIUM",
                            "Multi-AZ deployment not enabled",
                            region=region
                        )
                    )

                # ======================================================
                # 9️⃣ SSL Enforcement
                # ======================================================
                try:
                    param_group_name = db_instance["DBParameterGroups"][0]["DBParameterGroupName"]

                    params = rds.describe_db_parameters(
                        DBParameterGroupName=param_group_name
                    )["Parameters"]

                    for param in params:
                        if param["ParameterName"] in ["rds.force_ssl", "require_secure_transport"]:
                            if param.get("ParameterValue") in ["0", "false", None]:
                                findings.append(
                                    create_finding(
                                        SERVICE_NAME,
                                        "RDS-SSL-001",
                                        db_id,
                                        "CRITICAL",
                                        "SSL enforcement not enabled",
                                        region=region
                                    )
                                )
                except ClientError:
                    pass

                # ======================================================
                # 🔟 Parameter Group Hardening
                # ======================================================
                try:
                    param_group_name = db_instance["DBParameterGroups"][0]["DBParameterGroupName"]

                    params = rds.describe_db_parameters(
                        DBParameterGroupName=param_group_name
                    )["Parameters"]

                    for param in params:
                        if param["ParameterName"] in ["log_statement", "general_log"]:
                            if param.get("ParameterValue") in ["0", "off", None]:
                                findings.append(
                                    create_finding(
                                        SERVICE_NAME,
                                        "RDS-LOG-001",
                                        db_id,
                                        "MEDIUM",
                                        "Database logging disabled in parameter group",
                                        region=region
                                    )
                                )
                except ClientError:
                    pass

            # ======================================================
            # 1️⃣1️⃣ Public Snapshots
            # ======================================================
            try:
                snapshots = rds.describe_db_snapshots(SnapshotType="manual")["DBSnapshots"]

                for snapshot in snapshots:
                    snapshot_id = snapshot["DBSnapshotIdentifier"]

                    attrs = rds.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=snapshot_id
                    )["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]

                    for attr in attrs:
                        if attr["AttributeName"] == "restore":
                            if "all" in attr.get("AttributeValues", []):
                                findings.append(
                                    create_finding(
                                        SERVICE_NAME,
                                        "RDS-SNAP-001",
                                        snapshot_id,
                                        "CRITICAL",
                                        "RDS snapshot is publicly accessible",
                                        region=region
                                    )
                                )
            except ClientError:
                pass

    except ClientError as e:
        findings.append(
            create_finding(
                SERVICE_NAME,
                "RDS-ERROR-001",
                "ACCOUNT",
                "LOW",
                f"RDS audit failed: {str(e)}"
            )
        )

    return findings
