# core/kms_audit.py

import boto3
import json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
from core.models import create_finding

SERVICE_NAME = "KMS"


def run_kms_audit():
    findings = []

    try:
        ec2_global = boto3.client("ec2")
        regions = [r["RegionName"] for r in ec2_global.describe_regions()["Regions"]]

        for region in regions:
            kms = boto3.client("kms", region_name=region)

            # ======================================================
            # Get Customer Managed Keys
            # ======================================================
            try:
                keys = kms.list_keys()["Keys"]
            except ClientError:
                continue

            for key_ref in keys:
                try:
                    metadata = kms.describe_key(KeyId=key_ref["KeyId"])["KeyMetadata"]

                    # Skip AWS managed keys
                    if metadata["KeyManager"] != "CUSTOMER":
                        continue

                    key_id = metadata["KeyId"]

                    # ======================================================
                    # 1️⃣ Key Rotation Check
                    # ======================================================
                    if metadata["KeySpec"] == "SYMMETRIC_DEFAULT":
                        try:
                            rotation = kms.get_key_rotation_status(KeyId=key_id)
                            if not rotation["KeyRotationEnabled"]:
                                findings.append(
                                    create_finding(
                                        SERVICE_NAME,
                                        "KMS-ROT-001",
                                        key_id,
                                        "HIGH",
                                        "Key rotation disabled",
                                        region=region
                                    )
                                )
                        except ClientError:
                            findings.append(
                                create_finding(
                                    SERVICE_NAME,
                                    "KMS-ROT-002",
                                    key_id,
                                    "MEDIUM",
                                    "Unable to determine key rotation status",
                                    region=region
                                )
                            )

                    # ======================================================
                    # 2️⃣ Unused Keys
                    # ======================================================
                    if "LastUsedDate" in metadata:
                        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
                        if metadata["LastUsedDate"] < cutoff:
                            findings.append(
                                create_finding(
                                    SERVICE_NAME,
                                    "KMS-USAGE-001",
                                    key_id,
                                    "MEDIUM",
                                    "Key not used in last 90 days",
                                    region=region
                                )
                            )
                    else:
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "KMS-USAGE-002",
                                key_id,
                                "MEDIUM",
                                "Key has never been used",
                                region=region
                            )
                        )

                    # ======================================================
                    # 3️⃣ Scheduled Deletion
                    # ======================================================
                    if metadata["KeyState"] == "PendingDeletion":
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "KMS-STATE-001",
                                key_id,
                                "HIGH",
                                "Key scheduled for deletion",
                                region=region
                            )
                        )

                    # ======================================================
                    # 4️⃣ Overly Permissive Policy
                    # ======================================================
                    try:
                        policy = kms.get_key_policy(
                            KeyId=key_id,
                            PolicyName="default"
                        )["Policy"]

                        policy_json = json.loads(policy)

                        for statement in policy_json.get("Statement", []):
                            principal = statement.get("Principal")

                            if principal == "*" or principal == {"AWS": "*"}:
                                findings.append(
                                    create_finding(
                                        SERVICE_NAME,
                                        "KMS-POL-001",
                                        key_id,
                                        "CRITICAL",
                                        "Overly permissive key policy (Principal '*')",
                                        region=region
                                    )
                                )
                    except ClientError:
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "KMS-POL-002",
                                key_id,
                                "MEDIUM",
                                "Unable to evaluate key policy",
                                region=region
                            )
                        )

                    # ======================================================
                    # 5️⃣ Description Check
                    # ======================================================
                    if not metadata.get("Description"):
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "KMS-META-001",
                                key_id,
                                "LOW",
                                "Key has no description",
                                region=region
                            )
                        )

                except ClientError:
                    continue

            # ======================================================
            # 6️⃣ Default AWS Managed Key Usage (Service Check)
            # ======================================================
            try:
                # ---- S3 ----
                s3 = boto3.client("s3")
                buckets = s3.list_buckets()["Buckets"]

                for bucket in buckets:
                    try:
                        enc = s3.get_bucket_encryption(Bucket=bucket["Name"])
                        rules = enc["ServerSideEncryptionConfiguration"]["Rules"]

                        for rule in rules:
                            algo = rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                            if algo == "AES256":
                                findings.append(
                                    create_finding(
                                        SERVICE_NAME,
                                        "KMS-SVC-001",
                                        bucket["Name"],
                                        "HIGH",
                                        "S3 bucket uses AWS-managed encryption (not CMK)",
                                        region=region
                                    )
                                )
                    except Exception:
                        pass

                # ---- RDS ----
                rds = boto3.client("rds", region_name=region)
                instances = rds.describe_db_instances()["DBInstances"]

                for db in instances:
                    if db.get("StorageEncrypted") and not db.get("KmsKeyId"):
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "KMS-SVC-002",
                                db["DBInstanceIdentifier"],
                                "HIGH",
                                "RDS uses AWS-managed key instead of CMK",
                                region=region
                            )
                        )

                # ---- EC2 (EBS) ----
                ec2 = boto3.client("ec2", region_name=region)
                volumes = ec2.describe_volumes()["Volumes"]

                for vol in volumes:
                    if vol["Encrypted"] and not vol.get("KmsKeyId"):
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "KMS-SVC-003",
                                vol["VolumeId"],
                                "HIGH",
                                "EBS volume uses AWS-managed key instead of CMK",
                                region=region
                            )
                        )

            except ClientError:
                pass

    except ClientError as e:
        findings.append(
            create_finding(
                SERVICE_NAME,
                "KMS-ERROR-001",
                "ACCOUNT",
                "LOW",
                f"KMS audit failed: {str(e)}"
            )
        )

    return findings