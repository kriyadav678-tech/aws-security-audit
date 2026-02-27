# core/s3_audit.py

import boto3
from botocore.exceptions import ClientError
from core.models import create_finding

SERVICE_NAME = "S3"


def run_s3_audit():
    findings = []

    try:
        s3 = boto3.client("s3")
        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            bucket_name = bucket["Name"]

            # ======================================================
            # 1️⃣ Public Bucket Policy
            # ======================================================
            try:
                policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
                if policy_status["PolicyStatus"]["IsPublic"]:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "S3-PUB-001",
                            bucket_name,
                            "CRITICAL",
                            "Bucket has a public bucket policy"
                        )
                    )
            except ClientError:
                pass

            # ======================================================
            # 2️⃣ Public ACL
            # ======================================================
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)

                for grant in acl["Grants"]:
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")

                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "S3-PUB-002",
                                bucket_name,
                                "CRITICAL",
                                "Bucket has public ACL configured"
                            )
                        )
            except ClientError:
                pass

            # ======================================================
            # 3️⃣ Block Public Access
            # ======================================================
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab["PublicAccessBlockConfiguration"]

                if not all(config.values()):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "S3-PUB-003",
                            bucket_name,
                            "CRITICAL",
                            "Bucket does not fully block public access"
                        )
                    )
            except ClientError:
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "S3-PUB-004",
                        bucket_name,
                        "CRITICAL",
                        "Bucket has NO Public Access Block configured"
                    )
                )

            # ======================================================
            # 4️⃣ Encryption Check
            # ======================================================
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except ClientError:
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "S3-ENC-001",
                        bucket_name,
                        "HIGH",
                        "Bucket does not have default encryption enabled"
                    )
                )

            # ======================================================
            # 5️⃣ HTTPS Enforcement
            # ======================================================
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_text = policy["Policy"]

                if "aws:SecureTransport" not in policy_text:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "S3-HTTPS-001",
                            bucket_name,
                            "HIGH",
                            "Bucket does not enforce HTTPS access"
                        )
                    )
            except ClientError:
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "S3-HTTPS-002",
                        bucket_name,
                        "HIGH",
                        "Bucket has no HTTPS enforcement policy"
                    )
                )

            # ======================================================
            # 6️⃣ Versioning Check
            # ======================================================
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)

                if versioning.get("Status") != "Enabled":
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "S3-VERSION-001",
                            bucket_name,
                            "HIGH",
                            "Bucket does not have versioning enabled"
                        )
                    )
            except ClientError:
                pass

            # ======================================================
            # 7️⃣ Logging Check
            # ======================================================
            try:
                logging_config = s3.get_bucket_logging(Bucket=bucket_name)

                if "LoggingEnabled" not in logging_config:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "S3-LOG-001",
                            bucket_name,
                            "MEDIUM",
                            "Bucket does not have access logging enabled"
                        )
                    )
            except ClientError:
                pass

    except ClientError as e:
        findings.append(
            create_finding(
                SERVICE_NAME,
                "S3-ERROR-001",
                "ACCOUNT",
                "LOW",
                f"S3 audit failed: {str(e)}"
            )
        )

    return findings