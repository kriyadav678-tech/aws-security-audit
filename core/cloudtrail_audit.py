# core/cloudtrail_audit.py

import boto3
from botocore.exceptions import ClientError
from core.models import create_finding

SERVICE_NAME = "CLOUDTRAIL"


def run_cloudtrail_audit():
    findings = []

    try:
        ec2_global = boto3.client("ec2")
        regions = [r["RegionName"] for r in ec2_global.describe_regions()["Regions"]]

        for region in regions:
            cloudtrail = boto3.client("cloudtrail", region_name=region)
            s3 = boto3.client("s3")

            try:
                trails = cloudtrail.describe_trails(includeShadowTrails=False)["trailList"]
            except ClientError:
                continue

            # ======================================================
            # No Trail Found
            # ======================================================
            if not trails:
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "CT-CORE-001",
                        "ACCOUNT",
                        "CRITICAL",
                        "No CloudTrail trails found in region",
                        region=region
                    )
                )
                continue

            for trail in trails:
                trail_name = trail["Name"]

                # ======================================================
                # 1️⃣ Logging Enabled
                # ======================================================
                try:
                    status = cloudtrail.get_trail_status(Name=trail_name)
                    if not status.get("IsLogging"):
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "CT-CORE-002",
                                trail_name,
                                "CRITICAL",
                                "CloudTrail logging not enabled",
                                region=region
                            )
                        )
                except ClientError:
                    pass

                # ======================================================
                # 2️⃣ Multi-Region Trail
                # ======================================================
                if not trail.get("IsMultiRegionTrail"):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CT-CONFIG-001",
                            trail_name,
                            "HIGH",
                            "Trail not configured as multi-region",
                            region=region
                        )
                    )

                # ======================================================
                # 3️⃣ Log File Validation
                # ======================================================
                if not trail.get("LogFileValidationEnabled"):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CT-INTEG-001",
                            trail_name,
                            "HIGH",
                            "Log file validation not enabled",
                            region=region
                        )
                    )

                # ======================================================
                # 4️⃣ Global Service Events
                # ======================================================
                if not trail.get("IncludeGlobalServiceEvents"):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CT-CONFIG-002",
                            trail_name,
                            "MEDIUM",
                            "Global service events not logged",
                            region=region
                        )
                    )

                # ======================================================
                # 5️⃣ Management Events
                # ======================================================
                try:
                    selectors = cloudtrail.get_event_selectors(TrailName=trail_name)
                    has_management = False

                    for selector in selectors.get("EventSelectors", []):
                        if selector.get("IncludeManagementEvents"):
                            has_management = True

                    if not has_management:
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "CT-EVT-001",
                                trail_name,
                                "HIGH",
                                "Management events not logged",
                                region=region
                            )
                        )
                except ClientError:
                    pass

                # ======================================================
                # 6️⃣ Data Events
                # ======================================================
                try:
                    selectors = cloudtrail.get_event_selectors(TrailName=trail_name)
                    has_data = False

                    for selector in selectors.get("EventSelectors", []):
                        if selector.get("DataResources"):
                            has_data = True

                    if not has_data:
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "CT-EVT-002",
                                trail_name,
                                "LOW",
                                "Data events not logged",
                                region=region
                            )
                        )
                except ClientError:
                    pass

                # ======================================================
                # 7️⃣ S3 Bucket Encryption
                # ======================================================
                bucket_name = trail.get("S3BucketName")

                if bucket_name:
                    try:
                        s3.get_bucket_encryption(Bucket=bucket_name)
                    except ClientError:
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "CT-S3-001",
                                bucket_name,
                                "HIGH",
                                "CloudTrail S3 bucket not encrypted",
                                region=region
                            )
                        )

                # ======================================================
                # 8️⃣ CloudWatch Logs Integration
                # ======================================================
                if not trail.get("CloudWatchLogsLogGroupArn"):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CT-LOG-001",
                            trail_name,
                            "MEDIUM",
                            "CloudTrail not integrated with CloudWatch Logs",
                            region=region
                        )
                    )

    except ClientError as e:
        findings.append(
            create_finding(
                SERVICE_NAME,
                "CT-ERROR-001",
                "ACCOUNT",
                "LOW",
                f"CloudTrail audit failed: {str(e)}"
            )
        )

    return findings
