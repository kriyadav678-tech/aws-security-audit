# core/config_audit.py

import boto3
from botocore.exceptions import ClientError
from core.models import create_finding

SERVICE_NAME = "AWS_CONFIG"


def run_config_audit():
    findings = []

    try:
        ec2_global = boto3.client("ec2")
        regions = [r["RegionName"] for r in ec2_global.describe_regions()["Regions"]]

        for region in regions:
            config = boto3.client("config", region_name=region)

            # ======================================================
            # 1️⃣ Config Enabled
            # ======================================================
            try:
                recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]

                if not recorders:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CFG-CORE-001",
                            "ACCOUNT",
                            "CRITICAL",
                            "AWS Config not enabled in region",
                            region=region
                        )
                    )
                    continue

                recorder = recorders[0]

            except ClientError:
                continue

            # ======================================================
            # 2️⃣ Recording Status
            # ======================================================
            try:
                status = config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]

                if not status or not status[0]["recording"]:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CFG-CORE-002",
                            "ACCOUNT",
                            "CRITICAL",
                            "Config recorder not actively recording",
                            region=region
                        )
                    )
            except ClientError:
                pass

            # ======================================================
            # 3️⃣ Delivery Channel
            # ======================================================
            try:
                channels = config.describe_delivery_channels()["DeliveryChannels"]

                if not channels:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CFG-CORE-003",
                            "ACCOUNT",
                            "CRITICAL",
                            "No delivery channel configured",
                            region=region
                        )
                    )
                    channel = None
                else:
                    channel = channels[0]

            except ClientError:
                channel = None

            # ======================================================
            # 4️⃣ Recording Group Coverage
            # ======================================================
            group = recorder.get("recordingGroup", {})
            if not group.get("allSupported"):
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "CFG-REC-001",
                        "ACCOUNT",
                        "HIGH",
                        "Config not recording all supported resource types",
                        region=region
                    )
                )

            # ======================================================
            # 5️⃣ Conformance Packs
            # ======================================================
            try:
                packs = config.describe_conformance_packs()["ConformancePackDetails"]

                if not packs:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CFG-COMP-001",
                            "ACCOUNT",
                            "HIGH",
                            "No conformance packs deployed",
                            region=region
                        )
                    )
            except ClientError:
                pass

            # ======================================================
            # 6️⃣ Managed Rules
            # ======================================================
            try:
                rules = config.describe_config_rules()["ConfigRules"]

                if not rules:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CFG-RULE-001",
                            "ACCOUNT",
                            "HIGH",
                            "No AWS Config rules configured",
                            region=region
                        )
                    )
            except ClientError:
                pass

            # ======================================================
            # 7️⃣ Compliance Evaluation
            # ======================================================
            try:
                compliance = config.describe_compliance_by_config_rule()["ComplianceByConfigRules"]

                if not compliance:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CFG-COMP-002",
                            "ACCOUNT",
                            "HIGH",
                            "No compliance evaluations available",
                            region=region
                        )
                    )
            except ClientError:
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "CFG-COMP-003",
                        "ACCOUNT",
                        "MEDIUM",
                        "Could not retrieve compliance evaluation status",
                        region=region
                    )
                )

            # ======================================================
            # 8️⃣ Config Aggregators
            # ======================================================
            try:
                aggregators = config.describe_configuration_aggregators()["ConfigurationAggregators"]

                if not aggregators:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CFG-AGG-001",
                            "ACCOUNT",
                            "MEDIUM",
                            "No Config aggregators configured",
                            region=region
                        )
                    )
            except ClientError:
                pass

            # ======================================================
            # 9️⃣ Delivery Bucket Encryption
            # ======================================================
            if channel and channel.get("s3BucketName"):
                s3 = boto3.client("s3")
                bucket = channel["s3BucketName"]

                try:
                    s3.get_bucket_encryption(Bucket=bucket)
                except ClientError:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CFG-S3-001",
                            bucket,
                            "HIGH",
                            "Config delivery bucket not encrypted",
                            region=region
                        )
                    )

            # ======================================================
            # 🔟 SNS Notification
            # ======================================================
            if channel and not channel.get("snsTopicARN"):
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "CFG-SNS-001",
                        "ACCOUNT",
                        "MEDIUM",
                        "No SNS topic configured for Config notifications",
                        region=region
                    )
                )

            # ======================================================
            # 1️⃣1️⃣ Snapshot Delivery Frequency
            # ======================================================
            if channel:
                frequency = channel.get(
                    "configSnapshotDeliveryProperties", {}
                ).get("deliveryFrequency")

                if not frequency:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CFG-SNAP-001",
                            "ACCOUNT",
                            "MEDIUM",
                            "No snapshot delivery frequency configured",
                            region=region
                        )
                    )
                elif frequency not in ["One_Hour", "Three_Hours"]:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "CFG-SNAP-002",
                            "ACCOUNT",
                            "MEDIUM",
                            f"Snapshot delivery frequency set to {frequency}",
                            region=region
                        )
                    )

        # ======================================================
        # 1️⃣2️⃣ Multi-Region Recording Check
        # ======================================================
        missing_regions = []

        for region in regions:
            regional_config = boto3.client("config", region_name=region)
            recorders = regional_config.describe_configuration_recorders()["ConfigurationRecorders"]

            if not recorders:
                missing_regions.append(region)

        if missing_regions:
            findings.append(
                create_finding(
                    SERVICE_NAME,
                    "CFG-REG-001",
                    "ACCOUNT",
                    "CRITICAL",
                    f"AWS Config not enabled in regions: {', '.join(missing_regions)}"
                )
            )

    except ClientError as e:
        findings.append(
            create_finding(
                SERVICE_NAME,
                "CFG-ERROR-001",
                "ACCOUNT",
                "LOW",
                f"AWS Config audit failed: {str(e)}"
            )
        )

    return findings
