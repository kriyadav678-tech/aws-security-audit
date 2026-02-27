import argparse
import boto3
import json
import sys
from datetime import datetime
from botocore.exceptions import ClientError

# ===== Import Service Audit Modules =====
from core.iam_audit import run_iam_audit
from core.s3_audit import run_s3_audit
from core.ec2_audit import run_ec2_audit
from core.rds_audit import run_rds_audit
from core.cloudtrail_audit import run_cloudtrail_audit
from core.kms_audit import run_kms_audit
from core.vpc_audit import run_vpc_audit
from core.config_audit import run_config_audit

# ===== Severity Weight Mapping =====
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 3,
    "LOW": 1
}

# ===== Calculate Risk & Posture Score =====
def calculate_risk(findings):
    total_risk = 0

    for finding in findings:
        total_risk += SEVERITY_WEIGHTS.get(finding.get("severity"), 0)

    max_possible = len(findings) * 10 if findings else 1
    posture_score = max(0, 100 - int((total_risk / max_possible) * 100))

    return total_risk, posture_score


# ===== Export JSON Report =====
def export_report(account_id, findings, posture_score, risk_score):
    report = {
        "account_id": account_id,
        "timestamp": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "risk_score": risk_score,
        "posture_score": posture_score,
        "findings": findings
    }

    filename = f"cspm_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\nReport exported: {filename}")
    print(f"Posture Score: {posture_score}%")



# ===== Main Execution =====
def main():
    parser = argparse.ArgumentParser(description="AWS Security Audit CLI (CSPM Mode)")
    parser.add_argument(
        "--service",
        type=str,
        help="Specify service to audit (iam, s3, ec2, rds, cloudtrail, kms, vpc, config)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run audit for all services"
    )

    args = parser.parse_args()

    # ===== Validate AWS Identity =====
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        print(f"\nScanning AWS Account: {account_id}\n")

    except ClientError as e:
        print(f"Failed to validate AWS credentials: {e}")
        sys.exit(1)

    all_findings = []

    # ===== Service Execution =====
    if args.service:
        service = args.service.lower()

        if service == "iam":
            all_findings.extend(run_iam_audit())
        elif service == "s3":
            all_findings.extend(run_s3_audit())
        elif service == "ec2":
            all_findings.extend(run_ec2_audit())
        elif service == "rds":
            all_findings.extend(run_rds_audit())
        elif service == "cloudtrail":
            all_findings.extend(run_cloudtrail_audit())
        elif service == "kms":
            all_findings.extend(run_kms_audit())
        elif service == "vpc":
            all_findings.extend(run_vpc_audit())
        elif service == "config":
            all_findings.extend(run_config_audit())
        else:
            print("Invalid service specified.")
            sys.exit(1)

    elif args.all:
        all_findings.extend(run_iam_audit())
        all_findings.extend(run_s3_audit())
        all_findings.extend(run_ec2_audit())
        all_findings.extend(run_rds_audit())
        all_findings.extend(run_cloudtrail_audit())
        all_findings.extend(run_kms_audit())
        all_findings.extend(run_vpc_audit())
        all_findings.extend(run_config_audit())

    else:
        print("Please specify --service <name> or --all")
        sys.exit(1)

    # ===== Risk Calculation =====
    risk_score, posture_score = calculate_risk(all_findings)

    # ===== Export Report =====
    export_report(account_id, all_findings, posture_score, risk_score)

    # ===== Exit Code Logic (CI/CD Ready) =====
    if any(f["severity"] == "CRITICAL" for f in all_findings):
        sys.exit(2)
    elif any(f["severity"] == "HIGH" for f in all_findings):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()