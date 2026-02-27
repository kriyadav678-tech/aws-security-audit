# core/iam_audit.py

import boto3
import time
import csv
import io
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
from core.models import create_finding

SERVICE_NAME = "IAM"


def run_iam_audit():
    findings = []
    iam = boto3.client("iam")

    try:
        users = iam.list_users()["Users"]

        # ======================================================
        # 1️⃣ MFA CHECK
        # ======================================================
        for user in users:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

            if not mfa_devices:
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "IAM-MFA-001",
                        username,
                        "HIGH",
                        "IAM user without MFA enabled"
                    )
                )

        # ======================================================
        # 2️⃣ OLD ACCESS KEY CHECK
        # ======================================================
        for user in users:
            username = user["UserName"]
            access_keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

            for key in access_keys:
                key_age = (datetime.now(timezone.utc) - key["CreateDate"]).days

                if key_age > 90:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "IAM-KEY-001",
                            f"{username}:{key['AccessKeyId']}",
                            "MEDIUM",
                            f"Access key older than 90 days ({key_age} days)"
                        )
                    )

        # ======================================================
        # 3️⃣ UNUSED ACCESS KEYS
        # ======================================================
        for user in users:
            username = user["UserName"]
            access_keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

            for key in access_keys:
                last_used = iam.get_access_key_last_used(
                    AccessKeyId=key["AccessKeyId"]
                )["AccessKeyLastUsed"]

                if "LastUsedDate" not in last_used:
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "IAM-KEY-002",
                            f"{username}:{key['AccessKeyId']}",
                            "HIGH",
                            "Access key has NEVER been used"
                        )
                    )
                else:
                    days_unused = (
                        datetime.now(timezone.utc) - last_used["LastUsedDate"]
                    ).days

                    if days_unused > 90:
                        findings.append(
                            create_finding(
                                SERVICE_NAME,
                                "IAM-KEY-003",
                                f"{username}:{key['AccessKeyId']}",
                                "MEDIUM",
                                f"Access key unused for {days_unused} days"
                            )
                        )

        # ======================================================
        # 4️⃣ ADMIN USERS
        # ======================================================
        for user in users:
            username = user["UserName"]
            attached = iam.list_attached_user_policies(
                UserName=username
            )["AttachedPolicies"]

            for policy in attached:
                if policy["PolicyName"] == "AdministratorAccess":
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "IAM-PRIV-001",
                            username,
                            "HIGH",
                            "User has AdministratorAccess policy"
                        )
                    )

        # ======================================================
        # 5️⃣ ROOT ACCOUNT SECURITY
        # ======================================================
        iam.generate_credential_report()
        time.sleep(2)

        report = iam.get_credential_report()
        content = report["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))

        for row in reader:
            if row["user"] == "<root_account>":

                if row["mfa_active"] != "true":
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "IAM-ROOT-001",
                            "ROOT_ACCOUNT",
                            "CRITICAL",
                            "Root account does NOT have MFA enabled"
                        )
                    )

                if (
                    row["access_key_1_active"] == "true"
                    or row["access_key_2_active"] == "true"
                ):
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "IAM-ROOT-002",
                            "ROOT_ACCOUNT",
                            "CRITICAL",
                            "Root account has active access keys"
                        )
                    )

                break

        # ======================================================
        # 6️⃣ INACTIVE USERS
        # ======================================================
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)

        for user in users:
            username = user["UserName"]
            inactive = True

            if "PasswordLastUsed" in user and user["PasswordLastUsed"]:
                if user["PasswordLastUsed"] > cutoff:
                    inactive = False

            access_keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

            for key in access_keys:
                last_used = iam.get_access_key_last_used(
                    AccessKeyId=key["AccessKeyId"]
                )["AccessKeyLastUsed"]

                if "LastUsedDate" in last_used:
                    if last_used["LastUsedDate"] > cutoff:
                        inactive = False

            if inactive:
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "IAM-USER-001",
                        username,
                        "MEDIUM",
                        "IAM user inactive for more than 90 days"
                    )
                )

        # ======================================================
        # 7️⃣ ADMIN ROLES
        # ======================================================
        roles = iam.list_roles()["Roles"]

        for role in roles:
            role_name = role["RoleName"]

            attached = iam.list_attached_role_policies(
                RoleName=role_name
            )["AttachedPolicies"]

            for policy in attached:
                if policy["PolicyName"] == "AdministratorAccess":
                    findings.append(
                        create_finding(
                            SERVICE_NAME,
                            "IAM-ROLE-001",
                            role_name,
                            "HIGH",
                            "IAM Role has AdministratorAccess policy"
                        )
                    )

        # ======================================================
        # 8️⃣ PASSWORD POLICY
        # ======================================================
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]

            if policy.get("MinimumPasswordLength", 0) < 8:
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "IAM-PASS-001",
                        "ACCOUNT",
                        "MEDIUM",
                        "Password minimum length is weak (<8)"
                    )
                )

            if not policy.get("RequireSymbols"):
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "IAM-PASS-002",
                        "ACCOUNT",
                        "MEDIUM",
                        "Password policy does NOT require symbols"
                    )
                )

            if not policy.get("ExpirePasswords"):
                findings.append(
                    create_finding(
                        SERVICE_NAME,
                        "IAM-PASS-003",
                        "ACCOUNT",
                        "LOW",
                        "Passwords do NOT expire"
                    )
                )

        except iam.exceptions.NoSuchEntityException:
            findings.append(
                create_finding(
                    SERVICE_NAME,
                    "IAM-PASS-004",
                    "ACCOUNT",
                    "HIGH",
                    "No password policy configured"
                )
            )

    except ClientError as e:
        findings.append(
            create_finding(
                SERVICE_NAME,
                "IAM-ERROR-001",
                "ACCOUNT",
                "LOW",
                f"IAM audit error: {str(e)}"
            )
        )

    return findings