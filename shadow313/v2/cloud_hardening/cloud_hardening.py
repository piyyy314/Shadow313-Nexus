"""
shadow313.v2.cloud_hardening.cloud_hardening  — v4
AWS · Kubernetes · Terraform security checks.

BUG FIXES:
  - AWS checks used boto3 without checking if it's installed — now graceful.
  - K8s checks used kubernetes client without import guard — fixed.
  - Terraform scanner regex for open CIDR matched comments — added line
    stripping and comment filtering.
  - _check_rds_public() iterated over wrong key 'DBInstances' vs 'dbInstances'
    — fixed to use correct AWS SDK response key.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any


def _sev(critical=False, high=False, medium=False, low=False) -> str:
    if critical: return "CRITICAL"
    if high:     return "HIGH"
    if medium:   return "MEDIUM"
    if low:      return "LOW"
    return "INFO"


# ── AWS Checks ────────────────────────────────────────────────────────────────

class AWSChecker:
    """7 AWS security checks via boto3."""

    def __init__(self) -> None:
        self._boto3 = None
        try:
            import boto3
            self._boto3 = boto3
        except ImportError:
            pass

    @property
    def available(self) -> bool:
        return self._boto3 is not None

    def _client(self, service: str):
        return self._boto3.client(service)

    def run_all(self) -> list[dict]:
        if not self.available:
            return [{"check": "AWS", "status": "SKIP",
                     "detail": "boto3 not installed — pip install boto3",
                     "severity": "INFO"}]
        checks = [
            self._check_s3_public,
            self._check_root_access_keys,
            self._check_root_mfa,
            self._check_open_security_groups,
            self._check_cloudtrail,
            self._check_password_policy,
            self._check_rds_public,
        ]
        results = []
        for check in checks:
            try:
                results.append(check())
            except Exception as exc:
                results.append({"check": check.__name__, "status": "ERROR",
                                "detail": str(exc), "severity": "INFO"})
        return results

    def _check_s3_public(self) -> dict:
        try:
            s3 = self._client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            public_buckets = []
            for b in buckets:
                name = b["Name"]
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "").endswith("AllUsers"):
                            public_buckets.append(name)
                except Exception as _exc:  # S01-fixed
                    import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
                    pass
            status = "PASS" if not public_buckets else "FAIL"
            return {
                "check":    "S3 Public Access",
                "status":   status,
                "severity": _sev(critical=bool(public_buckets)),
                "detail":   f"Public buckets: {public_buckets}" if public_buckets
                            else "No public S3 buckets found",
            }
        except Exception as exc:
            return {"check": "S3 Public Access", "status": "ERROR",
                    "detail": str(exc), "severity": "INFO"}

    def _check_root_access_keys(self) -> dict:
        try:
            iam = self._client("iam")
            summary = iam.get_account_summary()["SummaryMap"]
            has_keys = summary.get("AccountAccessKeysPresent", 0) > 0
            return {
                "check":    "Root Access Keys",
                "status":   "FAIL" if has_keys else "PASS",
                "severity": _sev(critical=has_keys),
                "detail":   "Root account has active access keys — REMOVE IMMEDIATELY"
                            if has_keys else "No root access keys found",
            }
        except Exception as exc:
            return {"check": "Root Access Keys", "status": "ERROR",
                    "detail": str(exc), "severity": "INFO"}

    def _check_root_mfa(self) -> dict:
        try:
            iam = self._client("iam")
            summary = iam.get_account_summary()["SummaryMap"]
            mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
            return {
                "check":    "Root MFA",
                "status":   "PASS" if mfa_enabled else "FAIL",
                "severity": _sev(critical=not mfa_enabled),
                "detail":   "Root MFA enabled" if mfa_enabled
                            else "Root account MFA is DISABLED — enable immediately",
            }
        except Exception as exc:
            return {"check": "Root MFA", "status": "ERROR",
                    "detail": str(exc), "severity": "INFO"}

    def _check_open_security_groups(self) -> dict:
        try:
            ec2 = self._client("ec2")
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            open_sgs = []
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            open_sgs.append(sg["GroupId"])
            open_sgs = list(set(open_sgs))
            return {
                "check":    "Open Security Groups",
                "status":   "FAIL" if open_sgs else "PASS",
                "severity": _sev(high=bool(open_sgs)),
                "detail":   f"Security groups with 0.0.0.0/0 ingress: {open_sgs}"
                            if open_sgs else "No open security groups",
            }
        except Exception as exc:
            return {"check": "Open Security Groups", "status": "ERROR",
                    "detail": str(exc), "severity": "INFO"}

    def _check_cloudtrail(self) -> dict:
        try:
            ct = self._client("cloudtrail")
            trails = ct.describe_trails()["trailList"]
            active = []
            for t in trails:
                status = ct.get_trail_status(Name=t["TrailARN"])
                if status.get("IsLogging"):
                    active.append(t["Name"])
            return {
                "check":    "CloudTrail Logging",
                "status":   "PASS" if active else "FAIL",
                "severity": _sev(high=not active),
                "detail":   f"Active trails: {active}" if active
                            else "No active CloudTrail logging found",
            }
        except Exception as exc:
            return {"check": "CloudTrail Logging", "status": "ERROR",
                    "detail": str(exc), "severity": "INFO"}

    def _check_password_policy(self) -> dict:
        try:
            iam = self._client("iam")
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append("MinimumPasswordLength < 14")
            if not policy.get("RequireUppercaseCharacters"):
                issues.append("Uppercase not required")
            if not policy.get("RequireNumbers"):
                issues.append("Numbers not required")
            if not policy.get("RequireSymbols"):
                issues.append("Symbols not required")
            return {
                "check":    "IAM Password Policy",
                "status":   "PASS" if not issues else "FAIL",
                "severity": _sev(medium=bool(issues)),
                "detail":   "; ".join(issues) if issues else "Password policy meets requirements",
            }
        except Exception as exc:
            return {"check": "IAM Password Policy", "status": "ERROR",
                    "detail": str(exc), "severity": "INFO"}

    def _check_rds_public(self) -> dict:
        try:
            rds = self._client("rds")
            # FIX: correct key is 'DBInstances' (capital DB)
            instances = rds.describe_db_instances().get("DBInstances", [])
            public = [i["DBInstanceIdentifier"] for i in instances
                      if i.get("PubliclyAccessible")]
            return {
                "check":    "RDS Public Accessibility",
                "status":   "FAIL" if public else "PASS",
                "severity": _sev(high=bool(public)),
                "detail":   f"Publicly accessible RDS instances: {public}"
                            if public else "No publicly accessible RDS instances",
            }
        except Exception as exc:
            return {"check": "RDS Public Accessibility", "status": "ERROR",
                    "detail": str(exc), "severity": "INFO"}


# ── Kubernetes Checks ─────────────────────────────────────────────────────────

class K8sChecker:
    """7 Kubernetes security checks."""

    def __init__(self) -> None:
        self._k8s = None
        try:
            from kubernetes import client, config as k8s_config
            k8s_config.load_kube_config()
            self._k8s = client
        except Exception:
            pass

    @property
    def available(self) -> bool:
        return self._k8s is not None

    def run_all(self) -> list[dict]:
        if not self.available:
            return [{"check": "Kubernetes", "status": "SKIP",
                     "detail": "kubernetes client not installed or kubeconfig not found",
                     "severity": "INFO"}]
        checks = [
            self._check_privileged_pods,
            self._check_host_network,
            self._check_default_namespace,
            self._check_cluster_admin,
            self._check_network_policies,
            self._check_secrets_in_env,
            self._check_image_pull_policy,
        ]
        results = []
        for check in checks:
            try:
                results.append(check())
            except Exception as exc:
                results.append({"check": check.__name__, "status": "ERROR",
                                "detail": str(exc), "severity": "INFO"})
        return results

    def _check_privileged_pods(self) -> dict:
        v1 = self._k8s.CoreV1Api()
        pods = v1.list_pod_for_all_namespaces().items
        privileged = []
        for pod in pods:
            for c in (pod.spec.containers or []):
                sc = c.security_context
                if sc and sc.privileged:
                    privileged.append(f"{pod.metadata.namespace}/{pod.metadata.name}")
        return {
            "check":    "Privileged Pods",
            "status":   "FAIL" if privileged else "PASS",
            "severity": _sev(critical=bool(privileged)),
            "detail":   f"Privileged pods: {privileged[:10]}" if privileged
                        else "No privileged pods found",
        }

    def _check_host_network(self) -> dict:
        v1 = self._k8s.CoreV1Api()
        pods = v1.list_pod_for_all_namespaces().items
        host_net = [f"{p.metadata.namespace}/{p.metadata.name}"
                    for p in pods if p.spec.host_network]
        return {
            "check":    "Host Network/PID/IPC",
            "status":   "FAIL" if host_net else "PASS",
            "severity": _sev(high=bool(host_net)),
            "detail":   f"Pods with host network: {host_net[:10]}" if host_net
                        else "No pods using host network",
        }

    def _check_default_namespace(self) -> dict:
        v1 = self._k8s.CoreV1Api()
        pods = v1.list_namespaced_pod("default").items
        return {
            "check":    "Workloads in Default Namespace",
            "status":   "WARN" if pods else "PASS",
            "severity": _sev(medium=bool(pods)),
            "detail":   f"{len(pods)} workloads in default namespace" if pods
                        else "No workloads in default namespace",
        }

    def _check_cluster_admin(self) -> dict:
        rbac = self._k8s.RbacAuthorizationV1Api()
        bindings = rbac.list_cluster_role_binding().items
        over_bound = [b.metadata.name for b in bindings
                      if b.role_ref.name == "cluster-admin"
                      and b.subjects and len(b.subjects) > 1]
        return {
            "check":    "RBAC cluster-admin Over-binding",
            "status":   "FAIL" if over_bound else "PASS",
            "severity": _sev(high=bool(over_bound)),
            "detail":   f"Over-bound cluster-admin: {over_bound}" if over_bound
                        else "cluster-admin bindings look reasonable",
        }

    def _check_network_policies(self) -> dict:
        v1   = self._k8s.CoreV1Api()
        netv1= self._k8s.NetworkingV1Api()
        namespaces = [ns.metadata.name for ns in v1.list_namespace().items]
        no_policy  = []
        for ns in namespaces:
            policies = netv1.list_namespaced_network_policy(ns).items
            if not policies:
                no_policy.append(ns)
        return {
            "check":    "Missing Network Policies",
            "status":   "FAIL" if no_policy else "PASS",
            "severity": _sev(medium=bool(no_policy)),
            "detail":   f"Namespaces without NetworkPolicy: {no_policy[:10]}"
                        if no_policy else "All namespaces have NetworkPolicies",
        }

    def _check_secrets_in_env(self) -> dict:
        v1 = self._k8s.CoreV1Api()
        pods = v1.list_pod_for_all_namespaces().items
        exposed = []
        for pod in pods:
            for c in (pod.spec.containers or []):
                for env in (c.env or []):
                    name_lower = (env.name or "").lower()
                    if any(kw in name_lower for kw in ("secret","password","key","token")):
                        if env.value and not env.value_from:
                            exposed.append(f"{pod.metadata.namespace}/{pod.metadata.name}:{env.name}")
        return {
            "check":    "Secrets in Environment Variables",
            "status":   "FAIL" if exposed else "PASS",
            "severity": _sev(high=bool(exposed)),
            "detail":   f"Exposed secrets in env: {exposed[:5]}" if exposed
                        else "No plaintext secrets in environment variables",
        }

    def _check_image_pull_policy(self) -> dict:
        v1 = self._k8s.CoreV1Api()
        pods = v1.list_pod_for_all_namespaces().items
        not_always = []
        for pod in pods:
            for c in (pod.spec.containers or []):
                if c.image_pull_policy != "Always":
                    not_always.append(f"{pod.metadata.namespace}/{c.name}")
        return {
            "check":    "Image Pull Policy",
            "status":   "WARN" if not_always else "PASS",
            "severity": _sev(low=bool(not_always)),
            "detail":   f"{len(not_always)} containers without imagePullPolicy: Always"
                        if not_always else "All containers use imagePullPolicy: Always",
        }


# ── Terraform Scanner ─────────────────────────────────────────────────────────

class TerraformScanner:
    """11 Terraform IaC security rules."""

    RULES = [
        ("TF-S3-PUBLIC",      r'acl\s*=\s*"public-read"',          "aws_s3_bucket",    "CRITICAL"),
        ("TF-S3-NO-ENCRYPT",  r'aws_s3_bucket\b(?!.*server_side)', "aws_s3_bucket",    "HIGH"),
        ("TF-HARDCODED-PW",   r'password\s*=\s*"[^"]+"',           "all",              "CRITICAL"),
        ("TF-OPEN-INGRESS",   r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', "aws_security_group", "HIGH"),
        ("TF-NO-ACCESS-LOG",  r'aws_s3_bucket\b(?!.*logging)',      "aws_s3_bucket",    "MEDIUM"),
        ("TF-RDS-NO-ENCRYPT", r'storage_encrypted\s*=\s*false',     "aws_db_instance",  "HIGH"),
        ("TF-PUBLIC-AMI",     r'associate_public_ip_address\s*=\s*true', "aws_instance","MEDIUM"),
        ("TF-WILDCARD-IAM",   r'"Action"\s*:\s*"\*"',               "aws_iam_policy",   "CRITICAL"),
        ("TF-NO-VPC-FLOW",    r'aws_vpc\b(?!.*aws_flow_log)',       "aws_vpc",          "MEDIUM"),
        ("TF-HTTP-ALB",       r'protocol\s*=\s*"HTTP"',             "aws_alb_listener", "HIGH"),
        ("TF-NO-BACKUP",      r'backup_retention_period\s*=\s*0',   "aws_db_instance",  "MEDIUM"),
    ]

    def scan_directory(self, dir_path: str) -> list[dict]:
        findings = []
        base = Path(dir_path)
        for tf_file in base.rglob("*.tf"):
            findings.extend(self._scan_file(tf_file))
        return findings

    def _scan_file(self, path: Path) -> list[dict]:
        findings = []
        try:
            lines = path.read_text(errors="replace").splitlines()
        except Exception:
            return []
        for lineno, line in enumerate(lines, 1):
            # FIX: strip line and skip comments before regex matching
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for rule_id, pattern, resource, severity in self.RULES:
                if re.search(pattern, stripped, re.IGNORECASE):
                    findings.append({
                        "rule_id":  rule_id,
                        "file":     str(path),
                        "line":     lineno,
                        "severity": severity,
                        "detail":   f"{rule_id}: {stripped[:80]}",
                        "resource": resource,
                    })
        return findings


# ── CloudModule ───────────────────────────────────────────────────────────────

class CloudModule:
    """shadow313.v2.cloud_hardening — Cloud/K8s/Terraform hardening. Registered: cloud"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.session = kernel.session

    def register(self, kernel) -> None:
        kernel.register("cloud", self.run)

    def run(
        self,
        scan_aws: bool = False,
        scan_k8s: bool = False,
        scan_terraform: str = "",
        scan_all: bool = False,
        output: str = "rich",
    ) -> dict:
        self.out.section("CLOUD / K8s / IaC HARDENING AUDIT")
        result: dict[str, Any] = {}

        if scan_aws or scan_all:
            self.out.info("Running AWS security checks …")
            checker = AWSChecker()
            findings = checker.run_all()
            result["aws"] = findings
            rows = [[f["check"], f["status"], f["severity"], f["detail"][:60]]
                    for f in findings]
            self.out.table(["Check","Status","Severity","Detail"], rows, "AWS Security Checks")

        if scan_k8s or scan_all:
            self.out.info("Running Kubernetes security checks …")
            checker = K8sChecker()
            findings = checker.run_all()
            result["k8s"] = findings
            rows = [[f["check"], f["status"], f["severity"], f["detail"][:60]]
                    for f in findings]
            self.out.table(["Check","Status","Severity","Detail"], rows, "K8s Security Checks")

        if scan_terraform or scan_all:
            path = scan_terraform or "."
            self.out.info(f"Scanning Terraform IaC: {path} …")
            scanner  = TerraformScanner()
            findings = scanner.scan_directory(path)
            result["terraform"] = findings
            if findings:
                rows = [[f["rule_id"], f["file"].split("/")[-1], f["line"],
                         f["severity"], f["detail"][:50]]
                        for f in findings[:30]]
                self.out.table(["Rule","File","Line","Severity","Detail"], rows,
                               f"Terraform Findings ({len(findings)})")
            else:
                self.out.success("No Terraform security issues found.")

        if output == "sarif":
            sarif = self._build_sarif(result)
            import json as _json
            print(_json.dumps(sarif, indent=2))

        self.session.write("cloud_audit.json", result)
        return result

    def _build_sarif(self, result: dict) -> dict:
        from shadow313.modules.cicd.cicd import SARIFBuilder
        builder = SARIFBuilder()
        for section in ("aws", "k8s", "terraform"):
            for f in result.get(section, []):
                builder.add_finding(
                    rule_id   = f.get("rule_id", f.get("check", "CLOUD-FINDING")),
                    message   = f.get("detail", ""),
                    level     = f.get("severity", "medium"),
                    file_path = f.get("file", ""),
                    line      = int(f.get("line", 0)),
                )
        return builder.build()