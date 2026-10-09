"""
Example: AWS Access Key Detector
Demonstrates a minimal SecretDetectorPlugin implementation.
"""
from __future__ import annotations

import re

from shadow313_sdk import (
    FileChunk,
    ScanContext,
    SecretFinding,
    SecretDetectorPlugin,
    Severity,
    TargetType,
)

# AWS Access Key pattern: AKIA / ABIA / ACCA / ASIA followed by 16 uppercase alphanumeric chars
_AWS_KEY_PATTERN = re.compile(rb"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}")

# AWS Secret Key: 40-char base64-like string following common env var names
_AWS_SECRET_PATTERN = re.compile(
    rb"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret_key)\s*[=:]\s*([A-Za-z0-9/+]{40})",
    re.IGNORECASE,
)


class AWSKeyDetector(SecretDetectorPlugin):
    """Detects AWS Access Keys and Secret Keys in file content."""

    plugin_id       = "aws_key_detector_example"
    plugin_version  = "1.0.0"
    supported_types = [TargetType.FILESYSTEM, TargetType.REPO, TargetType.ENV]

    def detect(self, chunk: FileChunk, ctx: ScanContext) -> list[SecretFinding]:
        findings: list[SecretFinding] = []

        # Detect AWS Access Key IDs
        for match in _AWS_KEY_PATTERN.finditer(chunk.content):
            findings.append(ctx.make_finding(
                detector=self.plugin_id,
                secret_type="API_KEY",
                severity=Severity.CRITICAL,
                confidence=0.97,
                file_path=chunk.file_path,
                rule_id="aws_access_key_id",
                matched_value=match.group(0),
                remediation=(
                    "1. Revoke this key immediately via AWS IAM console.\n"
                    "2. Check CloudTrail for unauthorized usage.\n"
                    "3. Rotate all dependent credentials.\n"
                    "4. Store secrets in AWS Secrets Manager or environment injection."
                ),
            ))

        # Detect AWS Secret Access Keys
        for match in _AWS_SECRET_PATTERN.finditer(chunk.content):
            findings.append(ctx.make_finding(
                detector=self.plugin_id,
                secret_type="API_KEY",
                severity=Severity.CRITICAL,
                confidence=0.91,
                file_path=chunk.file_path,
                rule_id="aws_secret_access_key",
                matched_value=match.group(1),
                remediation=(
                    "1. Rotate the associated AWS Access Key immediately.\n"
                    "2. Audit all IAM permissions for the compromised key.\n"
                    "3. Move credentials to a secrets manager."
                ),
            ))

        return findings
