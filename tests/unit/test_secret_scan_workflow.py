"""Ensure fixture exceptions cannot hide new secrets or secrets in other paths."""
import hashlib
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('secret_check', ROOT / 'scripts/check-secrets.py')
SCANNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCANNER)


class SecretScanTests(unittest.TestCase):
    def test_exception_requires_exact_path_and_value(self):
        fixture = 'AK' + 'IA' + 'A' * 16
        other = 'AK' + 'IA' + 'B' * 16
        allowed = {'tests/fixture.py': [hashlib.sha256(fixture.encode()).hexdigest()]}
        self.assertEqual(list(SCANNER.violations('tests/fixture.py', fixture, allowed)), [])
        self.assertTrue(list(SCANNER.violations('app.py', fixture, allowed)))
        self.assertTrue(list(SCANNER.violations('tests/fixture.py', other, allowed)))

    def test_private_key_marker_detected(self):
        marker = '-----BEGIN ' + 'RSA PRIVATE KEY-----'
        self.assertEqual(list(SCANNER.violations('app.py', marker, {})), [1])

    def test_unapproved_github_token_detected(self):
        token = 'gh' + 'p_' + 'Z' * 36
        self.assertEqual(list(SCANNER.violations('tests/new.py', token, {})), [1])
