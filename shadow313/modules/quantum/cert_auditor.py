"""shadow313.modules.quantum.cert_auditor — X.509 certificate quantum auditor."""
from __future__ import annotations
import subprocess
from pathlib import Path
from .quantum_data import classify_algorithm


class CertificateAuditor:
    def audit_file(self, cert_path: str) -> dict:
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            with open(cert_path, "rb") as fh:
                data = fh.read()
            cert = x509.load_pem_x509_certificate(data, default_backend())
            return self._analyse_crypto_cert(cert)
        except ImportError:
            return self._openssl_audit(cert_path)
        except Exception as exc:
            return {"error": str(exc), "path": cert_path}

    def _analyse_crypto_cert(self, cert) -> dict:
        pub_key  = cert.public_key()
        key_type = type(pub_key).__name__
        key_size = getattr(pub_key, "key_size", None)
        findings = []
        algo_name = key_type.upper()
        if "RSA" in algo_name:
            info = classify_algorithm("RSA")
            findings.append({"algorithm": f"RSA-{key_size}", "quantum": info["vuln"],
                              "reason": info["reason"], "replace": info["replace"]})
        elif "EC" in algo_name or "ELLIPTIC" in algo_name:
            info = classify_algorithm("ECDSA")
            findings.append({"algorithm": f"ECDSA ({key_size}-bit)", "quantum": info["vuln"],
                              "reason": info["reason"], "replace": info["replace"]})
        try:
            sig_hash = cert.signature_hash_algorithm
            if sig_hash:
                hash_info = classify_algorithm(sig_hash.name.upper())
                if hash_info["vuln"] != "SAFE":
                    findings.append({"algorithm": sig_hash.name, "quantum": hash_info["vuln"],
                                     "reason": hash_info["reason"], "replace": hash_info["replace"]})
        except Exception:
            pass
        return {
            "subject":   cert.subject.rfc4514_string(),
            "issuer":    cert.issuer.rfc4514_string(),
            "not_before": str(cert.not_valid_before_utc),
            "not_after":  str(cert.not_valid_after_utc),
            "key_type":  key_type,
            "key_size":  key_size,
            "findings":  findings,
        }

    def _openssl_audit(self, cert_path: str) -> dict:
        try:
            out = subprocess.check_output(
                ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
                stderr=subprocess.DEVNULL, text=True, timeout=10
            )
            findings = []
            for line in out.splitlines():
                for algo in ["sha1WithRSAEncryption", "md5WithRSAEncryption",
                             "ecdsa-with-SHA256", "rsaEncryption"]:
                    if algo.lower() in line.lower():
                        info = classify_algorithm(algo)
                        findings.append({"algorithm": algo, "quantum": info["vuln"],
                                         "reason": info["reason"], "replace": info["replace"]})
            return {"raw_output": out[:2000], "findings": findings}
        except Exception as exc:
            return {"error": str(exc)}

    def audit_directory(self, dir_path: str) -> list[dict]:
        results = []
        p = Path(dir_path)
        for ext in ("*.pem", "*.crt", "*.cer", "*.der"):
            for cert_file in p.rglob(ext):
                audit = self.audit_file(str(cert_file))
                audit["path"] = str(cert_file)
                results.append(audit)
        return results