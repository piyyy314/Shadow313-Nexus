"""Build manifest or check one exact wheel in a fresh, external virtual environment."""

import argparse
import email
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_manifest(directory):
    artifacts = sorted([*directory.glob("*.whl"), *directory.glob("*.tar.gz")])
    if len(list(directory.glob("*.whl"))) != 1 or len(artifacts) != 2:
        raise ValueError("Expected exactly one wheel and one source archive in fresh output")
    manifest = {path.name: digest(path) for path in artifacts}
    (directory / "SHA256SUMS.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def validate_artifacts(directory):
    manifest = json.loads((directory / "SHA256SUMS.json").read_text(encoding="utf-8"))
    wheels = list(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("Expected exactly one wheel")
    actual = {p.name for p in directory.iterdir() if p.is_file()} - {"SHA256SUMS.json"}
    if set(manifest) != actual:
        raise ValueError("Artifact list differs from build manifest")
    for name, expected in manifest.items():
        if Path(name).name != name or digest(directory / name) != expected:
            raise ValueError(f"Artifact hash/path mismatch: {name}")
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        names = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError("Expected one distribution metadata record")
        metadata = email.message_from_bytes(archive.read(names[0]))
        if metadata["Name"] != "shadow313-nexus":
            raise ValueError("Wrong distribution identity")
    return wheel, metadata["Version"]


def check(directory, profile):
    wheel, version = validate_artifacts(directory)
    # No inherited project path or global packages; each run gets a unique directory.
    with tempfile.TemporaryDirectory(prefix="shadow313-wheel-ci-") as temp:
        root = Path(temp)
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env["PYTHONUTF8"] = "1"
        env["PYTHONNOUSERSITE"] = "1"
        extras = {"core": "", "api": "[dashboard]", "pqc": "[pqc]"}[profile]
        command = [str(python), "-m", "pip", "install", f"{wheel.resolve()}{extras}"]
        if profile == "api":
            command.append("httpx>=0.27")
        subprocess.run(command, cwd=root, env=env, check=True, timeout=600)
        subprocess.run(
            [str(python), "-m", "pip", "check"], cwd=root, env=env, check=True, timeout=60
        )
        smoke = root / "wheel_smoke.py"
        shutil.copyfile(
            Path(__file__).resolve().parents[1] / "tests/packaging/wheel_smoke.py", smoke
        )
        env["WHEEL_PROFILE"] = profile
        env["WHEEL_VERSION"] = version
        subprocess.run([str(python), str(smoke)], cwd=root, env=env, check=True, timeout=180)
        print(
            json.dumps(
                {
                    "profile": profile,
                    "wheel": wheel.name,
                    "sha256": digest(wheel),
                    "python": sys.version,
                    "platform": sys.platform,
                    "architecture": platform.machine(),
                    "os": platform.platform(),
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--profile", choices=["core", "api", "pqc"], default="core")
    args = parser.parse_args()
    if args.write_manifest:
        write_manifest(args.directory)
    else:
        check(args.directory, args.profile)
