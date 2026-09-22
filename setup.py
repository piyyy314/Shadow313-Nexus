"""
Shadow313 v1 — setup.py
"""
from setuptools import setup, find_packages
from pathlib import Path

long_description = Path("README.md").read_text(encoding="utf-8") if Path("README.md").exists() else ""

setup(
    name             = "shadow313",
    version          = "1.0.0",
    author           = "Shadow313 Core Team",
    description      = "Local-First AI-Powered Security Intelligence CLI",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url              = "https://github.com/piyyy314/Shadow313-Nexus",
    license          = "MIT",
    packages         = find_packages(),
    python_requires  = ">=3.11",
    install_requires = [
        "pyyaml>=6.0",
        "rich>=13.0",
    ],
    extras_require = {
        "full": [
            "dnspython>=2.4",
            "python-whois>=0.8",
            "cryptography>=41.0",
            "scapy>=2.5",
        ],
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio>=0.23",
            "black>=24.0",
            "ruff>=0.4",
            "mypy>=1.10",
        ],
    },
    entry_points = {
        "console_scripts": [
            "shadow313 = shadow313.cli.main:main",
        ],
    },
    classifiers = [
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    package_data = {
        "shadow313": ["data/wordlists/*.txt", "data/signatures/*.json"],
    },
)