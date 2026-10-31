# Contributing to Shadow313 NEXUS

## Getting Started
```bash
git clone https://github.com/piyyy314/Shadow313-Nexus.git
cd Shadow313-Nexus
pip install -e ".[full]"
pytest tests/ -q --ignore=tests/integration
```

## Workflow
1. Fork the repository
2. Create a branch: `git checkout -b feat/your-feature`
3. Write tests first — we maintain 4,107+ tests GREEN
4. Implement your feature
5. Run: `pytest tests/ -q`
6. Commit: `feat: add X module`
7. Open a Pull Request

## Standards
- Python 3.11+ with type hints
- All new modules need tests/unit/ coverage
- Run `ruff check .` before committing
- No hardcoded credentials

## Security Vulnerabilities
Report privately: matarmohamad313@duck.com — see SECURITY.md

## License
Contributions licensed under MIT.
