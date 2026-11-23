# Contributing to Shadow313 NEXUS

## Getting Started
```bash
git clone https://github.com/piyyy314/Shadow313-Nexus.git
cd Shadow313-Nexus
python -m pip install -e ".[dev]"
python -m pytest tests/ -q --tb=short
```

## Workflow
1. Fork the repository
2. Create a branch: `git checkout -b feat/your-feature`
3. Add or update focused tests for the behavior you change. Test counts vary by branch and optional dependencies; do not publish a fixed passing-test total.
4. Implement your feature
5. Run: `python -m pytest tests/ -q --tb=short`
6. Commit: `feat: add X module`
7. Open a Pull Request

## Validation

Run Python tests with `python -m pytest tests/ -q --tb=short` and lint with `ruff check .`. For public-site changes, also run `python -m unittest tests.unit.test_site_navigation -v`, `node --test tests/vercel-api.test.cjs tests/site-clocks.test.cjs`, and `python scripts/render-site-nav.py --check`. Check GitHub Actions on the exact commit; skipped optional integrations are not evidence that those integrations work.

## Standards
- Python 3.11+ with type hints
- All new modules need tests/unit/ coverage
- Run `ruff check .` before committing
- No hardcoded credentials

## Security Vulnerabilities
Report privately: pitty313@proton.me — see SECURITY.md

## License
Contributions licensed under MIT.
