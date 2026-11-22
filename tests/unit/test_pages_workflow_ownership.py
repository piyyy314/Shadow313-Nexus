from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_public_site_validation_does_not_publish_to_github_pages():
    workflow = (ROOT / ".github/workflows/github-pages.yml").read_text(encoding="utf-8")
    assert "Public Site Build Validation" in workflow
    assert "node scripts/build-public-site.cjs" in workflow
    assert "tests/public-site-boundary.test.cjs" in workflow
    assert "actions/deploy-pages" not in workflow
    assert "upload-pages-artifact" not in workflow
    assert "pages: write" not in workflow
    assert "id-token: write" not in workflow


def test_delivery_pipeline_is_the_single_github_pages_publisher():
    workflow = (ROOT / ".github/workflows/deliver.yml").read_text(encoding="utf-8")
    assert "actions/upload-pages-artifact@v5" in workflow
    assert "actions/deploy-pages@v5" in workflow
