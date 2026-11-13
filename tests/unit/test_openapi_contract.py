"""The checked-in OpenAPI contract matches the Python API routes."""
import json
import subprocess
from pathlib import Path

import yaml

from shadow313.api.server import create_app

ROOT = Path(__file__).resolve().parents[2]


def test_openapi_paths_match_api_routes():
    with open("api/openapi.yaml", encoding="utf-8") as contract_file:
        contract = yaml.safe_load(contract_file)

    app = create_app(api_key="test-key")
    internal_routes = {"/api/docs", "/api/redoc", "/api/openapi.json"}
    implementation_paths = set(app.openapi()["paths"]) - internal_routes
    contract_paths = set(contract["paths"])

    assert implementation_paths == contract_paths


def test_unavailable_integrations_document_200_without_503():
    with open("api/openapi.yaml", encoding="utf-8") as contract_file:
        contract = yaml.safe_load(contract_file)

    paths = (
        "/api/scan/recon",
        "/api/scan/vuln",
        "/api/mobile/scan",
        "/api/mobile/status",
        "/api/mobile/alerts",
        "/api/mobile/findings",
        "/api/mobile/sessions",
        "/api/events",
    )
    for path in paths:
        operations = contract["paths"][path]
        for operation in operations.values():
            assert "200" in operation["responses"]
            assert "503" not in operation["responses"]


def test_static_api_adapter_returns_200_with_unavailable_status():
    cases = [
        ("POST", "/api/scan/recon"),
        ("POST", "/api/scan/vuln"),
        ("POST", "/api/mobile/scan"),
        ("GET", "/api/mobile/status"),
        ("GET", "/api/mobile/alerts"),
        ("GET", "/api/mobile/findings"),
        ("GET", "/api/mobile/sessions"),
        ("GET", "/api/events"),
    ]
    script = """
const handler = require('./api/index.js');
const cases = JSON.parse(process.argv[1]);
const results = cases.map(([method, url]) => {
  const res = {
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    end(body) { this.body = body; },
  };
  handler({ method, url }, res);
  return { statusCode: res.statusCode, body: JSON.parse(res.body) };
});
console.log(JSON.stringify(results));
"""
    result = subprocess.run(
        ["node", "-e", script, json.dumps(cases)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    responses = json.loads(result.stdout)
    assert len(responses) == len(cases)
    assert all(response["statusCode"] == 200 for response in responses)
    assert all(response["body"]["status"] == "unavailable" for response in responses)



def test_static_openapi_contract_is_published_without_api_rewrite():
    source = (ROOT / "api/openapi.yaml").read_text(encoding="utf-8")
    published = (ROOT / "docs/openapi.yaml").read_text(encoding="utf-8")
    public_files = json.loads(
        (ROOT / "site/public-files.json").read_text(encoding="utf-8")
    )
    build_script = (ROOT / "scripts/build-public-site.cjs").read_text(encoding="utf-8")

    assert published == source
    assert "docs/openapi.yaml" in public_files
    assert "yaml|yml" in build_script
    api_page = (ROOT / "docs/api.html").read_text(encoding="utf-8")
    assert 'href="/docs/openapi.yaml"' in api_page


def test_openapi_auth_and_request_schemas_match_api_behavior():
    contract = yaml.safe_load((ROOT / "api/openapi.yaml").read_text(encoding="utf-8"))

    assert contract["security"] == [{"ApiKeyAuth": []}]
    assert contract["paths"]["/api/status"]["get"]["security"] == []
    assert contract["paths"]["/health"]["get"]["security"] == []

    detect = contract["paths"]["/api/detect"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert detect["required"] == ["event"]
    assert set(detect["properties"]) == {"event", "detectors"}

    webshell = contract["paths"]["/api/webshell/scan"]["post"]["requestBody"][
        "content"
    ]["application/json"]["schema"]
    assert webshell["required"] == ["content"]
    assert {"content", "file_path", "mode"} == set(webshell["properties"])

    bind = contract["paths"]["/api/bind/create"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert bind["required"] == ["payload"]

    chat = contract["paths"]["/api/chat"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert chat["properties"]["system_prompt"]["type"] == ["string", "null"]
    assert chat["properties"]["context"]["type"] == ["object", "null"]

    for path in ("/api/scan/recon", "/api/scan/vuln"):
        operation = contract["paths"][path]["post"]
        assert "requestBody" not in operation
        assert "No remote scan worker is connected" in operation["description"]

    assert contract["paths"]["/api/bind/{bind_id}"]["get"].get("security") is None
    assert contract["paths"]["/api/attck/coverage"]["get"].get("security") is None


def test_openapi_documents_soc_alert_cursor_parameters():
    contract = yaml.safe_load((ROOT / "api/openapi.yaml").read_text(encoding="utf-8"))
    parameters = contract["paths"]["/api/shiatoali/alerts"]["get"]["parameters"]

    assert {parameter["name"] for parameter in parameters} == {
        "limit", "offset", "since", "order"
    }
    since = next(parameter for parameter in parameters if parameter["name"] == "since")
    order = next(parameter for parameter in parameters if parameter["name"] == "order")
    assert since["schema"]["format"] == "date-time"
    assert order["schema"]["enum"] == ["asc", "desc"]
