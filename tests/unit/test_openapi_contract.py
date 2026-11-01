"""The checked-in OpenAPI contract matches the Python API routes."""
import yaml

from shadow313.api.server import create_app


def test_openapi_paths_match_api_routes():
    with open("api/openapi.yaml", encoding="utf-8") as contract_file:
        contract = yaml.safe_load(contract_file)

    app = create_app(api_key="test-key")
    internal_routes = {"/api/docs", "/api/redoc", "/api/openapi.json"}
    implementation_paths = set(app.openapi()["paths"]) - internal_routes
    contract_paths = set(contract["paths"])

    assert implementation_paths == contract_paths
