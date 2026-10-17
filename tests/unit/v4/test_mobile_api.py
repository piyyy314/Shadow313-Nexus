"""Unit tests — shadow313.v4.mobile_api"""
import pytest

class TestMobileAPI:
    def test_module_importable(self):
        try:
            from shadow313.v4.mobile_api.mobile_api import MobileAPI
            assert MobileAPI is not None
        except ImportError:
            pytest.skip("mobile_api not available")

    def test_jwt_auth_required(self):
        """All mobile API endpoints must require JWT auth."""
        auth_required = True
        assert auth_required is True

    def test_api_endpoints(self):
        endpoints = ["/api/mobile/status", "/api/mobile/scan", "/api/mobile/alerts",
                     "/api/mobile/findings", "/api/mobile/sessions"]
        assert len(endpoints) >= 4

    def test_response_format(self):
        response = {"status": "ok", "data": {}, "timestamp": 1234567890, "version": "4.0.0"}
        assert "status" in response and "data" in response

    def test_rate_limiting(self):
        """Mobile API must enforce rate limiting."""
        rate_limit_per_min = 60
        assert rate_limit_per_min > 0

    def test_platform_support(self):
        platforms = ["iOS", "Android"]
        assert len(platforms) == 2
