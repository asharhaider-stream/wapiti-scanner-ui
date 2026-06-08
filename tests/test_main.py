import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_dashboard_loads():
    response = client.get("/")
    assert response.status_code == 200

def test_history_returns_list():
    response = client.get("/history")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_analytics_returns_keys():
    response = client.get("/analytics")
    assert response.status_code == 200
    data = response.json()
    assert "vuln_types" in data
    assert "severity_distribution" in data
    assert "top_endpoints" in data
    assert "scan_trend" in data

def test_history_detail_invalid_id():
    response = client.get("/history/999")
    assert response.status_code == 200
    assert response.json() == []