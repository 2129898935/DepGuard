"""deps.dev 必须从具体版本接口读取许可证。"""
import json

import tools.depsdev_tool as depsdev


def test_query_package_info_uses_exact_version_endpoint(monkeypatch):
    calls = []

    def fake_get(url):
        calls.append(url)
        return {
            "versionKey": {"system": "PYPI", "name": "requests", "version": "2.31.0"},
            "licenses": ["Apache-2.0"],
            "licenseDetails": [{"license": "Apache 2.0", "spdx": "Apache-2.0"}],
            "isDefault": False,
        }

    monkeypatch.setattr(depsdev, "_get_json", fake_get)
    result = json.loads(depsdev.query_package_info.func("requests", "2.31.0", "PYPI"))

    assert result["ok"] is True
    assert result["licenses"] == ["Apache-2.0"]
    assert calls == [
        "https://api.deps.dev/v3alpha/systems/PYPI/packages/requests/versions/2.31.0"
    ]


def test_query_package_info_resolves_default_then_gets_version(monkeypatch):
    def fake_get(url):
        if "/versions/" not in url:
            return {"versions": [
                {"versionKey": {"version": "1.0"}, "isDefault": False},
                {"versionKey": {"version": "2.0"}, "isDefault": True},
            ]}
        return {
            "versionKey": {"system": "PYPI", "name": "demo", "version": "2.0"},
            "licenses": ["MIT"],
        }

    monkeypatch.setattr(depsdev, "_get_json", fake_get)
    result = json.loads(depsdev.query_package_info.func("demo"))

    assert result["version"] == "2.0"
    assert result["licenses"] == ["MIT"]
