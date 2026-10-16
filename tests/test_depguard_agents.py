"""六阶段 Agent 配置与轻量影响分析测试。"""
from pathlib import Path

import yaml

from tools.impact_analysis_tool import find_dependency_usage


def test_prompts_define_depguard_and_six_roles():
    prompt_path = Path(__file__).parents[1] / "prompt" / "prompts.yml"
    data = yaml.safe_load(prompt_path.read_text(encoding="utf-8"))
    main_prompt = data["main_agent"]["system_prompt"]
    assert "DepGuard" in main_prompt
    assert "电商" not in main_prompt
    assert list(data["sub_agents"]) == [
        "dependency_parser",
        "vulnerability_intelligence",
        "license_maintenance",
        "impact_analysis",
        "upgrade_planning",
        "report_review",
    ]


def test_find_dependency_usage_distinguishes_production_and_tests(tmp_path):
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_api.py").write_text("from requests import Session\n", encoding="utf-8")
    (tmp_path / "ignore.txt").write_text("import requests\n", encoding="utf-8")

    hits = find_dependency_usage(tmp_path, "requests")
    assert [(h["file"], h["scope"]) for h in hits] == [
        ("app.py", "production"),
        ("tests/test_api.py", "test"),
    ]


def test_find_dependency_usage_supports_javascript_require(tmp_path):
    (tmp_path / "index.js").write_text("const axios = require('axios');\n", encoding="utf-8")
    hits = find_dependency_usage(tmp_path, "axios")
    assert len(hits) == 1
    assert hits[0]["line"] == 1
