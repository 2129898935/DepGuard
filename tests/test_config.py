"""M9 —— 配置中心单元测试。"""
from agent.config import Settings, get_settings


def test_settings_defaults():
    s = Settings(_env_file=None)  # 不读 .env，纯默认值
    assert s.osv_api_base == "https://api.osv.dev/v1"
    assert s.depsdev_api_base == "https://api.deps.dev/v3alpha"
    assert s.max_iterations == 30
    assert s.severity_threshold == "MEDIUM"
    assert s.business_domain == "dependency-security"
    assert s.upgrade_strategy == "conservative"


def test_get_settings_singleton():
    assert get_settings() is get_settings()
