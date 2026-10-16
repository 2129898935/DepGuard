"""统一配置中心（M9）：用 pydantic-settings 集中管理 DepGuard 配置。

为什么集中：单一事实来源 + 类型校验 + 默认值 + 启动即报错，而不是散落的 os.getenv。
后续可逐步把各工具里散落的 os.getenv 迁移到这里。
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="DEPGUARD_", extra="ignore")

    # 数据源地址
    osv_api_base: str = "https://api.osv.dev/v1"
    depsdev_api_base: str = "https://api.deps.dev/v3alpha"
    github_token: str | None = None

    # 运行参数
    max_iterations: int = 30
    max_duration_seconds: int = 300
    token_budget_ratio: float = 0.6
    embedding_model: str | None = None

    # DepGuard 业务
    severity_threshold: str = "MEDIUM"
    business_domain: str = "dependency-security"
    upgrade_strategy: str = "conservative"


_settings: Settings | None = None


def get_settings() -> Settings:
    """懒加载全局 Settings 单例。"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
