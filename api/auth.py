"""JWT 身份认证（对齐 M1）。

为什么用 JWT：
    Agent 服务天然适合无状态水平扩展——每个请求自带身份，不用共享服务端 session。
    用「短 exp + 续期」应对过期；主动吊销用黑名单/版本号（实习生项目说清「短期过期」即可）。
"""
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# 默认仅用于本地开发；生产环境务必通过环境变量 DEPGUARD_JWT_SECRET 注入足够长的随机密钥
SECRET = os.getenv("DEPGUARD_JWT_SECRET", "dev-secret-change-me-do-not-use-in-prod")
ALGORITHM = "HS256"
_EXPIRE = timedelta(hours=2)

_scheme = HTTPBearer(auto_error=False)


def create_access_token(user_id: str) -> str:
    """签发 JWT：sub 存 user_id，exp 为过期时间。"""
    payload = {"sub": user_id, "exp": datetime.now(timezone.utc) + _EXPIRE}
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)


def get_current_user(
    cred: HTTPAuthorizationCredentials = Depends(_scheme),
) -> str:
    """FastAPI 依赖：从 Authorization: Bearer <token> 解析出 user_id，失败返回 401。"""
    if cred is None:
        raise HTTPException(status_code=401, detail="缺少 token")
    try:
        payload = jwt.decode(cred.credentials, SECRET, algorithms=[ALGORITHM])
        return payload["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="token 无效或过期")
