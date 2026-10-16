"""M1 —— JWT 认证单元测试。"""
import jwt

from api.auth import ALGORITHM, SECRET, create_access_token


def test_create_access_token_roundtrip():
    token = create_access_token("alice")
    assert isinstance(token, str)
    payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
    assert payload["sub"] == "alice"


def test_token_has_expiry():
    token = create_access_token("bob")
    payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
    assert "exp" in payload
