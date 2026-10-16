"""Memory embedding 后端：远程 Embedding 可选，本地稳定向量作为降级。"""
import hashlib
import math
import os
import re

from dotenv import find_dotenv, load_dotenv

load_dotenv(find_dotenv())

_LOCAL_DIMENSION = 384
_remote_disabled = False


def _tokens(text: str) -> list[str]:
    """同时提取英文词、中文单字/二元组，适配中英文安全记忆。"""
    value = (text or "").lower()
    tokens = re.findall(r"[a-z0-9_.-]+", value)
    for chunk in re.findall(r"[\u4e00-\u9fff]+", value):
        tokens.extend(chunk)
        tokens.extend(chunk[i : i + 2] for i in range(len(chunk) - 1))
    return tokens


def local_hash_embedding(text: str, dimension: int = _LOCAL_DIMENSION) -> list[float]:
    """无需模型下载的稳定稀疏向量；用于离线降级和测试。"""
    vector = [0.0] * dimension
    for token in _tokens(text):
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        index = int.from_bytes(digest[:4], "big") % dimension
        sign = 1.0 if digest[4] & 1 else -1.0
        vector[index] += sign
    norm = math.sqrt(sum(value * value for value in vector))
    if norm:
        vector = [value / norm for value in vector]
    return vector


def embed_text(text: str) -> tuple[str, list[float]]:
    """返回 (backend_id, vector)。

    配置 DEPGUARD_EMBEDDING_MODEL 时使用 OpenAI 兼容 embeddings API；
    服务不可用时自动降级到本地向量，并在当前进程内熔断后续远程尝试。
    """
    global _remote_disabled
    model = os.getenv("DEPGUARD_EMBEDDING_MODEL", "").strip()
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    base_url = os.getenv("OPENAI_BASE_URL", "").strip()
    if model and api_key and not _remote_disabled:
        try:
            from openai import OpenAI

            client = OpenAI(api_key=api_key, base_url=base_url or None)
            response = client.embeddings.create(model=model, input=text[:8000])
            return f"openai:{model}", list(response.data[0].embedding)
        except Exception:
            _remote_disabled = True
    return f"local-hash:{_LOCAL_DIMENSION}", local_hash_embedding(text)


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or len(left) != len(right):
        return 0.0
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if not left_norm or not right_norm:
        return 0.0
    return sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)
