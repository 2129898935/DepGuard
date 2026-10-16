"""版本范围精确匹配（对齐 M11）：判断某个版本是否落在漏洞影响范围内。

OSV 的 affected.ranges[].events 格式形如：
    [{"introduced": "0"}, {"fixed": "2.31.2"}]           → 影响 [0, 2.31.2)
    [{"introduced": "2.31.0"}, {"last_affected": "2.31.1"}] → 影响 [2.31.0, 2.31.1]

用 packaging 做版本比较：PyPI 的 PEP 440 精确，npm 的 Semver 大部分兼容；
Maven（maven-artifact）与 dpkg 的专属比较器留待后续（生态差异化比较器）。
"""
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version


def _range_to_specifier(events: list[dict]) -> str:
    """把 OSV events 转成 SpecifierSet 字符串。"""
    introduced = fixed = last_affected = None
    for e in events:
        if "introduced" in e:
            introduced = e["introduced"]
        elif "fixed" in e:
            fixed = e["fixed"]
        elif "last_affected" in e:
            last_affected = e["last_affected"]

    parts = []
    if introduced is not None and introduced != "0":
        parts.append(f">={introduced}")
    if fixed is not None:
        parts.append(f"<{fixed}")
    elif last_affected is not None:
        parts.append(f"<={last_affected}")
    return ",".join(parts)


def is_affected(version: str, ranges: list[dict], ecosystem: str = "PyPI") -> bool:
    """判断 version 是否落在 ranges（OSV affected.ranges 格式）中。"""
    for r in ranges or []:
        events = r.get("events") or []
        spec = _range_to_specifier(events)
        if not spec:
            continue
        try:
            if Version(version) in SpecifierSet(spec):
                return True
        except (InvalidVersion, ValueError, TypeError):
            # 无法解析的版本号（如 dpkg 的 epoch 格式）跳过，后续用生态专属比较器
            continue
    return False
