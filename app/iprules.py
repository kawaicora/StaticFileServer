"""IP 访问规则：白名单 / 黑名单的解析与匹配。

支持格式（忽略大小写与首尾空白）：

- 单个 IP：        192.168.2.3
- 通配符：         192.168.2.*      （等价于 192.168.2.0/24）
- CIDR：           192.168.2.0/24
- 区间：           192.168.2.100-192.168.2.150
- 缩写区间：       192.168.2.100-150（右侧仅写末段时自动补全前三段）
- IPv6：           ::1、fe80::1、2001:db8::/32
- 全部 / 任意：    *、0.0.0.0/0、any

匹配逻辑：
- 黑名单命中即拒绝（优先级最高）
- 白名单非空时，未命中白名单的 IP 一律拒绝
- 白名单为空时，只要不在黑名单就放行
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

ALL_TOKENS = {"*", "any", "all", "0.0.0.0/0", "::/0"}


class RuleError(ValueError):
    """规则串非法。"""


@dataclass
class IPRule:
    """单条已解析的规则。"""

    raw: str
    kind: str  # single | network | range
    start: int
    end: int
    version: int

    def contains(self, addr: ipaddress._BaseAddress) -> bool:
        if addr.version != self.version:
            return False
        value = int(addr)
        return self.start <= value <= self.end


@dataclass
class IPMatcher:
    """一组规则；用来判定某个 IP 是否命中。"""

    rules: list[IPRule] = field(default_factory=list)
    match_all: bool = False

    def __bool__(self) -> bool:
        return self.match_all or bool(self.rules)

    def contains(self, ip: str) -> bool:
        if self.match_all:
            return True
        if not self.rules:
            return False
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        return any(rule.contains(addr) for rule in self.rules)


def _to_int(addr: str) -> tuple[int, int]:
    """返回 (数值, 版本)。"""
    obj = ipaddress.ip_address(addr.strip())
    return int(obj), obj.version


def parse_rule(text: str) -> IPRule:
    """解析单条规则为 IPRule；非法时抛 RuleError。"""
    raw = (text or "").strip()
    if not raw:
        raise RuleError("规则为空")

    lowered = raw.lower()
    if lowered in ALL_TOKENS:
        # 用整个地址空间表示“全部”
        return IPRule(raw=raw, kind="all", start=0, end=(1 << 128) - 1, version=0)

    # 通配符：192.168.2.* -> 转成网络段
    if "*" in raw:
        return _parse_wildcard(raw)

    # 区间：a-b（含缩写形式 a.b.c.100-150）
    if "-" in raw:
        return _parse_range(raw)

    # CIDR 或单 IP
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise RuleError(f"非法网段: {raw}") from exc
        return IPRule(
            raw=raw,
            kind="network",
            start=int(net.network_address),
            end=int(net.broadcast_address),
            version=net.version,
        )

    try:
        value, version = _to_int(raw)
    except ValueError as exc:
        raise RuleError(f"非法 IP: {raw}") from exc
    return IPRule(raw=raw, kind="single", start=value, end=value, version=version)


def _parse_wildcard(raw: str) -> IPRule:
    """192.168.2.* / 192.168.*.* / 2001:db8::* 等。"""
    if raw.count("*") > 1 and ":" in raw:
        raise RuleError(f"IPv6 不支持多段通配符: {raw}")

    if ":" in raw:
        # IPv6：只允许末尾一段通配
        head = raw.rstrip("*").rstrip(":")
        try:
            base = ipaddress.IPv6Address(head)
        except ValueError as exc:
            raise RuleError(f"非法 IPv6 通配: {raw}") from exc
        prefix_len = len(base.exploded.split(":"))
        # 简化处理：把 base 当作网络前缀
        try:
            net = ipaddress.ip_network(f"{base}/{prefix_len * 16}", strict=False)
        except ValueError as exc:
            raise RuleError(f"非法 IPv6 通配: {raw}") from exc
        return IPRule(
            raw=raw,
            kind="network",
            start=int(net.network_address),
            end=int(net.broadcast_address),
            version=net.version,
        )

    parts = raw.split(".")
    if len(parts) != 4:
        raise RuleError(f"非法通配符地址: {raw}")
    if any(p != "*" and not (p.isdigit() and 0 <= int(p) <= 255) for p in parts):
        raise RuleError(f"非法通配符地址: {raw}")

    # 找到第一个 *，之后必须全是 *
    try:
        first_star = parts.index("*")
    except ValueError:
        raise RuleError(f"非法通配符地址: {raw}") from None
    if any(p != "*" for p in parts[first_star:]):
        raise RuleError(f"通配符只能出现在末尾: {raw}")

    fixed = parts[:first_star]
    if not fixed:
        return IPRule(raw=raw, kind="all", start=0, end=(1 << 128) - 1, version=0)

    # 用 0 补全通配段，得到网络地址（如 192.168.2.* -> 192.168.2.0）
    padded = fixed + ["0"] * (4 - first_star)
    base = ".".join(padded)
    prefix = first_star * 8
    try:
        net = ipaddress.ip_network(f"{base}/{prefix}", strict=False)
    except ValueError as exc:
        raise RuleError(f"非法通配符地址: {raw}") from exc
    return IPRule(
        raw=raw,
        kind="network",
        start=int(net.network_address),
        end=int(net.broadcast_address),
        version=net.version,
    )


def _parse_range(raw: str) -> IPRule:
    """192.168.2.100-192.168.2.150 或 192.168.2.100-150。"""
    left, _, right = raw.partition("-")
    left = left.strip()
    right = right.strip()
    if not left or not right:
        raise RuleError(f"非法区间: {raw}")

    try:
        start, version = _to_int(left)
    except ValueError as exc:
        raise RuleError(f"非法区间起点: {left}") from exc

    # 缩写：右侧仅末段
    if ":" not in left and "." in left and "." not in right and right.isdigit():
        head = left.rsplit(".", 1)[0]
        right = f"{head}.{right}"

    try:
        end, end_version = _to_int(right)
    except ValueError as exc:
        raise RuleError(f"非法区间终点: {right}") from exc

    if end_version != version:
        raise RuleError(f"区间两端 IP 版本不一致: {raw}")
    if end < start:
        start, end = end, start
    return IPRule(raw=raw, kind="range", start=start, end=end, version=version)


def build_matcher(entries) -> IPMatcher:
    """把字符串列表编译为 IPMatcher；非法项会被跳过（由调用方另行校验）。"""
    rules: list[IPRule] = []
    match_all = False
    for item in entries or []:
        try:
            rule = parse_rule(str(item))
        except RuleError:
            continue
        if rule.kind == "all":
            match_all = True
        else:
            rules.append(rule)
    return IPMatcher(rules=rules, match_all=match_all)


def validate_entries(entries) -> list[str]:
    """返回非法规则的错误信息列表（空列表表示全部合法）。"""
    errors: list[str] = []
    for item in entries or []:
        text = str(item).strip()
        if not text:
            continue
        try:
            parse_rule(text)
        except RuleError as exc:
            errors.append(f"{text}: {exc}")
    return errors


def is_allowed(ip: str, matcher_black: IPMatcher, matcher_white: IPMatcher) -> tuple[bool, str]:
    """判定 IP 是否放行；返回 (是否放行, 原因)。

    规则：黑名单优先；白名单非空时必须在白名单内。
    """
    if matcher_black.contains(ip):
        return False, "命中黑名单"
    if matcher_white:
        if matcher_white.contains(ip):
            return True, "命中白名单"
        return False, "不在白名单内"
    return True, "默认放行"
