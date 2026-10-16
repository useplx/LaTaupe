from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from urllib.parse import unquote_plus, urlsplit


@dataclass(frozen=True)
class Request:
    method: str
    target: str
    headers: dict[str, str]
    body: bytes = b""


@dataclass(frozen=True)
class Features:
    target_length: int
    query_length: int
    body_length: int
    parameter_count: int
    decode_depth: int
    non_alnum_ratio: float
    digit_ratio: float
    entropy: float
    quote_count: int
    angle_count: int
    traversal_count: int
    shell_count: int
    sql_count: int
    script_count: int
    template_count: int
    null_count: int
    method_code: int
    content_type_code: int

    def mapping(self) -> dict[str, int | float]:
        return asdict(self)


METHODS = {"GET": 1, "POST": 2, "PUT": 3, "PATCH": 4, "DELETE": 5, "OPTIONS": 6}
CONTENT_TYPES = {
    "application/json": 1,
    "application/x-www-form-urlencoded": 2,
    "multipart/form-data": 3,
    "application/xml": 4,
    "text/xml": 5,
}
SQL = re.compile(
    r"\b(select|union|insert|update|delete|drop|sleep|benchmark|information_schema)\b"
    r"|\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?\s*(?:--|#)",
    re.IGNORECASE,
)
SCRIPT = re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|<svg|document\.cookie)", re.IGNORECASE)
SHELL = re.compile(r"(;|\||&&|`|\$\(|/bin/(?:sh|bash)|(?:^|\s)(?:cat|curl|wget|id)(?:\s|$))", re.IGNORECASE)
TEMPLATE = re.compile(r"(\$\{|\{\{|<%|#\{)")


def decode(value: str, rounds: int = 3) -> tuple[str, int]:
    current, depth = value, 0
    for _ in range(rounds):
        decoded = unquote_plus(current)
        if decoded == current:
            break
        current, depth = decoded, depth + 1
    return current, depth


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def text(request: Request, limit: int = 65_536) -> tuple[str, int]:
    body = request.body[:limit].decode("utf-8", "replace")
    raw = f"{request.target}\n{body}"
    return decode(raw)


def extract(request: Request) -> Features:
    split = urlsplit(request.target)
    value, depth = text(request)
    compact = "".join(value.split())
    content_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
    return Features(
        target_length=len(request.target), query_length=len(split.query), body_length=len(request.body),
        parameter_count=split.query.count("=") + request.body.count(b"="), decode_depth=depth,
        non_alnum_ratio=sum(not char.isalnum() for char in compact) / max(len(compact), 1),
        digit_ratio=sum(char.isdigit() for char in compact) / max(len(compact), 1),
        entropy=entropy(compact), quote_count=value.count("'") + value.count('"'),
        angle_count=value.count("<") + value.count(">"),
        traversal_count=value.count("../") + value.count("..\\"), shell_count=len(SHELL.findall(value)),
        sql_count=len(SQL.findall(value)), script_count=len(SCRIPT.findall(value)),
        template_count=len(TEMPLATE.findall(value)), null_count=value.count("\x00") + value.lower().count("%00"),
        method_code=METHODS.get(request.method.upper(), 0), content_type_code=CONTENT_TYPES.get(content_type, 0),
    )


def hint(request: Request) -> str:
    value, _ = text(request)
    scores = {"sql-injection": len(SQL.findall(value)), "cross-site-scripting": len(SCRIPT.findall(value)),
              "path-traversal": value.count("../") + value.count("..\\"),
              "command-injection": len(SHELL.findall(value)), "template-injection": len(TEMPLATE.findall(value))}
    label, score = max(scores.items(), key=lambda item: item[1])
    return label if score else "web-anomaly"


def route(target: str) -> str:
    path = urlsplit(target).path or "/"
    return re.sub(r"/(?:(?:\d+)|(?:[0-9a-f]{8,}))(?=/|$)", "/:id", path, flags=re.IGNORECASE)
