from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class Source:
    title: str
    url: str
    summary: str


class Sources:
    COMMON: ClassVar[tuple[Source, ...]] = (
        Source(
            "OWASP Web Security Testing Guide",
            "https://owasp.org/www-project-web-security-testing-guide/",
            "Metodologia de teste, validacao de evidencias e comunicacao de riscos web.",
        ),
    )
    BY_ATTACK: ClassVar[dict[str, tuple[Source, ...]]] = {
        "sql injection": (
            Source(
                "CWE-89: SQL Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
                "Define SQL injection, consequencias, mitigacoes e exemplos de deteccao.",
            ),
            Source(
                "OWASP SQL Injection Prevention Cheat Sheet",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "Recomenda consultas parametrizadas, allow-lists e privilegios minimos.",
            ),
        ),
        "cross site scripting": (
            Source(
                "CWE-79: Cross-site Scripting",
                "https://cwe.mitre.org/data/definitions/79.html",
                "Define XSS e suas estrategias de neutralizacao de saida.",
            ),
            Source(
                "OWASP Cross Site Scripting Prevention Cheat Sheet",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "Orienta encoding contextual, sanitizacao e controles de browser.",
            ),
        ),
        "path traversal": (
            Source(
                "CWE-22: Path Traversal",
                "https://cwe.mitre.org/data/definitions/22.html",
                "Define acesso a caminhos fora do diretorio autorizado e mitigacoes.",
            ),
        ),
        "command injection": (
            Source(
                "CWE-78: OS Command Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
                "Define injecao de comandos do sistema operacional e controles preventivos.",
            ),
        ),
    }

    @classmethod
    def select(
        cls, attack_type: str, features: dict[str, int | float] | None = None
    ) -> list[Source]:
        normalized = attack_type.casefold().replace("_", "-")
        aliases = {
            "sqli": "sql injection",
            "sql-injection": "sql injection",
            "xss": "cross site scripting",
            "cross-site scripting": "cross site scripting",
            "traversal": "path traversal",
            "path-traversal": "path traversal",
            "rce": "command injection",
            "command-injection": "command injection",
        }
        category = aliases.get(normalized, normalized)
        signals = features or {}
        if category in {"automated-scan", "web-anomaly"}:
            ranked = {
                "sql injection": signals.get("sql_count", 0),
                "cross site scripting": signals.get("script_count", 0),
                "path traversal": signals.get("traversal_count", 0),
                "command injection": signals.get("shell_count", 0),
            }
            inferred, score = max(ranked.items(), key=lambda item: item[1])
            if score:
                category = inferred
        return [*cls.BY_ATTACK.get(category, ()), *cls.COMMON]
