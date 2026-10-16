from __future__ import annotations

from importlib.resources import files

from LibDOM.Elements import (
    H1,
    H2,
    Article,
    Body,
    Button,
    Div,
    Form,
    Head,
    Header,
    Html,
    Input,
    Label,
    Main,
    Meta,
    Nav,
    Option,
    Script,
    Section,
    Select,
    Small,
    Span,
    Strong,
    Table,
    Tbody,
    Th,
    Thead,
    Title,
    Tr,
)

from .styles import style


def attrs(**values: object) -> dict[str, object]:
    return {key.replace("_", "-"): value for key, value in values.items()}


def icon(name: str) -> Span:
    return Span(**attrs(data_lucide=name, aria_hidden="true", cls="icon"))


def tab(view: str, label: str, icon_name: str, active: bool = False) -> Button:
    classes = "nav-item active" if active else "nav-item"
    return Button(icon(icon_name), Span(label, **attrs(data_i18n=view)),
                  type="button", cls=classes, **attrs(data_view=view))


def metric(identifier: str, label: str, icon_name: str) -> Div:
    return Div(icon(icon_name), Label(label, **attrs(data_i18n=identifier)),
               Strong("0", id=identifier), cls="metric")


def table(headers: tuple[tuple[str, str], ...], body_id: str) -> Div:
    return Div(Table(
        Thead(Tr(*(Th(label, **attrs(data_i18n=key)) for key, label in headers))),
        Tbody(id=body_id),
    ), cls="table-scroll")


def home() -> Section:
    headers = (("lastSeen", "Última ocorrência"), ("client", "Cliente"),
               ("method", "Método"), ("route", "Rota"), ("class", "Classe"),
               ("risk", "Risco"), ("action", "Ação"), ("count", "Contador"),
               ("report", "Laudo"))
    return Section(
        Div(H1("Mitigações", **attrs(data_i18n="mitigations")),
            Button(icon("pause"), Span("Pausar tabela", **attrs(data_i18n="pause")),
                   id="pause", type="button", cls="button"), cls="page-heading"),
        Div(metric("requests", "REQUISIÇÕES ANALISADAS", "activity"),
            metric("blocked", "BLOQUEADAS", "shield-ban"),
            metric("unique", "MITIGAÇÕES ÚNICAS", "fingerprint"),
            metric("latency", "LATÊNCIA MÉDIA", "gauge"), cls="metrics"),
        Div(Article(H2("Ocorrências recentes", **attrs(data_i18n="occurrences")),
                    Div(id="chart", cls="chart"), cls="panel"),
            Article(H2("Classes observadas", **attrs(data_i18n="classes")),
                    Div(id="types", cls="types"), cls="panel"), cls="overview-grid"),
        Article(table(headers, "mitigations"), cls="panel"),
        id="home", cls="view active",
    )


def logs() -> Section:
    headers = (("updated", "Atualizado"), ("route", "Rota"),
               ("class", "Classe"), ("status", "Estado"))
    return Section(
        Div(H1("Laudos", **attrs(data_i18n="reports")), cls="page-heading"),
        Div(Article(table(headers, "reports"), cls="panel"),
            Article(Div(Strong("Selecione um laudo", id="reportTitle", **attrs(data_i18n="selectReport")),
                        Div(id="reportMeta", cls="muted"), cls="report-head"),
                    Div("A análise do Qwen3.5 aparece aqui após a mitigação.",
                        id="reportBody", cls="report", **attrs(data_i18n="reportPending")),
                    cls="panel"), cls="report-grid"),
        id="logs", cls="view",
    )


def setting(title_key: str, title: str, help_key: str, help_text: str, control: object) -> Div:
    return Div(Div(Strong(title, **attrs(data_i18n=title_key)),
                   Small(help_text, **attrs(data_i18n=help_key))), control, cls="config-row")


def configs() -> Section:
    languages = (("pt", "Português"), ("en", "English"), ("es", "Español"),
                 ("fr", "Français"), ("de", "Deutsch"), ("it", "Italiano"),
                 ("ja", "日本語"), ("zh", "中文"), ("ar", "العربية"))
    return Section(
        Div(H1("Configurações", **attrs(data_i18n="configs")), cls="page-heading"),
        Form(
            setting("protection", "Proteção ativa", "protectionHelp",
                    "Bloqueia requisições acima do limiar.",
                    Input(id="enforcement", type="checkbox", cls="switch")),
            setting("language", "Idioma", "languageHelp",
                    "Idioma da interface e dos laudos assistivos.",
                    Select(*(Option(label, value=code) for code, label in languages),
                           id="language", **attrs(aria_label="Idioma"))),
            setting("xgboostBackend", "Backend do XGBoost", "backendHelp",
                    "Aplicado ao reiniciar o LaTaupe.",
                    Select(id="xgboostBackend", **attrs(aria_label="Backend do XGBoost"))),
            setting("qwenBackend", "Backend do Qwen3.5", "backendHelp",
                    "Aplicado ao reiniciar o LaTaupe.",
                    Select(id="qwenBackend", **attrs(aria_label="Backend do Qwen3.5"))),
            setting("proxyPort", "Porta do proxy", "proxyPortHelp",
                    "Aplicada após reiniciar o LaTaupe.",
                    Input(id="proxyPort", type="number", min="1024", max="65535", step="1")),
            setting("observeThreshold", "Limiar de observação", "observeHelp",
                    "Registra atividade suspeita sem impedir.",
                    Input(id="observe", type="number", min="0", max="1", step="0.01")),
            setting("blockThreshold", "Limiar de bloqueio", "blockHelp",
                    "Decisão síncrona do XGBoost/PLeX.",
                    Input(id="blockAt", type="number", min="0", max="1", step="0.01")),
            Div(Button(icon("save"), Span("Salvar", **attrs(data_i18n="save")),
                       type="submit", cls="button primary"), Span(id="saved", cls="muted"),
                cls="form-actions"),
            id="configForm", cls="panel config-form",
        ), id="configs", cls="view",
    )


def render() -> str:
    document = Html(
        Head(Meta(charset="utf-8"),
             Meta(name="viewport", content="width=device-width,initial-scale=1"),
             Meta(name="color-scheme", content="dark"),
             Title("LaTaupe ML-Powered WAF"), style()),
        Body(
            Header(Div(Strong("LaTaupe"), Small("ML-Powered WAF"), cls="brand"),
                   Nav(tab("home", "Início", "layout-dashboard", True),
                       tab("logs", "Laudos", "file-search"),
                       tab("configs", "Configurações", "settings-2"), cls="navigation"),
                   Div(Span(id="status", cls="status-dot", role="status",
                            **attrs(aria_label="Proteção ativa")),
                       cls="runtime-status", title="Proteção ativa"), cls="topbar"),
            Main(home(), logs(), configs(), cls="shell"),
            Script(files("app").joinpath("assets/lucide.min.js").read_text()),
            Script(files("app").joinpath("assets/app.js").read_text()),
        ), lang="pt-BR",
    )
    return "<!doctype html>\n" + str(document)
