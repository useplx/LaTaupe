from __future__ import annotations

import nh3
from markdown_it import MarkdownIt

_renderer = MarkdownIt("commonmark", {"html": False, "linkify": False, "typographer": False})
_tags = {
    "a", "blockquote", "br", "code", "em", "h1", "h2", "h3", "h4", "hr", "li",
    "ol", "p", "pre", "strong", "table", "tbody", "td", "th", "thead", "tr", "ul",
}
_attributes = {"a": {"href", "title"}}


def render(source: str | None) -> str:
    """Render model Markdown while keeping untrusted payloads inert."""
    document = _renderer.render(source or "")
    return nh3.clean(document, tags=_tags, attributes=_attributes, url_schemes={"https"})
