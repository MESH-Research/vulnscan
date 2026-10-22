"""A small reader for the block-style YAML that Compose files and CI configuration use.

It understands nested mappings, lists of scalars and of mappings (including a list
written at the same indent as its key), quoted scalars and inline comments. Block
scalars (``|``, ``>``) collapse to a string, flow collections (``{...}``, ``[...]``)
and alias references (``*name``) are kept as the raw text, and ``<<:`` merges are
ignored. That is enough to find image references without a YAML dependency, and
anything not understood degrades to a string rather than an error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_KEY = re.compile(r'^(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'#][^:#]*?))\s*:(?:\s+|$)(.*)$')


class Scalar(str):
    """A string value that remembers the 0-based line it was read from."""

    line: int = -1

    def __new__(cls, value: str, line: int = -1) -> Scalar:
        scalar = super().__new__(cls, value)
        scalar.line = line
        return scalar


@dataclass
class _Line:
    indent: int
    text: str
    number: int


def _strip_comment(text: str) -> str:
    quote: str | None = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.rstrip()


def _scalar(text: str, line: int = -1) -> Scalar:
    value = text.strip()
    if value[:1] in ("'", '"') and len(value) >= 2 and value[-1] == value[0]:
        value = value[1:-1]
    elif value.startswith("&"):
        value = value.split(None, 1)[1] if " " in value else ""
    return Scalar(value, line)


def _lines(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for number, raw in enumerate(text.splitlines()):
        expanded = raw.replace("\t", "  ")
        stripped = expanded.strip()
        if not stripped or stripped.startswith("#"):
            continue
        content = _strip_comment(expanded.lstrip())
        if content:
            lines.append(_Line(len(expanded) - len(expanded.lstrip()), content, number))
    return lines


class _Parser:
    def __init__(self, lines: list[_Line]) -> None:
        self.lines = lines
        self.pos = 0

    def parse_block(self, indent: int) -> object:
        if self.pos >= len(self.lines):
            return None
        line = self.lines[self.pos]
        if line.indent != indent:
            return None
        if line.text == "-" or line.text.startswith("- "):
            return self.parse_list(indent)
        return self.parse_mapping(indent)

    def skip_deeper(self, indent: int) -> None:
        while self.pos < len(self.lines) and self.lines[self.pos].indent > indent:
            self.pos += 1

    def parse_value(self, indent: int, value: str, number: int) -> object:
        """The value of ``key: value``; a block follows when the value is empty."""
        if value in ("", "|", ">", "|-", ">-", "|+", ">+") or value.startswith("&"):
            if value.startswith("&") and " " in value.strip():
                return _scalar(value, number)
            if value.startswith(("|", ">")):
                self.skip_deeper(indent)
                return ""
            if self.pos < len(self.lines):
                nxt = self.lines[self.pos]
                if nxt.indent > indent:
                    return self.parse_block(nxt.indent)
                if nxt.indent == indent and (nxt.text == "-" or nxt.text.startswith("- ")):
                    return self.parse_list(indent)
            return None
        return _scalar(value, number)

    def parse_mapping(self, indent: int) -> dict:
        mapping: dict = {}
        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            if line.indent < indent:
                break
            if line.indent > indent:
                self.pos += 1  # continuation of a scalar: ignore
                continue
            if line.text == "-" or line.text.startswith("- "):
                break
            match = _KEY.match(line.text)
            self.pos += 1
            if not match:
                continue
            key = next(g for g in match.groups()[:3] if g is not None).strip()
            value = self.parse_value(indent, match.group(4).strip(), line.number)
            if key != "<<":
                mapping[key] = value
        return mapping

    def parse_list(self, indent: int) -> list:
        items: list = []
        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            if line.indent != indent or not (line.text == "-" or line.text.startswith("- ")):
                if line.indent > indent:
                    self.pos += 1
                    continue
                break
            rest = line.text[1:].lstrip()
            item_indent = indent + 1 + (len(line.text) - 1 - len(rest))
            if not rest:
                self.pos += 1
                items.append(
                    self.parse_block(self.lines[self.pos].indent)
                    if self.pos < len(self.lines) and self.lines[self.pos].indent > indent
                    else None
                )
                continue
            if rest.startswith("- "):
                self.lines[self.pos] = _Line(item_indent, rest, line.number)
                items.append(self.parse_list(item_indent))
                continue
            if _KEY.match(rest):
                self.lines[self.pos] = _Line(item_indent, rest, line.number)
                items.append(self.parse_mapping(item_indent))
                continue
            self.pos += 1
            items.append(_scalar(rest, line.number))
        return items


def load_yamlish(text: str) -> object:
    """Nested ``dict``/``list``/``str`` from block-style YAML, or ``None`` for empty text.

    Every string value is a :class:`Scalar`, which also records the line it came from.
    """
    lines = _lines(text)
    if not lines:
        return None
    parser = _Parser(lines)
    return parser.parse_block(lines[0].indent)
