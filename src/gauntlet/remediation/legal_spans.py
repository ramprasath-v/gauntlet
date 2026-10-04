"""Deterministic Python statement boundaries for bounded repair prompts."""

from __future__ import annotations

import ast
import textwrap

from pydantic import Field

from gauntlet.remediation.models import MAX_EDIT_LINES, StrictModel


MAX_LEGAL_EDIT_SPANS = 256

_COMPOUND_TYPES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.With,
    ast.AsyncWith,
    ast.Match,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
)
if hasattr(ast, "TryStar"):
    _COMPOUND_TYPES = (*_COMPOUND_TYPES, ast.TryStar)


class LegalEditSpan(StrictModel):
    """One complete statement or two adjacent complete sibling statements."""

    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    delete_line_count: int = Field(ge=1, le=MAX_EDIT_LINES)
    statement_kind: str
    compound_statement: bool


def derive_legal_edit_spans(source_text: str) -> list[LegalEditSpan]:
    """Return bounded symbol-relative spans without granting new authority."""
    tree = ast.parse(textwrap.dedent(source_text))
    spans: dict[tuple[int, int, str], LegalEditSpan] = {}

    def statement_start(node: ast.stmt) -> int:
        decorators = getattr(node, "decorator_list", ())
        return min(
            [node.lineno, *(decorator.lineno for decorator in decorators)]
        )

    def add(nodes: list[ast.stmt]) -> None:
        if not nodes:
            return
        for index, node in enumerate(nodes):
            if node.end_lineno is None:
                continue
            start = statement_start(node)
            end = node.end_lineno
            length = end - start + 1
            if length <= MAX_EDIT_LINES:
                kind = type(node).__name__
                spans[(start, end, kind)] = LegalEditSpan(
                    start_line=start,
                    end_line=end,
                    delete_line_count=length,
                    statement_kind=kind,
                    compound_statement=isinstance(node, _COMPOUND_TYPES),
                )
            if index + 1 < len(nodes):
                following = nodes[index + 1]
                if following.end_lineno is not None:
                    pair_end = following.end_lineno
                    pair_length = pair_end - start + 1
                    if pair_length <= MAX_EDIT_LINES:
                        pair_kind = (
                            f"{type(node).__name__}+{type(following).__name__}"
                        )
                        spans[(start, pair_end, pair_kind)] = LegalEditSpan(
                            start_line=start,
                            end_line=pair_end,
                            delete_line_count=pair_length,
                            statement_kind=pair_kind,
                            compound_statement=(
                                isinstance(node, _COMPOUND_TYPES)
                                or isinstance(following, _COMPOUND_TYPES)
                            ),
                        )

    def visit(node: ast.AST) -> None:
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                statements = [item for item in value if isinstance(item, ast.stmt)]
                if statements and len(statements) == len(value):
                    add(statements)
                for item in value:
                    if isinstance(item, ast.AST):
                        visit(item)
            elif isinstance(value, ast.AST):
                visit(value)

    visit(tree)
    ordered = sorted(
        spans.values(),
        key=lambda item: (
            item.start_line, item.end_line, item.statement_kind,
        ),
    )
    if len(ordered) > MAX_LEGAL_EDIT_SPANS:
        raise ValueError("authorized symbol has too many legal edit spans")
    return ordered
