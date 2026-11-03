"""Read facts from one source file with tree-sitter: imports and entry points.

tree-sitter builds a syntax tree without running the code. Each fact keeps
the line it came from, so every edge on the map can point at its evidence.
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field

import tree_sitter as ts


@dataclass
class ImportFact:
    spec: str
    """The module as written: './lib/insecurity', 'flask', 'dvwa/includes/dvwaPage.inc.php'."""
    line: int
    kind: str = "import"
    """import, require, include, use, dynamic."""
    text: str = ""
    complete: bool = True
    """False when the path is built at run time and only a fragment is known."""
    names: list[str] = field(default_factory=list)
    """Local names the import binds: 'searchProducts', 'models' for 'import * as models'."""


@dataclass
class FileFacts:
    imports: list[ImportFact] = field(default_factory=list)
    entry_point: bool = False
    package: str | None = None
    """Go package name, Java/PHP namespace or package."""
    declares: list[str] = field(default_factory=list)
    """Fully qualified names this file declares (PHP classes, Java types)."""
    functions: list[str] = field(default_factory=list)
    """Top-level function names (used to find the file behind a Go handler like handlers.Login)."""
    routes: list = field(default_factory=list)
    http_calls: list = field(default_factory=list)
    db_calls: list = field(default_factory=list)
    inputs: list = field(default_factory=list)
    engines: list = field(default_factory=list)
    mounts: list = field(default_factory=list)
    page: bool = False
    """PHP: the file runs code at the top level, so a request to it does something."""
    errors: bool = False

    def binding(self, name: str) -> ImportFact | None:
        for fact in self.imports:
            if name in fact.names:
                return fact
        return None


_MAIN_GUARD = re.compile(r"""__name__\s*==\s*['"]__main__['"]""")


@functools.lru_cache(maxsize=None)
def language(name: str) -> ts.Language | None:
    try:
        if name == "python":
            import tree_sitter_python as module

            return ts.Language(module.language())
        if name == "javascript":
            import tree_sitter_javascript as module

            return ts.Language(module.language())
        if name == "typescript":
            import tree_sitter_typescript as module

            return ts.Language(module.language_typescript())
        if name == "tsx":
            import tree_sitter_typescript as module

            return ts.Language(module.language_tsx())
        if name == "php":
            import tree_sitter_php as module

            return ts.Language(module.language_php())
        if name == "go":
            import tree_sitter_go as module

            return ts.Language(module.language())
        if name == "java":
            import tree_sitter_java as module

            return ts.Language(module.language())
    except ImportError:
        return None
    return None


def parse(name: str, source: bytes) -> ts.Tree | None:
    lang = language(name)
    if lang is None:
        return None
    parser = ts.Parser(lang)
    return parser.parse(source)


def walk(node: ts.Node):
    """Every node below and including node, depth first, without recursion limits."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def text(node: ts.Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def line_of(node: ts.Node) -> int:
    return node.start_point[0] + 1


def snippet(source: bytes, node: ts.Node, limit: int = 160) -> str:
    lines = source.splitlines()
    index = node.start_point[0]
    if 0 <= index < len(lines):
        return lines[index].decode("utf-8", errors="replace").strip()[:limit]
    return ""


def string_value(node: ts.Node | None) -> str | None:
    """The value of a plain string literal, or None when it is built from parts."""
    if node is None:
        return None
    if node.type in {"string", "interpreted_string_literal", "raw_string_literal", "string_literal", "encapsed_string"}:
        parts = [child for child in node.children if child.type not in {'"', "'", "`"}]
        if any(child.type in {"template_substitution", "interpolation", "escape_sequence_dynamic", "variable_name"} for child in parts):
            return None
        fragments = [child for child in parts if child.type in {"string_fragment", "string_content", "interpreted_string_literal_content", "raw_string_literal_content"}]
        if fragments:
            return "".join(text(child) for child in fragments)
        raw = text(node)
        if len(raw) >= 2 and raw[0] in "\"'`" and raw[-1] == raw[0]:
            return raw[1:-1]
        return raw
    if node.type == "template_string":
        if any(child.type == "template_substitution" for child in node.children):
            return None
        return "".join(text(child) for child in node.children if child.type == "string_fragment")
    return None


def string_tail(node: ts.Node | None) -> str | None:
    """For 'A . "/x.php"' or 'ROOT + "/x"': the last literal piece. Used for paths built from a constant prefix."""
    if node is None:
        return None
    value = string_value(node)
    if value is not None:
        return value
    if node.type in {"binary_expression", "parenthesized_expression"} and node.children:
        return string_tail(node.children[-1])
    return None


# --- per-language import extraction ---------------------------------------------------------


def _python(tree: ts.Tree, source: bytes, facts: FileFacts) -> None:
    for node in walk(tree.root_node):
        if node.type == "import_statement":
            for child in node.named_children:
                target = child.child_by_field_name("name") if child.type == "aliased_import" else child
                if target is not None and target.type == "dotted_name":
                    alias = child.child_by_field_name("alias") if child.type == "aliased_import" else None
                    bound = text(alias) if alias is not None else text(target).split(".")[0]
                    facts.imports.append(ImportFact(text(target), line_of(node), "import", snippet(source, node), names=[bound]))
        elif node.type == "import_from_statement":
            module = node.child_by_field_name("module_name")
            if module is None:
                continue
            spec = text(module)
            pairs = []
            for child in node.children_by_field_name("name"):
                if child.type == "aliased_import":
                    alias = child.child_by_field_name("alias")
                    original = text(child.child_by_field_name("name"))
                    pairs.append((original, text(alias) if alias is not None else original))
                else:
                    pairs.append((text(child), text(child)))
            if spec.strip(".") == "" and pairs:
                # "from . import views": each name may be a module.
                for original, bound in pairs:
                    facts.imports.append(ImportFact(spec + original, line_of(node), "import", snippet(source, node), names=[bound]))
            else:
                facts.imports.append(ImportFact(spec, line_of(node), "import", snippet(source, node), names=[bound for _, bound in pairs]))
        elif node.type == "if_statement":
            condition = text(node.child_by_field_name("condition"))
            if _MAIN_GUARD.search(condition):
                facts.entry_point = True
        elif node.type == "call":
            function = text(node.child_by_field_name("function"))
            if function in {"Flask", "FastAPI", "Django", "get_wsgi_application", "get_asgi_application"} or function.endswith(".run") and "app" in function:
                facts.entry_point = True


def _js_import_names(node: ts.Node) -> list[str]:
    names = []
    for clause in node.children:
        if clause.type != "import_clause":
            continue
        for part in clause.named_children:
            if part.type == "identifier":
                names.append(text(part))
            elif part.type == "namespace_import":
                names += [text(child) for child in part.named_children if child.type == "identifier"]
            elif part.type == "named_imports":
                for spec in part.named_children:
                    if spec.type == "import_specifier":
                        alias = spec.child_by_field_name("alias") or spec.child_by_field_name("name")
                        names.append(text(alias))
    return names


def _js_require_names(call: ts.Node) -> list[str]:
    """const x = require('y'), const { a, b: c } = require('y')."""
    parent = call.parent
    while parent is not None and parent.type in {"await_expression", "parenthesized_expression"}:
        parent = parent.parent
    if parent is None or parent.type != "variable_declarator":
        return []
    target = parent.child_by_field_name("name")
    if target is None:
        return []
    if target.type == "identifier":
        return [text(target)]
    names = []
    for part in target.named_children:
        if part.type == "shorthand_property_identifier_pattern":
            names.append(text(part))
        elif part.type == "pair_pattern":
            value = part.child_by_field_name("value")
            if value is not None and value.type == "identifier":
                names.append(text(value))
    return names


def _javascript(tree: ts.Tree, source: bytes, facts: FileFacts) -> None:
    for node in walk(tree.root_node):
        if node.type in {"import_statement", "export_statement"}:
            module = node.child_by_field_name("source")
            value = string_value(module)
            if value is not None:
                facts.imports.append(ImportFact(value, line_of(node), "import", snippet(source, node), names=_js_import_names(node)))
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            name = text(function)
            if function is not None and (name == "require" or function.type == "import") and arguments is not None:
                first = arguments.named_children[0] if arguments.named_children else None
                value = string_value(first)
                kind = "require" if name == "require" else "dynamic"
                if value is not None:
                    facts.imports.append(ImportFact(value, line_of(node), kind, snippet(source, node), names=_js_require_names(node)))
                elif first is not None:
                    facts.imports.append(ImportFact(text(first)[:80], line_of(node), kind, snippet(source, node), complete=False))
            elif name.endswith(".listen") or name in {"createServer", "http.createServer", "https.createServer", "bootstrapApplication", "platformBrowserDynamic().bootstrapModule"}:
                facts.entry_point = True
            elif name.endswith("bootstrapModule"):
                facts.entry_point = True


def _php(tree: ts.Tree, source: bytes, facts: FileFacts) -> None:
    namespace = ""
    for node in walk(tree.root_node):
        if node.type in {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}:
            argument = node.named_children[0] if node.named_children else None
            if argument is not None and argument.type == "parenthesized_expression" and argument.named_children:
                argument = argument.named_children[0]
            value = string_value(argument)
            kind = "require" if node.type.startswith("require") else "include"
            if value is not None:
                facts.imports.append(ImportFact(value, line_of(node), kind, snippet(source, node)))
            else:
                tail = string_tail(argument)
                facts.imports.append(
                    ImportFact(tail or text(argument)[:80], line_of(node), kind, snippet(source, node), complete=False)
                )
        elif node.type == "namespace_definition":
            name = node.child_by_field_name("name")
            if name is not None:
                namespace = text(name)
                facts.package = namespace
        elif node.type == "namespace_use_declaration":
            for clause in walk(node):
                if clause.type == "namespace_use_clause":
                    name = clause.named_children[0] if clause.named_children else None
                    if name is not None:
                        spec = text(name).lstrip("\\")
                        alias = clause.named_children[-1] if len(clause.named_children) > 1 else None
                        bound = text(alias) if alias is not None and alias.type == "name" else spec.split("\\")[-1]
                        facts.imports.append(ImportFact(spec, line_of(node), "use", snippet(source, node), names=[bound]))
        elif node.type in {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"}:
            name = node.child_by_field_name("name")
            if name is not None:
                facts.declares.append(f"{namespace}\\{text(name)}" if namespace else text(name))


def _go(tree: ts.Tree, source: bytes, facts: FileFacts) -> None:
    for node in walk(tree.root_node):
        if node.type == "package_clause":
            name = node.named_children[0] if node.named_children else None
            facts.package = text(name)
        elif node.type == "import_spec":
            path = node.child_by_field_name("path")
            value = string_value(path)
            if value is not None:
                alias = node.child_by_field_name("name")
                parts = [part for part in value.split("/") if not re.fullmatch(r"v\d+", part)]
                bound = text(alias) if alias is not None else (parts[-1] if parts else value)
                facts.imports.append(ImportFact(value, line_of(node), "import", snippet(source, node), names=[bound.replace("-", "_")]))
        elif node.type == "function_declaration":
            name = text(node.child_by_field_name("name"))
            facts.functions.append(name)
            if name == "main":
                facts.entry_point = facts.package == "main"


def _java(tree: ts.Tree, source: bytes, facts: FileFacts) -> None:
    package = ""
    for node in walk(tree.root_node):
        if node.type == "package_declaration":
            name = node.named_children[0] if node.named_children else None
            package = text(name)
            facts.package = package
        elif node.type == "import_declaration":
            names = [child for child in node.named_children if child.type in {"scoped_identifier", "identifier"}]
            if names:
                spec = text(names[0])
                star = any(child.type == "asterisk" for child in node.children)
                bound = [] if star else [spec.split(".")[-1]]
                if star:
                    spec += ".*"
                facts.imports.append(ImportFact(spec, line_of(node), "import", snippet(source, node), names=bound))
        elif node.type in {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration"}:
            name = node.child_by_field_name("name")
            if name is not None and node.parent is not None and node.parent.type == "program":
                facts.declares.append(f"{package}.{text(name)}" if package else text(name))
        elif node.type == "method_declaration" and text(node.child_by_field_name("name")) == "main":
            if "static" in text(node)[:200]:
                facts.entry_point = True
        elif node.type == "marker_annotation" and text(node) == "@SpringBootApplication":
            facts.entry_point = True


_EXTRACTORS = {
    "python": _python,
    "javascript": _javascript,
    "typescript": _javascript,
    "tsx": _javascript,
    "php": _php,
    "go": _go,
    "java": _java,
}


def read_facts(language_name: str, source: bytes) -> FileFacts:
    facts = FileFacts()
    tree = parse(language_name, source)
    if tree is None:
        return facts
    facts.errors = tree.root_node.has_error
    _EXTRACTORS[language_name](tree, source, facts)
    from grephunt.project_map import architecture_facts

    architecture_facts.extract(language_name, tree, source, facts)
    return facts
