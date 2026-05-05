from __future__ import annotations

import ast
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.orchestrator.agent_registry import AgentRegistry, discover_agents


IMPORT_RE = re.compile(
    r"""(?mx)
    ^
    \s*
    (?:
        import\s+([a-zA-Z0-9_.,\s]+)
        |
        from\s+([a-zA-Z0-9_\.]+)\s+import\s+
    )
    """
)


@dataclass
class DependencyEdge:
    source_path: str
    target_path: str
    relation: str
    confidence: str = "high"


@dataclass
class FileDependencyNode:
    relative_path: str
    imports: list[str] = field(default_factory=list)
    outgoing: list[str] = field(default_factory=list)
    incoming: list[str] = field(default_factory=list)
    blast_radius: int = 0
    risk_tier: str = "normal"


@dataclass
class DependencyGraph:
    project_root: str
    nodes: list[FileDependencyNode] = field(default_factory=list)
    edges: list[DependencyEdge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "project_root": self.project_root,
            "nodes": [asdict(node) for node in self.nodes],
            "edges": [asdict(edge) for edge in self.edges],
        }


def _read_text(path: Path, max_chars: int = 20000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except OSError:
        return ""


def _module_candidates_for_path(relative_path: str) -> set[str]:
    path = Path(relative_path)
    parts = list(path.with_suffix("").parts)
    if not parts:
        return set()

    dotted = ".".join(parts)
    candidates = {dotted}

    if parts[-1] == "__init__":
        package_name = ".".join(parts[:-1])
        if package_name:
            candidates.add(package_name)

    return candidates


def _build_module_index(registry: AgentRegistry) -> dict[str, str]:
    index: dict[str, str] = {}
    for item in registry.items:
        if item.language != "python":
            continue
        for candidate in _module_candidates_for_path(item.relative_path):
            index[candidate] = item.relative_path
    return index


def _extract_python_imports_ast(text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    imports: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)

    return imports


def _extract_imports_fallback(text: str) -> list[str]:
    imports: list[str] = []

    for match in IMPORT_RE.finditer(text):
        import_clause = match.group(1)
        from_clause = match.group(2)

        if import_clause:
            parts = [part.strip() for part in import_clause.split(",") if part.strip()]
            imports.extend(parts)

        if from_clause:
            imports.append(from_clause.strip())

    return imports


def _extract_imports(relative_path: str, text: str) -> list[str]:
    if relative_path.endswith(".py"):
        imports = _extract_python_imports_ast(text)
        if imports:
            return sorted(set(imports))

    return sorted(set(_extract_imports_fallback(text)))


def _resolve_import_to_path(import_name: str, module_index: dict[str, str]) -> str | None:
    if import_name in module_index:
        return module_index[import_name]

    current = import_name
    while "." in current:
        current = current.rsplit(".", 1)[0]
        if current in module_index:
            return module_index[current]

    return None


def _build_risk_tier(relative_path: str, blast_radius: int) -> str:
    lowered = relative_path.lower()

    if any(part in lowered for part in ["security", "guard", "scanner", "policy", "orchestrator"]):
        return "critical"

    if blast_radius >= 10:
        return "high"
    if blast_radius >= 4:
        return "elevated"
    return "normal"


def build_dependency_graph(project_root: str | Path) -> DependencyGraph:
    registry = discover_agents(project_root)
    module_index = _build_module_index(registry)

    node_map: dict[str, FileDependencyNode] = {
        item.relative_path: FileDependencyNode(relative_path=item.relative_path)
        for item in registry.items
    }

    edge_keys: set[tuple[str, str, str]] = set()
    edges: list[DependencyEdge] = []

    for item in registry.items:
        path = Path(item.absolute_path)
        text = _read_text(path)
        imports = _extract_imports(item.relative_path, text)

        node = node_map[item.relative_path]
        node.imports = imports

        for import_name in imports:
            target_path = _resolve_import_to_path(import_name, module_index)
            if not target_path:
                continue
            if target_path == item.relative_path:
                continue

            key = (item.relative_path, target_path, "imports")
            if key in edge_keys:
                continue
            edge_keys.add(key)

            edges.append(
                DependencyEdge(
                    source_path=item.relative_path,
                    target_path=target_path,
                    relation="imports",
                    confidence="high",
                )
            )

    for edge in edges:
        node_map[edge.source_path].outgoing.append(edge.target_path)
        node_map[edge.target_path].incoming.append(edge.source_path)

    for node in node_map.values():
        node.outgoing = sorted(set(node.outgoing))
        node.incoming = sorted(set(node.incoming))
        node.blast_radius = len(node.incoming) + len(node.outgoing)
        node.risk_tier = _build_risk_tier(node.relative_path, node.blast_radius)

    nodes = sorted(node_map.values(), key=lambda n: n.relative_path)
    edges = sorted(edges, key=lambda e: (e.source_path, e.target_path, e.relation))

    return DependencyGraph(
        project_root=str(Path(project_root).expanduser().resolve()),
        nodes=nodes,
        edges=edges,
    )


def save_dependency_graph(graph: DependencyGraph, output_path: str | Path) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(graph.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


if __name__ == "__main__":
    graph = build_dependency_graph(Path("."))
    print(json.dumps(graph.to_dict(), ensure_ascii=False, indent=2))