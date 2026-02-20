from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class PipelineNode:
    node_id: str
    runner: Callable[[dict[str, Any]], dict[str, Any]]
    depends_on: list[str] = field(default_factory=list)


class WorkflowEngine:
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers

    def run(self, nodes: list[PipelineNode], context: dict[str, Any]) -> dict[str, Any]:
        completed: dict[str, dict[str, Any]] = {}
        pending = {n.node_id: n for n in nodes}

        while pending:
            ready = [
                node
                for node in pending.values()
                if all(dep in completed for dep in node.depends_on)
            ]
            if not ready:
                raise RuntimeError("DAG存在循环依赖或缺失依赖")

            if len(ready) == 1:
                node = ready[0]
                completed[node.node_id] = node.runner(context)
                pending.pop(node.node_id, None)
                context["nodes"] = completed
                continue

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                fut_map = {executor.submit(node.runner, context): node for node in ready}
                for fut in as_completed(fut_map):
                    node = fut_map[fut]
                    completed[node.node_id] = fut.result()
                    pending.pop(node.node_id, None)
                    context["nodes"] = completed

        return completed
