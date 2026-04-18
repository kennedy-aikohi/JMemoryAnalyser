from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

@dataclass
class Plugin:
    name: str
    help: str
    backend: str  # "cdb" | "basic" | "hybrid"
    runner: Callable[..., dict]

_REGISTRY: Dict[str, Plugin] = {}

def register(p: Plugin) -> None:
    _REGISTRY[p.name] = p

def list_plugins() -> List[Plugin]:
    return sorted(_REGISTRY.values(), key=lambda x: x.name)

def get_plugin(name: str) -> Optional[Plugin]:
    return _REGISTRY.get(name)
