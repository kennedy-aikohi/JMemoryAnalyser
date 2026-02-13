from __future__ import annotations
from .cdb_plugins import register_all as _reg_cdb
from .yara_plugin import register_all as _reg_yara

def init_plugins() -> None:
    _reg_cdb()
    _reg_yara()
