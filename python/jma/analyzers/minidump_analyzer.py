from __future__ import annotations
from typing import Any
from .common import AnalysisResult
from ..utils import get_file_info

def run_minidump(path: str) -> AnalysisResult:
    """
    Uses the optional 'minidump' package.
    Works best on Windows minidumps (.dmp). If not installed, returns a helpful error.
    """
    info = get_file_info(path)
    warnings: list[str] = []
    try:
        from minidump.minidumpfile import MinidumpFile  # type: ignore
    except Exception as e:
        return AnalysisResult(
            analyzer="minidump",
            ok=False,
            summary="Python package 'minidump' not installed. Install it via: pip install minidump",
            details={"file": info.__dict__, "error": str(e)},
            warnings=[],
        )

    try:
        md = MinidumpFile.parse(path)
        sysinfo = getattr(md, "sysinfo", None)
        modules = getattr(md, "modules", None)
        threads = getattr(md, "threads", None)
        ex = getattr(md, "exception", None)

        details: dict[str, Any] = {
            "file": info.__dict__,
            "minidump": {
                "has_sysinfo": sysinfo is not None,
                "has_modules": modules is not None,
                "has_threads": threads is not None,
                "has_exception": ex is not None,
            }
        }

        if sysinfo:
            details["minidump"]["sysinfo"] = {
                "processor_architecture": str(sysinfo.processor_architecture),
                "number_of_processors": sysinfo.number_of_processors,
                "major_version": sysinfo.major_version,
                "minor_version": sysinfo.minor_version,
                "build_number": sysinfo.build_number,
                "platform_id": sysinfo.platform_id,
                "csd_version": sysinfo.csd_version,
            }

        if modules and modules.modules:
            details["minidump"]["module_count"] = len(modules.modules)
            details["minidump"]["modules_preview"] = [
                {
                    "name": m.name,
                    "baseaddress": hex(m.baseaddress),
                    "size": m.size,
                    "version": getattr(m, "version_info", None).to_dict() if getattr(m, "version_info", None) else None,
                }
                for m in modules.modules[:200]
            ]

        if threads and threads.threads:
            details["minidump"]["thread_count"] = len(threads.threads)

        if ex:
            details["minidump"]["exception"] = {
                "exception_code": hex(ex.exception_record.exception_code),
                "exception_flags": hex(ex.exception_record.exception_flags),
                "exception_address": hex(ex.exception_record.exception_address),
            }

        summary = "Parsed minidump successfully."
        if ex:
            summary += f" Exception code: {hex(ex.exception_record.exception_code)}"

        return AnalysisResult(
            analyzer="minidump",
            ok=True,
            summary=summary,
            details=details,
            warnings=warnings,
        )

    except Exception as e:
        return AnalysisResult(
            analyzer="minidump",
            ok=False,
            summary="Failed to parse dump as a minidump.",
            details={"file": info.__dict__, "error": str(e)},
            warnings=["Not all .dmp files are minidumps; Task Manager dumps can vary by type."],
        )
