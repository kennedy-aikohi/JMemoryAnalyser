from __future__ import annotations

import struct
from typing import Any

from .common import AnalysisResult
from ..utils import get_file_info, probe_dmp_format

# ---------------------------------------------------------------------------
# Minidump stream type constants (MINIDUMP_STREAM_TYPE)
# ---------------------------------------------------------------------------
_STREAM_TYPES: dict[int, str] = {
    0:  "UnusedStream",
    1:  "ReservedStream0",
    2:  "ReservedStream1",
    3:  "ThreadListStream",
    4:  "ModuleListStream",
    5:  "MemoryListStream",
    6:  "ExceptionStream",
    7:  "SystemInfoStream",
    8:  "ThreadExListStream",
    9:  "Memory64ListStream",
    10: "CommentStreamA",
    11: "CommentStreamW",
    12: "HandleDataStream",
    13: "FunctionTableStream",
    14: "UnloadedModuleListStream",
    15: "MiscInfoStream",
    16: "MemoryInfoListStream",
    17: "ThreadInfoListStream",
    18: "HandleOperationListStream",
    19: "TokenStream",
    21: "JavaScriptDataStream",
    22: "SystemMemoryInfoStream",
    23: "ProcessVmCountersStream",
}

# Exception codes
_EXCEPTION_CODES: dict[int, str] = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC0000025: "NONCONTINUABLE_EXCEPTION",
    0xC0000034: "OBJECT_NOT_FOUND",
    0xC000008C: "ARRAY_BOUNDS_EXCEEDED",
    0xC000008D: "FLOAT_DENORMAL_OPERAND",
    0xC000008E: "FLOAT_DIVIDE_BY_ZERO",
    0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
    0xC0000096: "PRIVILEGED_INSTRUCTION",
    0xC00000FD: "STACK_OVERFLOW",
    0xC0000409: "STACK_BUFFER_OVERRUN",
    0x80000003: "BREAKPOINT",
    0x80000004: "SINGLE_STEP",
    0xC0000374: "HEAP_CORRUPTION",
}


def _read_minidump_header(data: bytes) -> dict[str, Any] | None:
    """
    Parse MINIDUMP_HEADER (32 bytes):
      ULONG32  Signature;         // "MDMP" == 0x504D444D
      ULONG32  Version;           // Low 16 bits = version, high 16 = impl version
      ULONG32  NumberOfStreams;
      RVA      StreamDirectoryRva;
      ULONG32  CheckSum;
      ULONG32  TimeDateStamp;     // Unix timestamp
      ULONG64  Flags;
    """
    if len(data) < 32:
        return None
    sig, version, num_streams, dir_rva, checksum, timestamp, flags = struct.unpack_from("<4sIIIIIQ", data, 0)
    if sig != b"MDMP":
        return None
    ver_low  = version & 0xFFFF
    ver_high = (version >> 16) & 0xFFFF
    return {
        "signature": sig.decode("ascii"),
        "version_low": ver_low,
        "version_high": ver_high,
        "num_streams": num_streams,
        "stream_directory_rva": hex(dir_rva),
        "checksum": hex(checksum),
        "timestamp_unix": timestamp,
        "flags_hex": hex(flags),
        "_dir_rva_int": dir_rva,
        "_num_streams_int": num_streams,
    }


def _read_stream_directory(data: bytes, dir_rva: int, num_streams: int) -> list[dict]:
    """
    Parse MINIDUMP_DIRECTORY entries (12 bytes each):
      ULONG32  StreamType;
      ULONG32  DataSize;
      RVA      Rva;
    """
    entries = []
    off = dir_rva
    for _ in range(num_streams):
        if off + 12 > len(data):
            break
        stream_type, data_size, rva = struct.unpack_from("<III", data, off)
        name = _STREAM_TYPES.get(stream_type, f"UnknownStream_{stream_type}")
        entries.append({
            "stream_type": stream_type,
            "stream_name": name,
            "data_size": data_size,
            "rva": hex(rva),
            "_rva_int": rva,
        })
        off += 12
    return entries


def _read_system_info(data: bytes, rva: int, size: int) -> dict[str, Any]:
    """
    Parse MINIDUMP_SYSTEM_INFO (56 bytes):
      USHORT ProcessorArchitecture;
      USHORT ProcessorLevel;
      USHORT ProcessorRevision;
      UCHAR  NumberOfProcessors;
      UCHAR  ProductType;
      ULONG  MajorVersion;
      ULONG  MinorVersion;
      ULONG  BuildNumber;
      ULONG  PlatformId;
      RVA    CSDVersionRva;
      USHORT SuiteMask;
      USHORT Reserved2;
      ... CPU info union (12 bytes)
    """
    _ARCH = {0: "x86", 5: "ARM", 6: "IA-64", 9: "x64/AMD64", 12: "ARM64", 0xFFFF: "UNKNOWN"}
    _PRODUCT = {1: "Workstation", 2: "DomainController", 3: "Server"}
    if rva + 56 > len(data):
        return {"error": "SystemInfoStream truncated"}
    arch, lvl, rev, num_procs, product_type, major, minor, build, platform, csd_rva, suite = struct.unpack_from(
        "<HHHBBIIIIIHxxxxxx", data, rva
    )
    result: dict[str, Any] = {
        "processor_architecture": _ARCH.get(arch, f"arch_{arch}"),
        "processor_level": lvl,
        "number_of_processors": num_procs,
        "product_type": _PRODUCT.get(product_type, f"type_{product_type}"),
        "major_version": major,
        "minor_version": minor,
        "build_number": build,
        "platform_id": platform,
        "suite_mask_hex": hex(suite),
        "windows_version_string": f"{major}.{minor}.{build}",
    }
    # Resolve CSD version (Service Pack) string
    if csd_rva and csd_rva + 4 <= len(data):
        try:
            sp_len = struct.unpack_from("<I", data, csd_rva)[0]
            sp_str = data[csd_rva + 4: csd_rva + 4 + sp_len]
            result["csd_version"] = sp_str.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            result["csd_version"] = None
    return result


def _read_exception(data: bytes, rva: int, size: int) -> dict[str, Any]:
    """
    Parse MINIDUMP_EXCEPTION_STREAM:
      ULONG32 ThreadId;
      ULONG32 __alignment;
      MINIDUMP_EXCEPTION ExceptionRecord;   // 152 bytes on x64
        ULONG32 ExceptionCode;
        ULONG32 ExceptionFlags;
        ULONG64 ExceptionRecord (ptr);
        ULONG64 ExceptionAddress;
        ULONG32 NumberParameters;
        ULONG32 __unusedAlignment;
        ULONG64 ExceptionInformation[15];
    """
    if rva + 8 > len(data):
        return {"error": "ExceptionStream truncated"}
    thread_id = struct.unpack_from("<I", data, rva)[0]
    ex_off = rva + 8
    if ex_off + 168 > len(data):
        return {"thread_id": hex(thread_id), "error": "ExceptionRecord truncated"}
    exc_code, exc_flags = struct.unpack_from("<II", data, ex_off)
    exc_addr = struct.unpack_from("<Q", data, ex_off + 16)[0]
    code_name = _EXCEPTION_CODES.get(exc_code, "UNKNOWN_EXCEPTION")
    return {
        "thread_id": hex(thread_id),
        "exception_code_hex": hex(exc_code),
        "exception_code_name": code_name,
        "exception_flags_hex": hex(exc_flags),
        "exception_address_hex": hex(exc_addr),
    }


def _read_module_list(data: bytes, rva: int, size: int) -> list[dict[str, Any]]:
    """
    MINIDUMP_MODULE_LIST:
      ULONG32 NumberOfModules;
      MINIDUMP_MODULE Modules[NumberOfModules];  // each 108 bytes
    MINIDUMP_MODULE:
      ULONG64 BaseOfImage;
      ULONG32 SizeOfImage;
      ULONG32 CheckSum;
      ULONG32 TimeDateStamp;
      RVA     ModuleNameRva;
      ... VS_FIXEDFILEINFO (52 bytes) ...
      ... MINIDUMP_LOCATION_DESCRIPTOR CvRecord (8 bytes) ...
      ... MINIDUMP_LOCATION_DESCRIPTOR MiscRecord (8 bytes) ...
      ULONG64 Reserved0;
      ULONG64 Reserved1;
    """
    if rva + 4 > len(data):
        return []
    num_mods = struct.unpack_from("<I", data, rva)[0]
    modules = []
    off = rva + 4
    MODULE_SIZE = 108
    for _ in range(min(num_mods, 512)):
        if off + MODULE_SIZE > len(data):
            break
        base, size_img, checksum, timestamp, name_rva = struct.unpack_from("<QIIIII", data, off)
        # Read module name (UTF-16LE, prefixed by ULONG32 byte-length)
        mod_name = ""
        if name_rva and name_rva + 4 <= len(data):
            try:
                name_len = struct.unpack_from("<I", data, name_rva)[0]
                name_bytes = data[name_rva + 4: name_rva + 4 + name_len]
                mod_name = name_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
            except Exception:
                pass
        modules.append({
            "name": mod_name,
            "base_address": hex(base),
            "size": size_img,
            "checksum_hex": hex(checksum),
            "timestamp_unix": timestamp,
        })
        off += MODULE_SIZE
    return modules


def _read_thread_list(data: bytes, rva: int, size: int) -> list[dict[str, Any]]:
    """
    MINIDUMP_THREAD_LIST:
      ULONG32 NumberOfThreads;
      MINIDUMP_THREAD Threads[];   // each 48 bytes
    MINIDUMP_THREAD:
      ULONG32 ThreadId;
      ULONG32 SuspendCount;
      ULONG32 PriorityClass;
      ULONG32 Priority;
      ULONG64 Teb;
      MINIDUMP_MEMORY_DESCRIPTOR Stack (12 bytes);
      MINIDUMP_LOCATION_DESCRIPTOR ThreadContext (8 bytes);
    """
    if rva + 4 > len(data):
        return []
    num_threads = struct.unpack_from("<I", data, rva)[0]
    threads = []
    off = rva + 4
    THREAD_SIZE = 48
    for _ in range(min(num_threads, 2048)):
        if off + THREAD_SIZE > len(data):
            break
        tid, suspend, pri_class, priority, teb = struct.unpack_from("<IIIIq", data, off)
        threads.append({
            "thread_id": hex(tid),
            "suspend_count": suspend,
            "priority_class": pri_class,
            "priority": priority,
            "teb_address": hex(teb),
        })
        off += THREAD_SIZE
    return threads


def run_minidump(path: str) -> AnalysisResult:
    """
    Native Python MDMP parser - no external dependencies required.
    Falls back to the 'minidump' package for deeper analysis if available.
    """
    info = get_file_info(path)
    fmt  = probe_dmp_format(path)
    warnings: list[str] = []

    if not fmt.is_minidump:
        warnings.append(f"DMP format: {fmt.format}. {fmt.note}")
        if fmt.is_full_dump:
            warnings.append("Full dump detected. minidump mode works best on MDMP (Task Manager) dumps. "
                            "Consider Volatility for full images.")

    # -----------------------------------------------------------------------
    # Native parse path (no external deps)
    # -----------------------------------------------------------------------
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return AnalysisResult(
            analyzer="minidump",
            ok=False,
            summary=f"Cannot read file: {e}",
            details={"file": info.__dict__},
            warnings=warnings,
        )

    header = _read_minidump_header(data)
    if not header:
        return AnalysisResult(
            analyzer="minidump",
            ok=False,
            summary="File does not have a valid MDMP header (not a Windows minidump).",
            details={"file": info.__dict__, "format": fmt.__dict__},
            warnings=warnings,
        )

    streams = _read_stream_directory(data, header["_dir_rva_int"], header["_num_streams_int"])
    stream_names = [s["stream_name"] for s in streams]

    details: dict[str, Any] = {
        "file": {**info.__dict__, "format": fmt.__dict__},
        "header": {k: v for k, v in header.items() if not k.startswith("_")},
        "streams_present": stream_names,
        "stream_directory": streams,
    }

    # Parse specific streams
    for entry in streams:
        stype = entry["stream_type"]
        rva   = entry["_rva_int"]
        ssize = entry["data_size"]

        if stype == 7:   # SystemInfoStream
            details["system_info"] = _read_system_info(data, rva, ssize)

        elif stype == 6:  # ExceptionStream
            details["exception"] = _read_exception(data, rva, ssize)

        elif stype == 4:  # ModuleListStream
            mods = _read_module_list(data, rva, ssize)
            details["modules"] = {
                "count": len(mods),
                "modules": mods[:200],
            }

        elif stype == 3:  # ThreadListStream
            threads = _read_thread_list(data, rva, ssize)
            details["threads"] = {
                "count": len(threads),
                "threads": threads,
            }

        elif stype == 15:  # MiscInfoStream - contains PID, process times
            if rva + 24 <= len(data):
                misc_size, flags1, pid = struct.unpack_from("<III", data, rva)
                details["misc_info"] = {
                    "size": misc_size,
                    "flags1_hex": hex(flags1),
                    "process_id": pid if (flags1 & 0x1) else None,
                }

    # Build summary string
    sysinfo_str = ""
    if "system_info" in details:
        si = details["system_info"]
        sysinfo_str = (
            f" OS={si.get('windows_version_string','')} {si.get('processor_architecture','')} "
            f"x{si.get('number_of_processors','')}CPUs"
        )

    exc_str = ""
    if "exception" in details:
        ex = details["exception"]
        exc_str = f" Exception={ex.get('exception_code_name','')}({ex.get('exception_code_hex','')})"

    mod_count = details.get("modules", {}).get("count", 0)
    thr_count = details.get("threads", {}).get("count", 0)

    summary = (
        f"MDMP parsed OK.{sysinfo_str}{exc_str} "
        f"Streams={len(streams)}, Modules={mod_count}, Threads={thr_count}."
    )

    # -----------------------------------------------------------------------
    # Opportunistic: try the 'minidump' package for extra data
    # -----------------------------------------------------------------------
    try:
        from minidump.minidumpfile import MinidumpFile  # type: ignore
        md = MinidumpFile.parse(path)
        pkg_extra: dict[str, Any] = {"package": "minidump", "available": True}

        pkg_mods = getattr(md, "modules", None)
        if pkg_mods and getattr(pkg_mods, "modules", None):
            pkg_extra["module_names"] = [m.name for m in pkg_mods.modules[:200] if m.name]

        details["minidump_package"] = pkg_extra
    except ImportError:
        details["minidump_package"] = {"available": False, "note": "pip install minidump for extra data"}
    except Exception as e:
        details["minidump_package"] = {"available": True, "error": str(e)}

    return AnalysisResult(
        analyzer="minidump",
        ok=True,
        summary=summary,
        details=details,
        warnings=warnings,
    )
