"""Static analysis of Windows PE files.

Nothing in this module executes, loads or emulates the sample. ``pefile`` is
used purely as a structure parser on bytes read from disk.

Every indicator produced here carries:

* a stable ``id`` so it can be documented and tested,
* a ``classification`` (``suspicious`` / ``informational`` / ``inconclusive``),
* a ``rationale`` explaining *why* it was raised and what benign explanations exist.

No combination of indicators is reported as "malicious". The overall
assessment summarises evidence for an analyst; it is not a verdict.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pefile

from .entropy import describe_entropy, shannon_entropy
from .filetype import detect_bytes
from .hashing import hash_file
from .strings import categorise, extract_strings

ENGINE_VERSION = "pe-1.0"

MACHINE_TYPES = {0x14C: "x86 (i386)", 0x8664: "x64 (AMD64)", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA-64"}
SUBSYSTEMS = {1: "Native", 2: "Windows GUI", 3: "Windows console", 9: "Windows CE GUI", 10: "EFI application"}
STANDARD_SECTIONS = {".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata", ".idata", ".edata", ".tls",
                     ".bss", ".crt", ".didat", ".gfids", ".00cfg", "CODE", "DATA", "BSS", ".CRT", ".xdata"}
PACKER_SECTIONS = {"UPX0": "UPX", "UPX1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".petite": "Petite",
                   ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS", ".themida": "Themida", ".vmp0": "VMProtect",
                   ".vmp1": "VMProtect", ".nsp0": "NsPack", ".enigma1": "Enigma"}

# API -> (category, explanation). Presence of an API is never proof of intent:
# most of these are used by legitimate software too.
SUSPICIOUS_APIS: dict[str, tuple[str, str]] = {
    "VirtualAllocEx": ("process_injection", "Allocates memory in another process"),
    "WriteProcessMemory": ("process_injection", "Writes into another process's memory"),
    "CreateRemoteThread": ("process_injection", "Starts a thread inside another process"),
    "NtCreateThreadEx": ("process_injection", "Undocumented remote thread creation"),
    "QueueUserAPC": ("process_injection", "Queues code for execution in another thread"),
    "SetThreadContext": ("process_injection", "Changes a thread's register state (process hollowing)"),
    "OpenProcess": ("process_access", "Obtains a handle to another process"),
    "VirtualAlloc": ("memory", "Allocates memory; combined with VirtualProtect may indicate unpacking"),
    "VirtualProtect": ("memory", "Changes memory protection, e.g. making data executable"),
    "LoadLibraryA": ("dynamic_resolution", "Loads libraries at runtime; can hide imports from static analysis"),
    "LoadLibraryW": ("dynamic_resolution", "Loads libraries at runtime; can hide imports from static analysis"),
    "GetProcAddress": ("dynamic_resolution", "Resolves functions at runtime; can hide imports from static analysis"),
    "IsDebuggerPresent": ("anti_analysis", "Checks for an attached debugger (also common in benign CRT code)"),
    "CheckRemoteDebuggerPresent": ("anti_analysis", "Checks for a remote debugger"),
    "GetTickCount": ("anti_analysis", "Timing source sometimes used for sandbox evasion (very common)"),
    "InternetOpenW": ("network", "Initialises WinINet HTTP client"),
    "InternetOpenA": ("network", "Initialises WinINet HTTP client"),
    "InternetConnectW": ("network", "Opens an HTTP/FTP session to a server"),
    "InternetConnectA": ("network", "Opens an HTTP/FTP session to a server"),
    "HttpOpenRequestW": ("network", "Builds an HTTP request"),
    "HttpSendRequestW": ("network", "Sends an HTTP request"),
    "InternetReadFile": ("network", "Downloads data over HTTP"),
    "URLDownloadToFileW": ("network", "Downloads a URL directly to disk"),
    "URLDownloadToFileA": ("network", "Downloads a URL directly to disk"),
    "WinHttpOpen": ("network", "Initialises WinHTTP client"),
    "WSAStartup": ("network", "Initialises Winsock"),
    "RegSetValueExW": ("persistence", "Writes a registry value (e.g. Run keys)"),
    "RegSetValueExA": ("persistence", "Writes a registry value (e.g. Run keys)"),
    "RegCreateKeyExW": ("persistence", "Creates a registry key"),
    "CreateServiceW": ("persistence", "Installs a Windows service"),
    "CreateServiceA": ("persistence", "Installs a Windows service"),
    "OpenSCManagerW": ("persistence", "Opens the service control manager"),
    "ShellExecuteW": ("execution", "Launches a program or document"),
    "WinExec": ("execution", "Launches a program"),
    "CreateProcessW": ("execution", "Launches a program"),
    "CryptEncrypt": ("crypto", "Encrypts data with CryptoAPI"),
    "BCryptEncrypt": ("crypto", "Encrypts data with CNG"),
    "SetWindowsHookExW": ("collection", "Installs a system hook (used by keyloggers and accessibility tools)"),
    "GetAsyncKeyState": ("collection", "Polls keyboard state"),
    "AdjustTokenPrivileges": ("privilege", "Enables privileges on an access token"),
}

DOUBLE_EXTENSION = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|zip|rtf|csv)\.(exe|scr|com|pif|bat|cmd|js|vbs)$", re.I)


def _indicator(ind_id: str, title: str, classification: str, severity: str, confidence: str,
               rationale: str, evidence: Any = None) -> dict[str, Any]:
    return {"id": ind_id, "title": title, "classification": classification, "severity": severity,
            "confidence": confidence, "rationale": rationale, "evidence": evidence}


def _section_flags(characteristics: int) -> list[str]:
    flags = []
    if characteristics & 0x20:
        flags.append("CODE")
    if characteristics & 0x40:
        flags.append("INITIALIZED_DATA")
    if characteristics & 0x80:
        flags.append("UNINITIALIZED_DATA")
    if characteristics & 0x20000000:
        flags.append("EXECUTE")
    if characteristics & 0x40000000:
        flags.append("READ")
    if characteristics & 0x80000000:
        flags.append("WRITE")
    return flags


def analyze_pe(path: Path, original_filename: str = "", now: datetime | None = None) -> dict[str, Any]:
    """Statically analyse the PE file at ``path``. ``path`` is only ever opened for reading."""
    now = now or datetime.now(timezone.utc)
    data = path.read_bytes()
    hashes = hash_file(path)
    detected = detect_bytes(data[:65536], len(data))
    file_entropy = shannon_entropy(data)
    result: dict[str, Any] = {
        "engine_version": ENGINE_VERSION,
        "file": {
            "original_filename": original_filename,
            "size_bytes": hashes.size,
            "sha256": hashes.sha256,
            "sha1": hashes.sha1,
            "md5": hashes.md5,
            "detected_type": detected.description,
            "entropy": round(file_entropy, 4),
            "entropy_assessment": describe_entropy(file_entropy),
        },
        "pe": None,
        "sections": [],
        "imports": [],
        "exports": [],
        "suspicious_apis": [],
        "strings": {},
        "indicators": [],
        "parse_warnings": [],
        "errors": [],
    }
    indicators: list[dict[str, Any]] = result["indicators"]

    if original_filename and DOUBLE_EXTENSION.search(original_filename):
        indicators.append(_indicator(
            "PE-001", "Executable disguised with a document-style double extension", "suspicious", "high", "high",
            f"The filename '{original_filename}' ends in a document extension followed by an executable extension. "
            "Windows hides known extensions by default, so users may see only the document-like part. "
            "This is a common social-engineering technique; legitimate software rarely uses it.",
            original_filename,
        ))

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        result["errors"].append(f"PE parsing failed: {exc}")
        indicators.append(_indicator("PE-000", "PE structure could not be parsed", "inconclusive", "low", "high",
                                     "The file has an MZ header but its PE structure is malformed or truncated. "
                                     "Static results are incomplete.", str(exc)))
        result["assessment"] = _assess(indicators, parse_failed=True)
        return result

    try:
        result["parse_warnings"] = pe.get_warnings()[:25]
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        compile_ts = datetime.fromtimestamp(fh.TimeDateStamp, tz=timezone.utc) if fh.TimeDateStamp else None
        entry = oh.AddressOfEntryPoint
        entry_section = next((s.Name.rstrip(b"\x00").decode("latin-1") for s in pe.sections
                              if s.contains_rva(entry)), None)
        overlay_offset = pe.get_overlay_data_start_offset()
        overlay = data[overlay_offset:] if overlay_offset else b""
        stored_checksum = oh.CheckSum
        computed_checksum = pe.generate_checksum()
        result["pe"] = {
            "machine": MACHINE_TYPES.get(fh.Machine, hex(fh.Machine)),
            "is_64bit": oh.Magic == 0x20B,
            "is_dll": bool(fh.Characteristics & 0x2000),
            "compile_timestamp": compile_ts.isoformat() if compile_ts else None,
            "compile_timestamp_raw": fh.TimeDateStamp,
            "subsystem": SUBSYSTEMS.get(oh.Subsystem, str(oh.Subsystem)),
            "entry_point": hex(entry),
            "entry_section": entry_section,
            "image_base": hex(oh.ImageBase),
            "number_of_sections": fh.NumberOfSections,
            "imphash": pe.get_imphash() or None,
            "aslr": bool(oh.DllCharacteristics & 0x40),
            "dep_nx": bool(oh.DllCharacteristics & 0x100),
            "checksum_stored": hex(stored_checksum),
            "checksum_computed": hex(computed_checksum),
            "overlay": {"offset": overlay_offset, "size": len(overlay),
                        "entropy": round(shannon_entropy(overlay), 4)} if overlay else None,
        }

        # ---- sections ------------------------------------------------------
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
            ent = s.get_entropy()
            flags = _section_flags(s.Characteristics)
            notes = []
            if "EXECUTE" in flags and "WRITE" in flags:
                notes.append("writable_and_executable")
            if ent >= 7.2:
                notes.append("high_entropy")
            if name not in STANDARD_SECTIONS:
                notes.append("nonstandard_name")
            if s.SizeOfRawData == 0 and s.Misc_VirtualSize > 0x10000:
                notes.append("virtual_only_large")
            result["sections"].append({
                "name": name, "virtual_address": hex(s.VirtualAddress), "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData, "raw_offset": s.PointerToRawData, "entropy": round(ent, 4),
                "characteristics": hex(s.Characteristics), "flags": flags, "notes": notes,
            })

        # ---- imports / exports -------------------------------------------
        total_imports = 0
        for entry_imp in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry_imp.dll.decode("latin-1", errors="replace")
            funcs = []
            for imp in entry_imp.imports:
                fname = imp.name.decode("latin-1", errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
                funcs.append(fname)
                total_imports += 1
                if fname in SUSPICIOUS_APIS:
                    category, why = SUSPICIOUS_APIS[fname]
                    result["suspicious_apis"].append({"api": fname, "dll": dll, "category": category, "explanation": why})
            result["imports"].append({"dll": dll, "functions": funcs})
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:500]:
                result["exports"].append(exp.name.decode("latin-1", errors="replace") if exp.name else f"ordinal_{exp.ordinal}")

        # ---- strings -------------------------------------------------------
        all_strings = extract_strings(data)
        interesting = categorise(all_strings)
        result["strings"] = {"total_extracted": len(all_strings), "interesting": interesting[:300]}

        _pe_indicators(result, indicators, total_imports, compile_ts, now, stored_checksum, computed_checksum, interesting)
        beyond = [s["name"] for s in result["sections"] if s["raw_offset"] + s["raw_size"] > len(data)]
        if beyond:
            indicators.append(_indicator(
                "PE-015", "PE image is truncated", "inconclusive", "low", "high",
                "Section data declared in the header extends beyond the end of the file, so part of the image is "
                "missing (incomplete download/carving, or deliberate corruption). Results for missing regions are "
                "unavailable.", beyond))
    finally:
        pe.close()

    result["assessment"] = _assess(indicators, parse_failed=any(i["id"] == "PE-015" for i in indicators))
    return result


def _pe_indicators(result, indicators, total_imports, compile_ts, now, stored_checksum, computed_checksum, interesting):
    sections = result["sections"]
    apis = {a["api"] for a in result["suspicious_apis"]}
    categories = {a["category"] for a in result["suspicious_apis"]}

    wx = [s["name"] for s in sections if "writable_and_executable" in s["notes"]]
    if wx:
        indicators.append(_indicator(
            "PE-002", "Section is both writable and executable", "suspicious", "medium", "medium",
            "Sections marked WRITE+EXECUTE allow code to be modified at run time, which packers and "
            "self-modifying loaders rely on. Some legitimate JIT-based or older software also does this.", wx))

    high = [f"{s['name']} ({s['entropy']:.2f})" for s in sections if "high_entropy" in s["notes"]]
    if high:
        indicators.append(_indicator(
            "PE-003", "High-entropy section", "suspicious", "medium", "low",
            "Entropy at or above 7.2 bits/byte indicates compressed or encrypted content, which can hide code "
            "from static analysis. Legitimate installers, compressed resources and media also score this high, "
            "so this indicator alone is weak.", high))

    injection = apis & {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
                        "QueueUserAPC", "SetThreadContext"}
    if len(injection) >= 2 or ({"WriteProcessMemory", "CreateRemoteThread"} <= apis):
        indicators.append(_indicator(
            "PE-004", "Imports consistent with process injection", "suspicious", "high", "medium",
            "The import table combines APIs that write into and start execution inside another process. "
            "Debuggers, security products and some management tools legitimately use the same APIs.",
            sorted(injection | (apis & {"OpenProcess", "VirtualAlloc"}))))

    urls = [s["value"] for s in interesting if s["category"] == "url"]
    if "network" in categories:
        net_apis = sorted(a["api"] for a in result["suspicious_apis"] if a["category"] == "network")
        if urls:
            indicators.append(_indicator(
                "PE-005", "HTTP client APIs together with embedded URLs", "suspicious", "medium", "medium",
                "The binary imports HTTP client functionality and contains hard-coded URLs, so it is able to contact "
                "the listed destinations. Whether it does so, and why, cannot be established statically.",
                {"apis": net_apis, "urls": urls[:10]}))
        else:
            indicators.append(_indicator(
                "PE-005", "HTTP client APIs imported", "informational", "low", "high",
                "The binary can make HTTP requests. Very common in legitimate software (updaters, telemetry).",
                {"apis": net_apis}))

    persist = sorted(a["api"] for a in result["suspicious_apis"] if a["category"] == "persistence")
    persist_strings = [s["value"] for s in interesting if s["category"] == "persistence"]
    if persist and persist_strings:
        indicators.append(_indicator(
            "PE-006", "Persistence capability (service/registry APIs with autostart references)", "suspicious",
            "medium", "medium",
            "Service-installation or registry-write APIs are imported and the strings reference autostart "
            "locations or scheduled-task tooling. Installers legitimately do this; context is required.",
            {"apis": persist, "strings": persist_strings[:10]}))
    elif persist:
        indicators.append(_indicator(
            "PE-006", "Service or registry modification APIs imported", "informational", "low", "medium",
            "Registry/service APIs are common in legitimate software.", {"apis": persist}))

    if apis & {"IsDebuggerPresent", "CheckRemoteDebuggerPresent"}:
        indicators.append(_indicator(
            "PE-007", "Debugger detection API imported", "informational", "low", "high",
            "Debugger checks are inserted by many compilers' runtime libraries; noted for context only.",
            sorted(apis & {"IsDebuggerPresent", "CheckRemoteDebuggerPresent"})))

    odd = [s["name"] for s in sections if "nonstandard_name" in s["notes"]]
    packers = sorted({PACKER_SECTIONS[n] for n in odd if n in PACKER_SECTIONS})
    if packers:
        indicators.append(_indicator(
            "PE-008", f"Section names associated with known packers: {', '.join(packers)}", "suspicious", "medium",
            "medium", "Packers compress or obfuscate code. They are used by malware and by legitimate vendors.", odd))
    elif odd:
        indicators.append(_indicator(
            "PE-008", "Non-standard section names", "informational", "low", "medium",
            "Section names outside the usual compiler set can indicate custom tooling or packing; they can also be "
            "produced by less common compilers.", odd))

    overlay = result["pe"]["overlay"]
    if overlay:
        sev, cls = ("low", "suspicious") if overlay["entropy"] >= 7.2 else ("info", "informational")
        indicators.append(_indicator(
            "PE-009", "Data appended after the last section (overlay)", cls, sev, "high",
            "Overlays are used by installers and signed binaries (certificate tables) but also to carry "
            f"encrypted payloads or configuration. Overlay size {overlay['size']} bytes, entropy {overlay['entropy']}.",
            overlay))

    if compile_ts is None:
        indicators.append(_indicator("PE-010", "Compile timestamp is zero", "inconclusive", "info", "medium",
                                     "Zeroed timestamps occur with reproducible builds and with deliberate tampering.", None))
    elif compile_ts > now:
        indicators.append(_indicator("PE-010", "Compile timestamp is in the future", "suspicious", "low", "medium",
                                     "The PE header timestamp is later than the analysis time, suggesting it was "
                                     "forged or the build clock was wrong.", compile_ts.isoformat()))
    else:
        indicators.append(_indicator("PE-010", "Compile timestamp recorded", "informational", "info", "low",
                                     "The PE timestamp is trivially forgeable; it is recorded for context and is not "
                                     "used for timeline reconstruction.", compile_ts.isoformat()))

    ps = [s["value"] for s in interesting if s["category"] == "powershell"]
    if any(re.search(r"-enc|-w(?:indowstyle)?\s+hidden", v, re.I) for v in ps):
        indicators.append(_indicator(
            "PE-011", "Embedded hidden/encoded PowerShell command line", "suspicious", "high", "medium",
            "A string builds a PowerShell command line with hidden window and/or encoded command options. Encoded "
            "commands obscure what is executed and are frequently abused; some administrative tools also use them.",
            ps[:5]))

    if total_imports and total_imports < 6 and any("high_entropy" in s["notes"] for s in sections):
        indicators.append(_indicator(
            "PE-012", "Very small import table combined with high-entropy data", "suspicious", "medium", "medium",
            "Packed executables often import only a loader stub's worth of functions and resolve the rest at "
            "run time.", total_imports))

    if stored_checksum and stored_checksum != computed_checksum:
        indicators.append(_indicator(
            "PE-013", "PE checksum mismatch", "informational", "info", "medium",
            "The optional-header checksum is only enforced for drivers and some system DLLs; a mismatch indicates "
            "the file was modified after linking.", {"stored": hex(stored_checksum), "computed": hex(computed_checksum)}))

    ips = [s["value"] for s in interesting if s["category"] == "ipv4"]
    if urls or ips:
        indicators.append(_indicator(
            "PE-014", "Network indicators embedded in strings", "informational", "info", "high",
            "Hard-coded URLs and IP addresses are extracted as potential IOCs. Their presence does not show they "
            "were contacted; correlate with network evidence.", {"urls": urls[:10], "ipv4": ips[:10]}))


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _assess(indicators: list[dict[str, Any]], parse_failed: bool) -> dict[str, Any]:
    suspicious = [i for i in indicators if i["classification"] == "suspicious"]
    max_sev = max((SEVERITY_ORDER[i["severity"]] for i in suspicious), default=0)
    if parse_failed:
        label = "inconclusive"
        summary = ("PE structure could not be fully parsed or the image is truncated; static results are incomplete"
                   + (f" ({len(suspicious)} suspicious indicator(s) were still observed)." if suspicious else "."))
    elif max_sev >= 3 and len(suspicious) >= 3:
        label = "suspicious_high"
        summary = (f"{len(suspicious)} suspicious indicators including high-severity traits. This does not prove "
                   "malicious intent; it justifies prioritised dynamic analysis in an isolated environment and "
                   "correlation with host and network evidence.")
    elif suspicious:
        label = "suspicious"
        summary = f"{len(suspicious)} suspicious indicator(s). Context from other evidence is required."
    else:
        label = "no_suspicious_indicators"
        summary = ("No suspicious static indicators were raised. Static analysis cannot prove a file is benign "
                   "(packing, staged payloads and runtime behaviour are invisible to it).")
    return {
        "label": label,
        "summary": summary,
        "suspicious_count": len(suspicious),
        "informational_count": sum(1 for i in indicators if i["classification"] == "informational"),
        "inconclusive_count": sum(1 for i in indicators if i["classification"] == "inconclusive"),
    }
