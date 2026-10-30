/*
    TraceForge core YARA rules
    --------------------------
    Original rules written for the TraceForge project. They detect generic,
    documented techniques and the harmless synthetic test marker used by the
    Meridian training dataset. They contain no commercial or third-party
    malware signatures.

    Required meta fields (validated at load time):
      id, description, severity (info|low|medium|high|critical), explanation
*/

import "pe"
import "math"

rule TF_Synthetic_Test_Marker
{
    meta:
        id = "TF-YARA-001"
        description = "TraceForge synthetic test sample marker"
        severity = "info"
        explanation = "The file contains the marker string embedded in every synthetic TraceForge sample. It proves the file belongs to the training dataset and says nothing about behaviour."
        author = "TraceForge project"
    strings:
        $marker = "TRACEFORGE-SYNTHETIC-TEST-SAMPLE"
        $marker_w = "TRACEFORGE-SYNTHETIC-TEST-SAMPLE" wide
    condition:
        any of them
}

rule TF_PE_Process_Injection_Imports
{
    meta:
        id = "TF-YARA-002"
        description = "PE imports the classic remote-process injection API triad"
        severity = "high"
        explanation = "WriteProcessMemory and CreateRemoteThread together with a memory allocation API allow code to be written into and run inside another process. Debuggers and security tools share this capability, so treat as a strong lead, not proof."
        author = "TraceForge project"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread") and
        (pe.imports("kernel32.dll", "VirtualAllocEx") or pe.imports("kernel32.dll", "VirtualAlloc"))
}

rule TF_PE_WX_HighEntropy_Section
{
    meta:
        id = "TF-YARA-003"
        description = "PE contains a writable+executable section with near-random content"
        severity = "medium"
        explanation = "A section that is both writable and executable and whose entropy exceeds 7.2 bits/byte is typical of packed or encrypted payloads that are decoded in place at run time."
        author = "TraceForge project"
    condition:
        pe.is_pe and
        for any s in pe.sections : (
            (s.characteristics & pe.SECTION_MEM_EXECUTE) != 0 and
            (s.characteristics & pe.SECTION_MEM_WRITE) != 0 and
            s.raw_data_size > 1024 and
            math.entropy(s.raw_data_offset, s.raw_data_size) > 7.2
        )
}

rule TF_Encoded_Hidden_PowerShell
{
    meta:
        id = "TF-YARA-004"
        description = "Hidden-window and/or encoded PowerShell command line"
        severity = "high"
        explanation = "PowerShell launched with -EncodedCommand (or abbreviations such as -enc) and hidden window style conceals the executed script from casual inspection. Some management tooling does this legitimately."
        author = "TraceForge project"
    strings:
        $ps = "powershell" nocase ascii wide
        $enc1 = /\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=%]{4,}/ nocase ascii wide
        $hid = /\s-w(indowstyle)?\s+hidden/ nocase ascii wide
    condition:
        $ps and ($enc1 or $hid)
}

rule TF_Archive_And_Upload_Staging
{
    meta:
        id = "TF-YARA-005"
        description = "Script or binary that both archives files and uploads data over HTTP POST"
        severity = "medium"
        explanation = "The combination of archive creation and an HTTP POST upload is a common data-staging pattern. Backup and sync tools legitimately do the same, so correlate with what was archived and where it was sent."
        author = "TraceForge project"
    strings:
        $a1 = "Compress-Archive" nocase ascii wide
        $a2 = "ZipFile]::CreateFromDirectory" nocase ascii wide
        $u1 = "Invoke-WebRequest" nocase ascii wide
        $u2 = "Invoke-RestMethod" nocase ascii wide
        $post = /-Method\s+Post/ nocase ascii wide
    condition:
        any of ($a*) and any of ($u*) and $post
}

rule TF_Autostart_Persistence_Strings
{
    meta:
        id = "TF-YARA-006"
        description = "References to Run-key or scheduled-task persistence together with an executable path in ProgramData/AppData"
        severity = "medium"
        explanation = "Persistence locations combined with a binary path in a user-writable directory indicate the file may install itself to survive reboots. Legitimate installers also register autostart entries."
        author = "TraceForge project"
    strings:
        $run = "CurrentVersion\\Run" nocase ascii wide
        $task = "schtasks" nocase ascii wide
        $svc = "CreateServiceW" ascii
        $path1 = /C:\\ProgramData\\[^\\\x00]{1,64}\\[^\\\x00]{1,64}\.exe/ nocase ascii wide
        $path2 = /\\AppData\\(Roaming|Local)\\[^\x00]{1,128}\.exe/ nocase ascii wide
    condition:
        (any of ($run, $task, $svc)) and (any of ($path*))
}

rule TF_Sensitive_Document_Targeting
{
    meta:
        id = "TF-YARA-007"
        description = "Hard-coded reference to a confidential document location"
        severity = "low"
        explanation = "A hard-coded path to a folder named Confidential is unusual in general-purpose software and may indicate targeted collection. It is a weak indicator on its own."
        author = "TraceForge project"
    strings:
        $c = "\\Documents\\Confidential" nocase ascii wide
    condition:
        $c
}
