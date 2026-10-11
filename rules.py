"""Detection content for ransomware investigations on Windows hosts."""
import ipaddress
import re

# ------------------------------------------------------------ command rules ---
# (id, severity, category, title, regex)
CMD_RULES = [
    ("shadow-delete", "high", "anti-recovery", "Shadow copies deleted",
     r"vssadmin(\.exe)?\s+delete\s+shadows|vssadmin(\.exe)?\s+resize\s+shadowstorage|shadowcopy\s+delete|win32_shadowcopy.*(delete|remove)|Get-WmiObject\s+Win32_Shadowcopy|vssadmin.*delete"),
    ("backup-delete", "high", "anti-recovery", "Backups / catalog deleted",
     r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)|wbadmin.*-quiet"),
    ("recovery-off", "high", "anti-recovery", "Windows recovery disabled",
     r"bcdedit(\.exe)?.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures|safeboot)|reagentc(\.exe)?\s+/disable"),
    ("usn-delete", "high", "anti-forensics", "USN journal deleted", r"fsutil(\.exe)?\s+usn\s+deletejournal"),
    ("log-clear", "high", "anti-forensics", "Event log cleared",
     r"wevtutil(\.exe)?\s+(cl|clear-log)\b|Clear-EventLog|Remove-EventLog|Limit-EventLog.*-MaximumSize"),
    ("wipe", "high", "anti-forensics", "Free space / file wiping",
     r"cipher(\.exe)?\s+/w|sdelete(64)?(\.exe)?|\bformat(\.com)?\s+[a-z]:"),
    ("defender-off", "high", "defense-evasion", "Microsoft Defender disabled / weakened",
     r"Set-MpPreference\s+.*-Disable\w+\s+(\$true|1)|DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|DisableIOAVProtection|MpCmdRun.*-RemoveDefinitions|sc(\.exe)?\s+(stop|delete|config)\s+(windefend|sense|wdboot|wdfilter|wdnissvc)"),
    ("defender-exclusion", "high", "defense-evasion", "Defender exclusion added",
     r"Add-MpPreference\s+.*-Exclusion(Path|Process|Extension|IpAddress)|Windows Defender\\Exclusions"),
    ("av-kill", "high", "defense-evasion", "Security tools / services killed",
     r"taskkill.*(/im|/f).*(msmpeng|sophos|mcshield|ekrn|avp|savservice|sentinel|cb\.exe|csfalcon|bdagent|ntrtscan|tmlisten)|net\s+stop\s+.*(sophos|mcafee|sentinel|symantec|defend|kaspersky|eset|veeam|backup|vss|sql)"),
    ("svc-stop-mass", "medium", "impact", "Services stopped (backup, database, mail)",
     r"(net1?|sc)(\.exe)?\s+(stop|config)\s+\"?(vss|sql|msexchange|veeam|backup|memtas|mepocs|sophos|svc\$|sql\w*|oracle|ocssd|dbsnmp|synctime|agntsvc|isqlplussvc|xfssvccon|mydesktop|ocautoupds|encsvc|firefox|tbirdconfig|mydesktopqos|ocomm|dbeng50|sqbcoreservice|excel|infopath|msaccess|mspub|onenote|outlook|powerpnt|steam|thebat|thunderbird|visio|winword|wordpad|notepad)"),
    ("taskkill-mass", "medium", "impact", "Applications force-closed (files unlocked for encryption)",
     r"taskkill(\.exe)?\s+.*/f.*/im\s+\"?(sql|oracle|ocssd|dbsnmp|winword|excel|outlook|onenote|thunderbird|firefox|steam|visio|powerpnt)"),
    ("icacls-grant", "medium", "impact", "Permissions opened on whole drive",
     r"icacls(\.exe)?\s+\"?[a-z]:\\?\*?\"?\s+/grant\s+\"?Everyone:F|icacls.*/grant\s+Everyone:\(?F|takeown(\.exe)?\s+/f\s+[a-z]:\\.*\/r"),
    ("symlink-eval", "medium", "impact", "Remote symlink evaluation enabled (encrypt network shares)",
     r"fsutil(\.exe)?\s+behavior\s+set\s+SymlinkEvaluation\s+R2L:1|R2R:1"),
    ("linked-conn", "medium", "impact", "EnableLinkedConnections (mapped drives visible to elevated ransomware)",
     r"EnableLinkedConnections"),
    ("mountvol", "low", "impact", "Hidden volumes mounted", r"mountvol(\.exe)?\s+[a-z]:\s+\\\\\?\\Volume"),
    ("firewall-off", "medium", "defense-evasion", "Firewall disabled or rule added",
     r"netsh(\.exe)?\s+(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+disable|advfirewall\s+firewall\s+add\s+rule)|Set-NetFirewallProfile.*-Enabled\s+False"),
    ("rdp-enable", "medium", "lateral-movement", "RDP enabled from command line",
     r"fDenyTSConnections.*/d\s+0|fDenyTSConnections.*0|Set-ItemProperty.*Terminal Server.*fDenyTSConnections|netsh.*remote ?desktop.*enable"),
    ("wdigest", "high", "credential-access", "WDigest plaintext credentials enabled", r"UseLogonCredential.*(/d\s+1|1)"),
    ("lsass-dump", "high", "credential-access", "LSASS memory dump",
     r"comsvcs(\.dll)?[,#\s]+(MiniDump|#\s*24)|procdump(64)?(\.exe)?\s+.*(-ma\s+)?lsass|sekurlsa::|mimikatz|lsass\.(dmp|zip)|nanodump|pypykatz|Out-Minidump"),
    ("ntds", "high", "credential-access", "NTDS / SAM hive dumped",
     r"ntdsutil.*(ifm|snapshot)|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)|copy.*\\(ntds\.dit|config\\sam)"),
    ("psexec", "medium", "lateral-movement", "PsExec-style remote execution",
     r"\b(psexec|paexec|psexesvc|remcom|csexec)(64)?(\.exe)?\b|\\\\[^\\\s]+\\(admin|c|ipc)\$"),
    ("wmic-remote", "medium", "lateral-movement", "WMIC remote process creation", r"wmic(\.exe)?\s+/node:.*process\s+call\s+create"),
    ("winrm", "low", "lateral-movement", "Remote PowerShell / WinRM", r"Invoke-Command\s+.*-ComputerName|Enter-PSSession|winrs(\.exe)?\s"),
    ("discovery-ad", "medium", "discovery", "Active Directory discovery",
     r"\badfind(\.exe)?\b|nltest(\.exe)?\s+/(dclist|domain_trusts|dsgetdc)|net1?(\.exe)?\s+group\s+\"?(domain admins|enterprise admins|domain computers)|Get-AD(Computer|User|Group)|sharphound|bloodhound|dsquery"),
    ("discovery-net", "low", "discovery", "Network / host discovery",
     r"net1?(\.exe)?\s+view|net1?(\.exe)?\s+(user|localgroup)\s|arp\s+-a|nbtstat|\bquser\b|\bqwinsta\b|systeminfo|whoami\s+/(all|groups|priv)|netscan|advanced_?ip_?scanner|angry ?ip|\bnmap\b|masscan|softperfect"),
    ("ps-encoded", "medium", "execution", "Encoded / hidden PowerShell",
     r"powershell(\.exe)?.*\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand|ec)\s+[A-Za-z0-9+/=]{16,}|-w(indowstyle)?\s+hidden|FromBase64String|IEX\s*\(|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|iwr\s+http|bitsadmin(\.exe)?\s+/transfer|certutil(\.exe)?\s+.*-(urlcache|decode)"),
    ("lolbin", "low", "execution", "LOLBin proxy execution",
     r"mshta(\.exe)?\s+(http|javascript|vbscript)|regsvr32(\.exe)?\s+.*/i:http|rundll32(\.exe)?\s+.*(javascript:|\\\\|http)|msiexec(\.exe)?\s+.*/q.*http|cmstp(\.exe)?\s+/s"),
    ("schtask-create", "medium", "persistence", "Scheduled task created from command line", r"schtasks(\.exe)?\s+/create|Register-ScheduledTask|New-ScheduledTask"),
    ("svc-create", "medium", "persistence", "Service created from command line", r"sc(\.exe)?\s+(\\\\\S+\s+)?create\s|New-Service\s"),
    ("run-key", "medium", "persistence", "Run key written from command line", r"reg(\.exe)?\s+add\s+.*\\(Run|RunOnce)\b|Set-ItemProperty.*\\(Run|RunOnce)\b"),
    ("user-add", "medium", "persistence", "Local account created / promoted",
     r"net1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add|net1?(\.exe)?\s+localgroup\s+\"?(administrators|remote desktop users)\"?\s+\S+\s+/add|New-LocalUser|Add-LocalGroupMember"),
    ("autologon", "high", "impact", "AutoAdminLogon set (safe-mode reboot trick)", r"AutoAdminLogon|DefaultPassword"),
    ("safeboot", "high", "defense-evasion", "Reboot into Safe Mode / SafeBoot service registration",
     r"bcdedit(\.exe)?\s+/set\s+.*safeboot|\\SafeBoot\\(Minimal|Network)\\"),
    ("archive-pw", "medium", "exfiltration", "Password-protected archive (staging)",
     r"\b(7z|7za|7zr|rar|winrar)(\.exe)?\s+a\s+.*-(p|hp)\S+"),
    ("exfil-tool", "high", "exfiltration", "Exfiltration tool",
     r"\brclone(\.exe)?\b|megasync|megacmd|mega\.nz|\brestic\b|filezilla|winscp|pscp(\.exe)?|\bcurl(\.exe)?\s+.*-(T|F|-upload-file)|transfer\.sh|temp\.sh|anonfiles|ufile\.io|sendspace|filemail"),
    ("tunnel", "high", "command-and-control", "Tunnel / proxy tool",
     r"\bngrok\b|\bplink(\.exe)?\b.*-R\s|\bchisel\b|cloudflared|\bfrpc?\b|\bligolo|\bssh(\.exe)?\s+.*-R\s|socks5"),
    ("rmm", "medium", "remote-access", "Remote-access / RMM tool",
     r"\b(anydesk|screenconnect|connectwise|atera|splashtop|teamviewer|tightvnc|ultravnc|rustdesk|meshagent|netsupport|logmein|remoteutilities|zoho\s*assist|simplehelp|action1|level\.io|n-able)\b"),
    ("security-tools", "high", "defense-evasion", "AV-killer / rootkit tool",
     r"\b(defendercontrol|dcontrol|gmer|pchunter|powertool|processhacker|systeminformer|iobit ?unlocker|kdmapper|killav|terminator|aukill|edrsandblast|backstab|blackout)\b"),
    ("ransom-note-cmd", "high", "impact", "Ransom note / wallpaper set from command line",
     r"\\Control Panel\\Desktop.*Wallpaper|SystemParametersInfo|LegalNoticeText|LegalNoticeCaption"),
    ("gpo-deploy", "high", "lateral-movement", "Deployment via GPO / SYSVOL",
     r"\\SYSVOL\\.*\\(Scripts|ScheduledTasks)|New-GPO|Set-GPRegistryValue|gpupdate\s+/force"),
]
CMD_RULES = [(i, s, c, t, re.compile(r, re.I)) for i, s, c, t, r in CMD_RULES]


def scan_text(text):
    """Return [(rule_id, sev, cat, title, matched_text)] for command-line style text."""
    if not text:
        return []
    out = []
    for rid, sev, cat, title, rx in CMD_RULES:
        m = rx.search(text)
        if m:
            out.append((rid, sev, cat, title, m.group(0)[:160]))
    return out


# ----------------------------------------------------------- known tools ---
TOOL_NAMES = {
    "mimikatz": ("credential-access", "high"), "procdump": ("credential-access", "medium"), "nanodump": ("credential-access", "high"),
    "lazagne": ("credential-access", "high"), "psexec": ("lateral-movement", "medium"), "psexesvc": ("lateral-movement", "medium"),
    "paexec": ("lateral-movement", "medium"), "rclone": ("exfiltration", "high"), "megasync": ("exfiltration", "high"),
    "winscp": ("exfiltration", "medium"), "filezilla": ("exfiltration", "medium"), "adfind": ("discovery", "high"),
    "sharphound": ("discovery", "high"), "netscan": ("discovery", "medium"), "advanced_ip_scanner": ("discovery", "medium"),
    "advanced ip scanner": ("discovery", "medium"), "ipscan": ("discovery", "medium"), "nmap": ("discovery", "medium"),
    "anydesk": ("remote-access", "medium"), "screenconnect": ("remote-access", "medium"), "atera": ("remote-access", "medium"),
    "splashtop": ("remote-access", "medium"), "teamviewer": ("remote-access", "low"), "rustdesk": ("remote-access", "medium"),
    "ngrok": ("command-and-control", "high"), "plink": ("command-and-control", "medium"), "chisel": ("command-and-control", "high"),
    "cloudflared": ("command-and-control", "medium"), "processhacker": ("defense-evasion", "medium"),
    "defendercontrol": ("defense-evasion", "high"), "dcontrol": ("defense-evasion", "high"), "gmer": ("defense-evasion", "high"),
    "pchunter": ("defense-evasion", "high"), "powertool": ("defense-evasion", "high"), "iobitunlocker": ("defense-evasion", "high"),
    "kdmapper": ("defense-evasion", "high"), "7z.exe": ("exfiltration", "low"), "rar.exe": ("exfiltration", "low"),
    "vssadmin": ("anti-recovery", "medium"), "wbadmin": ("anti-recovery", "medium"), "bcdedit": ("anti-recovery", "low"),
    "wevtutil": ("anti-forensics", "low"), "cipher.exe": ("anti-forensics", "low"), "sdelete": ("anti-forensics", "high"),
    "nltest": ("discovery", "medium"), "bloodhound": ("discovery", "high"), "cobaltstrike": ("command-and-control", "high"),
    "beacon": ("command-and-control", "medium"), "meterpreter": ("command-and-control", "high"),
}


def tool_hit(path):
    p = (path or "").lower().replace("/", "\\")
    base = p.rsplit("\\", 1)[-1]
    for name, (cat, sev) in TOOL_NAMES.items():
        if name in base:
            return name, cat, sev
    return None


# -------------------------------------------------------- path heuristics ---
SUSPICIOUS_DIRS = [
    (r"^\\users\\public\\", "Users\\Public"), (r"^\\perflogs\\", "PerfLogs"), (r"^\\windows\\temp\\", "Windows\\Temp"),
    (r"\\appdata\\local\\temp\\", "user Temp"), (r"^\\programdata\\[^\\]+\.(exe|dll|bat|ps1|cmd|vbs|js|hta)$", "ProgramData root"),
    (r"^\\\$recycle\.bin\\", "Recycle Bin"), (r"^\\[^\\]+\.(exe|dll|bat|ps1|cmd|scr)$", "volume root"),
    (r"\\downloads\\", "Downloads"), (r"\\desktop\\[^\\]+\.(exe|dll|bat|ps1|cmd|scr)$", "Desktop"),
    (r"\\appdata\\roaming\\[^\\]+\.(exe|dll|bat|ps1)$", "AppData\\Roaming root"), (r"^\\windows\\[^\\]+\.(exe|dll)$", "Windows root"),
    (r"\\music\\|\\videos\\|\\pictures\\", "media folder"), (r"\\intel\\|\\nvidia\\[^\\]+\.exe$", "vendor-looking folder"),
    (r"^\\windows\\(system32|syswow64)\\tasks\\", "Tasks folder"), (r"\\sysvol\\|\\netlogon\\", "SYSVOL/NETLOGON"),
]
SUSPICIOUS_DIRS = [(re.compile(r, re.I), why) for r, why in SUSPICIOUS_DIRS]
EXEC_EXT = {"exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "hta", "msi", "com", "pif", "wsf", "lnk", "sys", "cpl", "jar"}


def normalize_path(p):
    p = (p or "").strip().strip('"').replace("/", "\\")
    p = re.sub(r"^(\\\\\?\\|\\\?\?\\)", "", p)
    p = re.sub(r"^[a-z]:", "", p, flags=re.I)
    p = re.sub(r"^%systemroot%|^%windir%", r"\\Windows", p, flags=re.I)
    p = re.sub(r"^\\SystemRoot", r"\\Windows", p, flags=re.I)
    p = re.sub(r"^%programdata%", r"\\ProgramData", p, flags=re.I)
    return p


def odd_path(path):
    p = normalize_path(path)
    for rx, why in SUSPICIOUS_DIRS:
        if rx.search(p):
            return why
    return None


def image_path_of(cmd):
    """Executable part of a command line / ImagePath."""
    c = (cmd or "").strip()
    if c.startswith('"'):
        return c[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.(exe|dll|sys|bat|cmd|ps1|com|scr))\b", c, re.I)
    return m.group(1) if m else c.split(" ", 1)[0]


def service_flags(svc):
    img = svc.get("image", "") or ""
    reasons = []
    low = img.lower()
    if re.search(r"cmd(\.exe)?\s+/c|powershell|%comspec%|mshta|rundll32\s|wscript|cscript|\.bat\b|\.ps1\b|\\\\[^\\]+\\(admin|c)\$", low):
        reasons.append("runs a shell / script")
    w = odd_path(image_path_of(img))
    if w:
        reasons.append("binary in " + w)
    exe = image_path_of(img).rsplit("\\", 1)[-1]
    from util import looks_random
    if looks_random(exe) or looks_random(svc.get("name", "")):
        reasons.append("random-looking name")
    t = tool_hit(img)
    if t:
        reasons.append("known tool: " + t[0])
    return reasons


# -------------------------------------------------------------- event rules ---
LOGON_TYPES = {2: "interactive", 3: "network", 4: "batch", 5: "service", 7: "unlock", 8: "network cleartext",
               9: "new credentials", 10: "remote interactive (RDP)", 11: "cached interactive", 12: "cached remote", 13: "cached unlock"}


def is_public_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global
    except ValueError:
        return False


def _d(ev, *names):
    data = ev.get("data") or {}
    for n in names:
        if data.get(n):
            return data[n]
    return ""


def event_summary(ev):
    """One-line human summary for common events; falls back to key=value text."""
    eid, ch = ev.get("eid"), (ev.get("channel") or "")
    d = ev.get("data") or {}
    chl = ch.lower()
    try:
        if chl == "security":
            if eid in (4624, 4625):
                lt = int(_d(ev, "LogonType") or 0)
                ok = "Logon" if eid == 4624 else "FAILED logon"
                return "%s %s\\%s type %s (%s) from %s %s" % (ok, _d(ev, "TargetDomainName"), _d(ev, "TargetUserName"), lt,
                                                           LOGON_TYPES.get(lt, "?"), _d(ev, "IpAddress", "WorkstationName") or "-",
                                                           _d(ev, "ProcessName", "AuthenticationPackageName"))
            if eid == 4688:
                return "Process %s ← %s by %s: %s" % (_d(ev, "NewProcessName"), _d(ev, "ParentProcessName"),
                                                      _d(ev, "SubjectUserName"), _d(ev, "CommandLine"))
            if eid == 4648:
                return "Explicit credentials %s\\%s → %s by %s" % (_d(ev, "TargetDomainName"), _d(ev, "TargetUserName"),
                                                                  _d(ev, "TargetServerName"), _d(ev, "ProcessName"))
            if eid in (4697,):
                return "Service installed %s: %s" % (_d(ev, "ServiceName"), _d(ev, "ServiceFileName"))
            if eid in (4698, 4699, 4700, 4701, 4702):
                return "Scheduled task %s %s by %s" % ({4698: "created", 4699: "deleted", 4700: "enabled", 4701: "disabled",
                                                       4702: "updated"}[eid], _d(ev, "TaskName"), _d(ev, "SubjectUserName"))
            if eid == 4720:
                return "User created %s by %s" % (_d(ev, "TargetUserName"), _d(ev, "SubjectUserName"))
            if eid in (4728, 4732, 4756):
                return "Added %s to group %s by %s" % (_d(ev, "MemberName", "MemberSid"), _d(ev, "TargetUserName"), _d(ev, "SubjectUserName"))
            if eid == 1102:
                return "Security log cleared by %s" % (_d(ev, "SubjectUserName") or d.get("LogFileCleared.SubjectUserName", ""))
            if eid == 4657:
                return "Registry value %s\\%s changed by %s: %s → %s" % (_d(ev, "ObjectName"), _d(ev, "ObjectValueName"),
                                                                         _d(ev, "ProcessName"), _d(ev, "OldValue"), _d(ev, "NewValue"))
            if eid in (5140, 5145):
                return "Share %s accessed from %s by %s %s" % (_d(ev, "ShareName"), _d(ev, "IpAddress"), _d(ev, "SubjectUserName"),
                                                              _d(ev, "RelativeTargetName"))
            if eid == 4719:
                return "Audit policy changed by %s" % _d(ev, "SubjectUserName")
            if eid in (4778, 4779):
                return "RDP session %s %s from %s (%s)" % ("reconnected" if eid == 4778 else "disconnected",
                                                          _d(ev, "AccountName"), _d(ev, "ClientAddress"), _d(ev, "ClientName"))
        if chl == "system":
            if eid == 7045:
                return "Service installed %s: %s (%s, %s)" % (_d(ev, "ServiceName"), _d(ev, "ImagePath"), _d(ev, "StartType"), _d(ev, "AccountName"))
            if eid == 7036:
                return "Service %s → %s" % (_d(ev, "param1", "Data1"), _d(ev, "param2", "Data2"))
            if eid == 7040:
                return "Service %s start type %s → %s" % (_d(ev, "param1", "Data1"), _d(ev, "param2", "Data2"), _d(ev, "param3", "Data3"))
            if eid == 104:
                return "Event log cleared: %s by %s" % (_d(ev, "Channel", "LogFileCleared.Channel"), _d(ev, "SubjectUserName", "LogFileCleared.SubjectUserName"))
            if eid == 1074:
                return "Shutdown/restart by %s: %s (%s)" % (_d(ev, "param1"), _d(ev, "param5", "param3"), _d(ev, "param7"))
            if eid in (6005, 6006, 6008, 12, 13):
                return {6005: "Event log service started (boot)", 6006: "Event log service stopped (shutdown)",
                        6008: "Unexpected shutdown", 12: "OS started", 13: "OS shutting down"}[eid]
        if "powershell" in chl:
            if eid == 4104:
                return "ScriptBlock: " + (_d(ev, "ScriptBlockText") or "")[:400]
            if eid in (400, 403, 600, 800):
                hm = re.search(r"HostApplication=([^\r\n]+)", " ".join(str(v) for v in d.values()))
                return "PowerShell %s %s" % ({400: "engine start", 403: "engine stop", 600: "provider", 800: "pipeline"}[eid],
                                            hm.group(1) if hm else "")
        if "windows defender" in chl:
            if eid in (1116, 1117, 1118, 1119):
                return "Defender %s: %s in %s (%s)" % ({1116: "detected", 1117: "action", 1118: "action failed", 1119: "critical failure"}[eid],
                                                      _d(ev, "Threat Name"), _d(ev, "Path"), _d(ev, "Action Name", "Process Name"))
            if eid == 5007:
                return "Defender config changed: %s → %s" % (_d(ev, "Old Value"), _d(ev, "New Value"))
            if eid in (5001, 5010, 5012, 5013):
                return {5001: "Defender real-time protection DISABLED", 5010: "Defender malware scanning disabled",
                        5012: "Defender virus scanning disabled", 5013: "Tamper protection blocked a change: %s" % _d(ev, "Value")}[eid]
        if "terminalservices" in chl:
            if eid in (21, 22, 24, 25):
                return "RDP %s %s from %s" % ({21: "logon", 22: "shell start", 24: "disconnect", 25: "reconnect"}[eid],
                                             _d(ev, "User"), _d(ev, "Address"))
            if eid == 1149:
                return "RDP authentication succeeded %s\\%s from %s" % (_d(ev, "Param2"), _d(ev, "Param1"), _d(ev, "Param3"))
        if "taskscheduler" in chl and eid in (106, 140, 141, 200, 201):
            return "Task %s %s %s" % ({106: "registered", 140: "updated", 141: "deleted", 200: "action started", 201: "action completed"}[eid],
                                      _d(ev, "TaskName"), _d(ev, "ActionName", "UserContext", "UserName"))
        if "sysmon" in chl:
            if eid == 1:
                return "Process %s ← %s by %s: %s" % (_d(ev, "Image"), _d(ev, "ParentImage"), _d(ev, "User"), _d(ev, "CommandLine"))
            if eid == 3:
                return "Network %s → %s:%s" % (_d(ev, "Image"), _d(ev, "DestinationIp"), _d(ev, "DestinationPort"))
            if eid == 11:
                return "File created %s by %s" % (_d(ev, "TargetFilename"), _d(ev, "Image"))
            if eid in (12, 13, 14):
                return "Registry %s %s = %s by %s" % (_d(ev, "EventType"), _d(ev, "TargetObject"), _d(ev, "Details"), _d(ev, "Image"))
            if eid in (23, 26):
                return "File deleted %s by %s" % (_d(ev, "TargetFilename"), _d(ev, "Image"))
        if "wmi-activity" in chl and eid == 5861:
            return "WMI permanent subscription: " + " ".join(str(v) for v in d.values())[:400]
        if "bits-client" in chl and eid in (59, 60):
            return "BITS %s %s %s" % ("transfer started" if eid == 59 else "transfer stopped", _d(ev, "name"), _d(ev, "url"))
        if "firewall" in chl and eid in (2004, 2005, 2006, 2097, 2099):
            return "Firewall rule %s: %s %s" % ({2004: "added", 2005: "modified", 2006: "deleted", 2097: "added", 2099: "modified"}.get(eid),
                                                _d(ev, "RuleName"), _d(ev, "ApplicationPath"))
    except Exception:
        pass
    parts = ["%s=%s" % (k, v) for k, v in d.items() if v not in ("", "-", None)]
    return "; ".join(parts)[:500]


# event-level rules: (channel substring, ids, sev, cat, title)
EVENT_RULES = [
    ("security", {1102}, "high", "anti-forensics", "Security log cleared"),
    ("system", {104}, "high", "anti-forensics", "Event log cleared"),
    ("security", {4719}, "high", "defense-evasion", "Audit policy changed"),
    ("system", {7045}, "medium", "persistence", "Service installed"),
    ("security", {4697}, "medium", "persistence", "Service installed"),
    ("security", {4698, 4702}, "medium", "persistence", "Scheduled task created/updated"),
    ("taskscheduler", {106, 140}, "low", "persistence", "Scheduled task registered/updated"),
    ("taskscheduler", {141}, "medium", "anti-forensics", "Scheduled task deleted"),
    ("security", {4720}, "high", "persistence", "Local user account created"),
    ("security", {4732, 4728, 4756}, "medium", "persistence", "Account added to a group"),
    ("windows defender", {1116, 1117, 1118, 1119}, "high", "malware", "Defender detection"),
    ("windows defender", {5001, 5010, 5012}, "high", "defense-evasion", "Defender protection disabled"),
    ("windows defender", {5007}, "medium", "defense-evasion", "Defender configuration changed"),
    ("windows defender", {5013}, "medium", "defense-evasion", "Tamper protection blocked a change"),
    ("wmi-activity", {5861}, "high", "persistence", "WMI permanent event subscription"),
    ("remoteconnectionmanager", {1149}, "medium", "lateral-movement", "RDP authentication"),
    ("localsessionmanager", {21, 25}, "low", "lateral-movement", "RDP session logon/reconnect"),
    ("security", {4778}, "low", "lateral-movement", "RDP session reconnected"),
    ("security", {4616}, "medium", "anti-forensics", "System time changed"),
    ("system", {6008}, "low", "impact", "Unexpected shutdown"),
    ("system", {1074}, "low", "impact", "Shutdown / restart initiated"),
    ("bits-client", {59}, "low", "execution", "BITS transfer"),
    ("firewall", {2004, 2097}, "low", "defense-evasion", "Firewall rule added"),
    ("firewall", {2003}, "medium", "defense-evasion", "Firewall profile setting changed"),
    ("security", {4657}, "low", "defense-evasion", "Registry value modified (audited)"),
    ("sysmon", {23, 26}, "low", "impact", "File deleted (Sysmon)"),
]
WATCH_SERVICES = re.compile(r"volume shadow copy|vss|windows defender|microsoft defender|windefend|security center|wscsvc|"
                            r"windows backup|wbengine|sdrsvc|backup|veeam|sql|windows event log|eventlog|sysmon|sense|firewall|mpssvc", re.I)


def event_findings(ev, summary):
    """Return [(sev, cat, title)] for one event."""
    out = []
    ch = (ev.get("channel") or "").lower()
    eid = ev.get("eid")
    for sub, ids, sev, cat, title in EVENT_RULES:
        if sub in ch and eid in ids:
            if eid == 5007 and re.search(r"Exclusions|DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|TamperProtection", summary, re.I):
                sev, title = "high", "Defender exclusion / protection setting changed"
            if eid in (4732, 4728, 4756) and re.search(r"admin|remote desktop", summary, re.I):
                sev = "high"
            out.append((sev, cat, title))
    if ch == "security" and eid == 4624:
        d = ev.get("data") or {}
        lt = str(d.get("LogonType", ""))
        ip = d.get("IpAddress", "")
        if lt == "10":
            out.append(("medium" if not is_public_ip(ip) else "high", "lateral-movement", "RDP logon" + (" from public IP" if is_public_ip(ip) else "")))
        elif lt == "3" and is_public_ip(ip):
            out.append(("high", "initial-access", "Network logon from public IP"))
    if ch == "system" and eid in (7036, 7040):
        s = summary
        if WATCH_SERVICES.search(s) and re.search(r"stopped|disabled|demand start|→ (stopped|disabled)", s, re.I):
            out.append(("medium", "defense-evasion", "Security / backup service stopped or disabled"))
    return out


# ---------------------------------------------------------- registry checks ---
# (hive, path (CS = current control set), value, test, sev, title, why)
def _eq(x):
    return lambda v: v == x


def _nonempty(v):
    return v not in (None, "", 0, b"", [])


REG_CHECKS = [
    ("SOFTWARE", r"Policies\Microsoft\Windows Defender", "DisableAntiSpyware", _eq(1), "high", "Defender disabled by policy", "DisableAntiSpyware=1"),
    ("SOFTWARE", r"Policies\Microsoft\Windows Defender", "DisableAntiVirus", _eq(1), "high", "Defender AV disabled by policy", ""),
    ("SOFTWARE", r"Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", _eq(1), "high", "Real-time protection disabled by policy", ""),
    ("SOFTWARE", r"Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", _eq(1), "high", "Behaviour monitoring disabled by policy", ""),
    ("SOFTWARE", r"Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", _eq(1), "high", "On-access protection disabled", ""),
    ("SOFTWARE", r"Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableIOAVProtection", _eq(1), "high", "Download scanning disabled", ""),
    ("SOFTWARE", r"Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", _eq(1), "high", "Real-time protection off", ""),
    ("SOFTWARE", r"Microsoft\Windows Defender", "DisableAntiSpyware", _eq(1), "high", "Defender disabled", ""),
    ("SOFTWARE", r"Microsoft\Windows Defender\Features", "TamperProtection", lambda v: isinstance(v, int) and v in (0, 4), "medium", "Tamper protection off", "value 4/0 = off, 5 = on"),
    ("SYSTEM", r"CS\Control\Terminal Server", "fDenyTSConnections", _eq(0), "low", "RDP enabled", "fDenyTSConnections=0"),
    ("SYSTEM", r"CS\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", _eq(0), "medium", "RDP without Network Level Authentication", ""),
    ("SYSTEM", r"CS\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber", lambda v: isinstance(v, int) and v != 3389, "medium", "RDP on a non-standard port", ""),
    ("SYSTEM", r"CS\Control\SecurityProviders\WDigest", "UseLogonCredential", _eq(1), "high", "WDigest stores plaintext passwords", "credential theft preparation"),
    ("SYSTEM", r"CS\Control\Lsa", "DisableRestrictedAdmin", _eq(0), "medium", "Restricted Admin enabled (pass-the-hash over RDP)", ""),
    ("SYSTEM", r"CS\Control\Lsa", "RunAsPPL", _eq(0), "low", "LSA protection off", ""),
    ("SOFTWARE", r"Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", _eq(0), "high", "UAC disabled", ""),
    ("SOFTWARE", r"Microsoft\Windows\CurrentVersion\Policies\System", "LocalAccountTokenFilterPolicy", _eq(1), "medium", "Remote UAC filtering off (lateral movement with local admin)", ""),
    ("SOFTWARE", r"Microsoft\Windows\CurrentVersion\Policies\System", "EnableLinkedConnections", _eq(1), "medium", "EnableLinkedConnections=1", "lets elevated ransomware see the user's mapped drives"),
    ("SOFTWARE", r"Microsoft\Windows\CurrentVersion\Policies\System", "legalnoticetext", _nonempty, "medium", "Logon banner text set", "ransomware often puts the note here"),
    ("SOFTWARE", r"Microsoft\Windows\CurrentVersion\Policies\System", "legalnoticecaption", _nonempty, "medium", "Logon banner caption set", ""),
    ("SOFTWARE", r"Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", _eq(1), "medium", "Task Manager disabled", ""),
    ("SOFTWARE", r"Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", lambda v: str(v) == "1", "high", "AutoAdminLogon enabled", "used to reboot into Safe Mode and log on automatically"),
    ("SOFTWARE", r"Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword", _nonempty, "high", "Plaintext DefaultPassword stored", ""),
    ("SOFTWARE", r"Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", lambda v: isinstance(v, str) and v.strip().lower() not in ("explorer.exe", ""), "high", "Winlogon Shell replaced", ""),
    ("SOFTWARE", r"Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", lambda v: isinstance(v, str) and v.strip().strip(",").lower() not in (r"c:\windows\system32\userinit.exe", "userinit.exe", ""), "high", "Winlogon Userinit modified", ""),
    ("SOFTWARE", r"Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", _nonempty, "high", "AppInit_DLLs set", ""),
    ("SOFTWARE", r"Policies\Microsoft\Windows NT\SystemRestore", "DisableSR", _eq(1), "high", "System Restore disabled by policy", ""),
    ("SOFTWARE", r"Policies\Microsoft\Windows NT\SystemRestore", "DisableConfig", _eq(1), "high", "System Restore configuration disabled", ""),
    ("SYSTEM", r"CS\Services\VSS", "Start", _eq(4), "high", "Volume Shadow Copy service disabled", ""),
    ("SYSTEM", r"CS\Services\wbengine", "Start", _eq(4), "medium", "Block-level backup engine disabled", ""),
    ("SYSTEM", r"CS\Services\WinDefend", "Start", _eq(4), "high", "Defender service disabled", ""),
    ("SYSTEM", r"CS\Services\EventLog", "Start", _eq(4), "high", "Event Log service disabled", ""),
    ("SYSTEM", r"CS\Services\wscsvc", "Start", _eq(4), "medium", "Security Center disabled", ""),
    ("SYSTEM", r"CS\Services\MpsSvc", "Start", _eq(4), "medium", "Firewall service disabled", ""),
    ("SYSTEM", r"CS\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall", _eq(0), "medium", "Firewall off (private profile)", ""),
    ("SYSTEM", r"CS\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", _eq(0), "medium", "Firewall off (public profile)", ""),
    ("SYSTEM", r"CS\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", _eq(0), "medium", "Firewall off (domain profile)", ""),
    ("SYSTEM", r"CS\Control\FileSystem", "SymlinkRemoteToLocalEvaluation", _eq(1), "medium", "Remote→local symlinks enabled", "fsutil trick used by BlackCat and others"),
    ("SYSTEM", r"CS\Control\FileSystem", "SymlinkRemoteToRemoteEvaluation", _eq(1), "medium", "Remote→remote symlinks enabled", ""),
    ("SYSTEM", r"CS\Services\LanmanServer\Parameters", "MaxMpxCt", lambda v: isinstance(v, int) and v >= 1000, "medium", "SMB MaxMpxCt raised", "BlackCat raises it to spread encryption faster"),
    ("SOFTWARE", r"Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", _eq(0), "medium", "PowerShell script block logging disabled", ""),
    ("SOFTWARE", r"Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled", _eq(1), "info", "Command lines are recorded in 4688 events", "good: Security 4688 events carry command lines"),
]


# --------------------------------------------------------- ransomware bits ---
DOC_EXTS = set("""doc docx docm dot dotx xls xlsx xlsm xlsb xlt csv ppt pptx pptm pps ppsx odt ods odp rtf txt pdf
jpg jpeg png gif bmp tif tiff heic psd ai svg raw cr2 nef mp3 mp4 mov avi mkv wav wma wmv m4a flac zip rar 7z gz tar
bak sql mdf ldf ndf db dbf sqlite accdb mdb pst ost msg eml vsd vsdx one xml json html htm php js css py java cs cpp
c h ps1 config ini log dwg dxf skp key pages numbers qbw qbb tax iso vhd vhdx vmdk ova ovf pfx p12 kdbx""".split())

COMMON_EXTS = set("""exe dll sys ini txt log dat tmp lnk xml json js css html htm png jpg jpeg gif ico svg bmp mui cat
manifest inf pnf etl evtx db sqlite cab msi msp mum cdxml ps1 psm1 psd1 pdf doc docx xls xlsx ppt pptx zip rar 7z gz
mp3 mp4 wav ttf otf fon woff woff2 nls tlb ocx cpl drv scr com bat cmd vbs config resx pdb pf chk jrs edb jfm
bak old cache idx pak bin dmp mof dic lex aux res pri appx msix winmd node map ts md rst yml yaml toml lock
pyc py pyd so h c cpp cs java class jar mdf ldf ndf accdb mdb pst ost csv tsv sql dbf odt ods odp rtf vhd vhdx
iso img pnf mui mun xsd xsl dtd wim esd cer crt pem pfx p7b key lic url""".split())

KNOWN_RANSOM_EXTS = set("""locked lockbit lockbit3 encrypted enc crypt crypted crypto blackcat alphv akira royal play conti
ryuk hive phobos eking eight acute dharma wallet arena java bip combo devos makop medusa rhysida basta
blacksuit cuba avos avoslocker lockfile quantum vice babuk ransomhub hunters 8base lynx inc bianlian cactus
qilin agenda nokoyawa clop cl0p kraken djvu stop maze egregor sodinokibi revil ragnar ragnarok netwalker
mallox fargo tohnichi trigona money monti bluesky cryptolocker wannacry wncry wcry locky zepto odin thor
osiris aesir zzzzz cerber cerber3 sage spora gandcrab krab""".split())

NOTE_NAME_RX = re.compile(r"(readme|read_me|read-me|restore|recover|decrypt|how_to|how-to|howto|help_|_help|instruction|"
                          r"ransom|unlock|!!!|files|attention|important|info\.hta|_info|note)", re.I)
NOTE_EXTS = {"txt", "html", "htm", "hta", "rtf", "url", "png", "jpg", "bmp", "pdf"}
BENIGN_REPEATED = {"desktop.ini", "thumbs.db", "readme.txt.lnk", ".ds_store", "icon\r", "folder.jpg", "albumartsmall.jpg",
                   "index.dat", "license.txt", "license", "changelog.txt", "license.md", "notice.txt", "copying",
                   "copying.txt", "authors.txt", "third party notices.txt", "thirdpartynotices.txt"}
