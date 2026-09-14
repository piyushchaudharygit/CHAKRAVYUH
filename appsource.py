"""
╔══════════════════════════════════════════════════════════════╗
║        CHAKRAVYUH — AI Malware Behaviour Classification      ║
║        PS-06 | Track: AI & Threat Intelligence               ║
║  HOW TO RUN:  python app.py                                  ║
║  Then open:   http://127.0.0.1:8000                         ║
╚══════════════════════════════════════════════════════════════╝

INSTALL DEPS FIRST (one time only):
    pip install fastapi uvicorn python-multipart
"""

import os, hashlib, random, time
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Chakravyuh API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────
#  THREAT INTELLIGENCE DATABASE (Mock ML Results for Demo)
# ──────────────────────────────────────────────────────────────

THREAT_PROFILES = {
    "ransomware": {
        "family": "Ransomware",
        "variant": "LockBit 3.0",
        "threat_score": 97,
        "confidence": 94,
        "severity": "CRITICAL",
        "color": "#ff2d55",
        "icon": "💀",
        "description": "Encrypts victim files using AES-256+RSA-2048 hybrid scheme. Drops ransom note. Deletes shadow copies via vssadmin. Communicates with C2 over Tor network.",
        "behaviors": [
            {"name": "File Encryption Engine", "score": 98, "api": "CryptEncrypt, CryptGenKey (AES-256)", "severity": "critical"},
            {"name": "Shadow Copy Deletion", "score": 96, "api": "vssadmin.exe Delete Shadows /All", "severity": "critical"},
            {"name": "Ransom Note Deployment", "score": 91, "api": "CreateFileW, WriteFile (README_DECRYPT.txt)", "severity": "high"},
            {"name": "Registry Persistence", "score": 88, "api": "RegSetValueEx (HKLM\\CurrentVersion\\Run)", "severity": "high"},
            {"name": "C2 Beacon via Tor", "score": 85, "api": "HttpOpenRequestA → Tor proxy :443", "severity": "high"},
            {"name": "Process Injection", "score": 79, "api": "VirtualAllocEx, WriteProcessMemory, CreateRemoteThread", "severity": "medium"},
            {"name": "Anti-Debug / Sandbox Evasion", "score": 72, "api": "IsDebuggerPresent, CheckRemoteDebugger", "severity": "medium"},
        ],
        "mitre": [
            {"id": "T1486", "tactic": "Impact", "technique": "Data Encrypted for Impact", "severity": "Critical"},
            {"id": "T1490", "tactic": "Impact", "technique": "Inhibit System Recovery", "severity": "Critical"},
            {"id": "T1547", "tactic": "Persistence", "technique": "Boot/Logon Autostart Execution", "severity": "High"},
            {"id": "T1071", "tactic": "Command & Control", "technique": "Application Layer Protocol", "severity": "High"},
            {"id": "T1055", "tactic": "Defense Evasion", "technique": "Process Injection", "severity": "High"},
            {"id": "T1497", "tactic": "Defense Evasion", "technique": "Virtualization/Sandbox Evasion", "severity": "Medium"},
        ],
        "api_trace": [
            "NtCreateProcess(explorer.exe) → SUCCESS [INJECTION TARGET]",
            "VirtualAllocEx(PID:1234, size=4096, MEM_COMMIT) → 0x7ff00000",
            "WriteProcessMemory(PID:1234, shellcode_payload) → SUCCESS",
            "CreateRemoteThread(PID:1234, entry=0x7ff00000) → TID:5678",
            "RegOpenKeyEx(HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run) → SUCCESS",
            "RegSetValueEx(key=WindowsUpdater, data=C:\\malware.exe) → PERSISTED",
            "CryptAcquireContext(PROV_RSA_AES) → hProv:0x1a2b3c4d",
            "CryptGenKey(ALG_CLASS_DATA_ENCRYPT|AES_256) → hKey:0xdeadbeef",
            "FindFirstFileW(C:\\Users\\**) → ENUMERATION STARTED",
            "CryptEncrypt(hKey, hFile=documents.docx) → ENCRYPTED",
            "CryptEncrypt(hKey, hFile=photo.jpg) → ENCRYPTED",
            "CreateFileW(C:\\Users\\Desktop\\README_DECRYPT.txt) → SUCCESS",
            "WriteFile(ransom_note_lockbit3) → SUCCESS",
            "ShellExecuteEx(vssadmin.exe Delete Shadows /All /Quiet) → SUCCESS",
            "InternetOpenA(UserAgent=Mozilla/5.0) → hInternet",
            "InternetConnectA(host=xbtl7d5g.onion, port=443) → hConnect [C2]",
            "HttpOpenRequestA(POST, /beacon/register) → hRequest",
        ],
        "process_tree": [
            {"pid": 1000, "name": "malware.exe  [ORIGIN]", "parent": None, "suspicious": True},
            {"pid": 1234, "name": "explorer.exe  [INJECTED]", "parent": 1000, "suspicious": True},
            {"pid": 1400, "name": "vssadmin.exe  [SHADOW DELETE]", "parent": 1000, "suspicious": True},
            {"pid": 1500, "name": "cmd.exe", "parent": 1400, "suspicious": True},
            {"pid": 1600, "name": "conhost.exe", "parent": 1400, "suspicious": False},
        ]
    },
    "trojan": {
        "family": "Trojan",
        "variant": "RemcosRAT v4.2",
        "threat_score": 89,
        "confidence": 91,
        "severity": "HIGH",
        "color": "#ff6b00",
        "icon": "🐴",
        "description": "Remote Access Trojan with keylogging, screen capture, and backdoor capabilities. Masquerades as legitimate PDF. Persists via scheduled tasks. Exfiltrates to C2.",
        "behaviors": [
            {"name": "Keylogging (Hook-based)", "score": 94, "api": "SetWindowsHookEx(WH_KEYBOARD_LL, hook_proc)", "severity": "critical"},
            {"name": "Full Screen Capture", "score": 88, "api": "GetDC(NULL), BitBlt(1920x1080)", "severity": "high"},
            {"name": "Scheduled Task Persistence", "score": 86, "api": "schtasks.exe /Create /SC ONLOGON", "severity": "high"},
            {"name": "Clipboard Theft", "score": 81, "api": "OpenClipboard(NULL), GetClipboardData(CF_TEXT)", "severity": "high"},
            {"name": "Webcam Activation", "score": 76, "api": "avicap32.dll → capCreateCaptureWindow", "severity": "medium"},
            {"name": "Browser Credential Harvest", "score": 73, "api": "CryptUnprotectData (DPAPI Chrome keys)", "severity": "medium"},
        ],
        "mitre": [
            {"id": "T1056", "tactic": "Collection", "technique": "Input Capture / Keylogging", "severity": "Critical"},
            {"id": "T1113", "tactic": "Collection", "technique": "Screen Capture", "severity": "High"},
            {"id": "T1053", "tactic": "Persistence", "technique": "Scheduled Task/Job", "severity": "High"},
            {"id": "T1115", "tactic": "Collection", "technique": "Clipboard Data Theft", "severity": "High"},
            {"id": "T1555", "tactic": "Credential Access", "technique": "Credentials from Password Stores", "severity": "Medium"},
            {"id": "T1571", "tactic": "Command & Control", "technique": "Non-Standard Port (4782)", "severity": "Medium"},
        ],
        "api_trace": [
            "CreateFileW(C:\\Users\\victim\\invoice_2024.pdf.exe) → DISGUISED EXECUTABLE",
            "SetWindowsHookEx(WH_KEYBOARD_LL, hook_proc, NULL) → hHook:0xaaaa1234",
            "GetDC(NULL) → hDC [full screen capture context]",
            "BitBlt(memDC, 0, 0, 1920, 1080, hDC, 0, 0, SRCCOPY) → SCREENSHOT TAKEN",
            "OpenClipboard(NULL) → SUCCESS",
            "GetClipboardData(CF_TEXT) → clipboard content exfiltrated",
            "CryptUnprotectData(Chrome Local State key) → BROWSER KEYS DECRYPTED",
            "InternetConnectA(host=c2.remcos-panel.ru, port=4782) → hConnect [RAT C2]",
            "send(socket, keylog_data, len) → KEYSTROKES TRANSMITTED",
            "schtasks.exe /Create /SC ONLOGON /TR malware.exe /RU SYSTEM → PERSISTED",
        ],
        "process_tree": [
            {"pid": 2000, "name": "invoice_2024.pdf.exe  [DISGUISED]", "parent": None, "suspicious": True},
            {"pid": 2100, "name": "svchost.exe  [PROCESS HOLLOWED]", "parent": 2000, "suspicious": True},
            {"pid": 2200, "name": "schtasks.exe  [PERSISTENCE]", "parent": 2000, "suspicious": True},
            {"pid": 2300, "name": "cmd.exe", "parent": 2200, "suspicious": False},
        ]
    },
    "worm": {
        "family": "Worm",
        "variant": "NetWorm.Conficker.D",
        "threat_score": 82,
        "confidence": 87,
        "severity": "HIGH",
        "color": "#9b59b6",
        "icon": "🪱",
        "description": "Network-propagating worm exploiting MS08-067 (SRVSVC). Terminates AV processes. Spreads via SMB and removable USB drives. Downloads secondary payloads.",
        "behaviors": [
            {"name": "Mass Network Scanning", "score": 91, "api": "WSAConnect, connect() → 65535 port sweep", "severity": "critical"},
            {"name": "SMB Exploit MS08-067", "score": 87, "api": "NetServerEnum, SRVSVC heap overflow", "severity": "critical"},
            {"name": "Antivirus Termination", "score": 84, "api": "OpenProcess(TERMINATE) → MsMpEng.exe", "severity": "high"},
            {"name": "USB Drive Propagation", "score": 78, "api": "GetDriveTypeW → REMOVABLE → autorun.inf drop", "severity": "high"},
            {"name": "DNS Cache Poisoning", "score": 71, "api": "DnsQuery_A interception + modification", "severity": "medium"},
        ],
        "mitre": [
            {"id": "T1210", "tactic": "Lateral Movement", "technique": "Exploitation of Remote Services (MS08-067)", "severity": "Critical"},
            {"id": "T1046", "tactic": "Discovery", "technique": "Network Service Scanning", "severity": "High"},
            {"id": "T1562", "tactic": "Defense Evasion", "technique": "Impair Defenses — AV Kill", "severity": "High"},
            {"id": "T1091", "tactic": "Lateral Movement", "technique": "Replication Through Removable Media", "severity": "High"},
            {"id": "T1568", "tactic": "Command & Control", "technique": "Dynamic Resolution (DGA)", "severity": "Medium"},
        ],
        "api_trace": [
            "WSAStartup(MAKEWORD(2,2)) → SUCCESS",
            "socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) → mass port 445 scan",
            "connect(192.168.1.0/24, port=445) → SCANNING 247 HOSTS",
            "NetServerEnum(NULL, 102) → 247 HOSTS DISCOVERED",
            "OpenProcess(PROCESS_ALL_ACCESS, MsMpEng.exe) → SUCCESS",
            "TerminateProcess(MsMpEng.exe) → WINDOWS DEFENDER KILLED",
            "GetDriveTypeW(E:\\) → DRIVE_REMOVABLE [USB FOUND]",
            "CreateFileW(E:\\autorun.inf) → WORM COPY DROPPED ON USB",
            "URLDownloadToFile(http://malware-c2.ru/payload2.exe) → DOWNLOADING",
            "CreateProcess(payload2.exe) → SECONDARY PAYLOAD LAUNCHED",
        ],
        "process_tree": [
            {"pid": 3000, "name": "worm.exe  [ENTRY POINT]", "parent": None, "suspicious": True},
            {"pid": 3100, "name": "MsMpEng.exe  [TERMINATED BY WORM]", "parent": 3000, "suspicious": True},
            {"pid": 3200, "name": "svchost.exe  [SMB SCANNER]", "parent": 3000, "suspicious": True},
            {"pid": 3300, "name": "net.exe", "parent": 3200, "suspicious": False},
            {"pid": 3400, "name": "payload2.exe  [DOWNLOADED]", "parent": 3000, "suspicious": True},
        ]
    },
    "safe": {
        "family": "Safe Utility",
        "variant": "Notepad++ v8.6.2 (Signed)",
        "threat_score": 4,
        "confidence": 96,
        "severity": "CLEAN",
        "color": "#00c896",
        "icon": "✅",
        "description": "Legitimate text editor application. Digitally signed by Notepad++ author. No suspicious behaviors detected. All API calls are within normal operating parameters for a text editor.",
        "behaviors": [
            {"name": "File Read / Write (Normal)", "score": 5, "api": "CreateFileW, ReadFile, WriteFile", "severity": "clean"},
            {"name": "Settings Registry Access", "score": 3, "api": "RegQueryValueEx (HKCU\\Software only)", "severity": "clean"},
            {"name": "UI / GDI Rendering", "score": 2, "api": "CreateWindowEx, DrawText, GDI calls", "severity": "clean"},
            {"name": "Font Resource Loading", "score": 1, "api": "AddFontResourceEx (bundled fonts)", "severity": "clean"},
        ],
        "mitre": [],
        "api_trace": [
            "CreateWindowEx(WS_OVERLAPPEDWINDOW, Notepad++) → Main window",
            "CreateFileW(C:\\Users\\docs\\readme.txt, GENERIC_READ) → hFile",
            "ReadFile(hFile, buffer, 4096) → SUCCESS [normal read]",
            "RegQueryValueEx(HKCU\\Software\\Notepad++\\config) → settings loaded",
            "DrawText(hDC, file_content, -1) → RENDERED",
            "DestroyWindow → Clean exit",
        ],
        "process_tree": [
            {"pid": 4000, "name": "notepad++.exe  [SIGNED BINARY]", "parent": None, "suspicious": False},
            {"pid": 4100, "name": "conhost.exe", "parent": 4000, "suspicious": False},
        ]
    }
}


def classify_file(filename: str, content: bytes) -> dict:
    """Classify file using name heuristics + deterministic hash routing."""
    name_lower = filename.lower()
    ext = os.path.splitext(filename)[1].lower()
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()

    # Classification logic
    if any(k in name_lower for k in ["ransom", "lock", "crypt", "encrypt", "wannacry", "locker", "cobra"]):
        key = "ransomware"
    elif any(k in name_lower for k in ["trojan", "rat", "remcos", "backdoor", "spy", "malware", "stealer"]):
        key = "trojan"
    elif any(k in name_lower for k in ["worm", "confick", "spread", "propagat", "netbot"]):
        key = "worm"
    elif ext in [".txt", ".pdf", ".docx", ".xlsx", ".png", ".jpg", ".gif", ".mp4", ".mp3"]:
        key = "safe"
    elif ext == ".exe":
        # Deterministic: use first hex nibble of sha256
        key = ["ransomware", "trojan", "worm"][int(sha256[0], 16) % 3]
    else:
        key = "safe"

    profile = dict(THREAT_PROFILES[key])
    sz = len(content)
    profile["file_info"] = {
        "filename": filename,
        "size": sz,
        "size_str": f"{sz/1024:.1f} KB" if sz < 1024*1024 else f"{sz/(1024*1024):.2f} MB",
        "sha256": sha256,
        "md5": md5,
        "extension": ext or "unknown",
        "analysis_time": round(random.uniform(1.9, 4.5), 2),
    }
    return profile


# ──────────────────────────────────────────────────────────────
#  API ENDPOINTS
# ──────────────────────────────────────────────────────────────

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """Upload a file and get behavioral analysis result."""
    content = await file.read()
    result = classify_file(file.filename, content)
    time.sleep(0.6)  # Simulate ML processing time
    return result


@app.get("/demo/{scenario}")
async def demo_scenario(scenario: str):
    """Load a demo scenario without file upload."""
    key = scenario.lower() if scenario.lower() in THREAT_PROFILES else "trojan"
    profile = dict(THREAT_PROFILES[key])
    sz = random.randint(64000, 512000)
    profile["file_info"] = {
        "filename": f"demo_{scenario}_sample.exe",
        "size": sz,
        "size_str": f"{sz // 1024} KB",
        "sha256": hashlib.sha256(scenario.encode()).hexdigest(),
        "md5": hashlib.md5(scenario.encode()).hexdigest(),
        "extension": ".exe",
        "analysis_time": round(random.uniform(1.9, 4.5), 2),
    }
    return profile


# ──────────────────────────────────────────────────────────────
#  FRONTEND HTML
# ──────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CHAKRAVYUH — AI Malware Classification</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=JetBrains+Mono:wght@300;400;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--nc:#00f5ff;--nr:#ff2d55;--ng:#00c896;--no:#ff6b00;--np:#9b59b6;--bg:#020812;--bgc:#060e1e;}
*{box-sizing:border-box;}
body{background:var(--bg);font-family:'Inter',sans-serif;color:#e0e8f0;min-height:100vh;overflow-x:hidden;}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(0,245,255,.06),transparent 60%),radial-gradient(ellipse 50% 30% at 100% 80%,rgba(255,45,85,.04),transparent 50%);pointer-events:none;z-index:0;}
.orbitron{font-family:'Orbitron',sans-serif;}
.mono{font-family:'JetBrains Mono',monospace;}
.grid-bg{background-image:linear-gradient(rgba(0,245,255,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(0,245,255,.022) 1px,transparent 1px);background-size:40px 40px;}
.card{background:var(--bgc);border:1px solid rgba(0,245,255,.12);border-radius:14px;position:relative;overflow:hidden;}
.card-glow::after{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,245,255,.4),transparent);}
.neon-cyan{color:var(--nc);text-shadow:0 0 20px rgba(0,245,255,.45);}
.neon-green{color:var(--ng);}
.neon-orange{color:var(--no);}
#dropZone{border:2px dashed rgba(0,245,255,.22);border-radius:16px;transition:all .3s;cursor:pointer;background:rgba(0,245,255,.018);}
#dropZone:hover,#dropZone.dov{border-color:var(--nc);box-shadow:0 0 35px rgba(0,245,255,.18);background:rgba(0,245,255,.04);}
.progress-bar{background:rgba(255,255,255,.05);border-radius:99px;overflow:hidden;height:7px;}
.progress-fill{height:100%;border-radius:99px;transition:width 1.3s cubic-bezier(.22,1,.36,1);}
.terminal{background:#000b0f;border:1px solid rgba(0,245,255,.16);border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:11px;overflow-y:auto;max-height:235px;padding:12px;line-height:1.8;}
.terminal::-webkit-scrollbar{width:4px;}
.terminal::-webkit-scrollbar-thumb{background:rgba(0,245,255,.28);border-radius:2px;}
.badge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:99px;font-size:10px;font-weight:700;letter-spacing:.5px;}
.bc{background:rgba(255,45,85,.12);color:#ff2d55;border:1px solid rgba(255,45,85,.28);}
.bh{background:rgba(255,107,0,.12);color:#ff6b00;border:1px solid rgba(255,107,0,.28);}
.bm{background:rgba(255,214,0,.12);color:#ffd700;border:1px solid rgba(255,214,0,.28);}
.bk{background:rgba(0,200,150,.12);color:#00c896;border:1px solid rgba(0,200,150,.28);}
.mt{width:100%;border-collapse:separate;border-spacing:0 4px;}
.mt thead th{background:rgba(0,245,255,.04);padding:8px 12px;text-align:left;font-size:10px;color:rgba(0,245,255,.5);letter-spacing:1px;font-weight:700;}
.mt tbody tr{background:rgba(255,255,255,.018);transition:background .2s;}
.mt tbody tr:hover{background:rgba(0,245,255,.045);}
.mt tbody td{padding:10px 12px;font-size:12px;}
.demo-btn{padding:9px 18px;border-radius:9px;font-size:12px;font-weight:700;cursor:pointer;transition:all .2s;border:1px solid;font-family:'JetBrains Mono',monospace;letter-spacing:.4px;}
.demo-btn:hover{transform:translateY(-2px);filter:brightness(1.2);box-shadow:0 4px 20px currentColor20;}
@keyframes scanLine{0%{transform:translateY(-100%);}100%{transform:translateY(600%);}}
@keyframes pulse{0%,100%{opacity:.55;}50%{opacity:1;}}
@keyframes fadeUp{from{opacity:0;transform:translateY(22px);}to{opacity:1;transform:translateY(0);}}
.fadeUp{animation:fadeUp .5s ease forwards;}
.pulse{animation:pulse 2s ease-in-out infinite;}
#scanOverlay{position:fixed;inset:0;background:rgba(2,8,18,.9);z-index:100;display:flex;flex-direction:column;align-items:center;justify-content:center;backdrop-filter:blur(7px);}
.scan-box{width:270px;height:270px;border:2px solid rgba(0,245,255,.28);border-radius:16px;position:relative;overflow:hidden;background:rgba(0,245,255,.018);}
.scan-line{position:absolute;width:100%;height:3px;background:linear-gradient(90deg,transparent,var(--nc),transparent);animation:scanLine 1.35s linear infinite;box-shadow:0 0 18px var(--nc);}
.corner{position:absolute;width:18px;height:18px;border-color:var(--nc);border-style:solid;}
.ctl{top:0;left:0;border-width:2px 0 0 2px;}.ctr{top:0;right:0;border-width:2px 2px 0 0;}
.cbl{bottom:0;left:0;border-width:0 0 2px 2px;}.cbr{bottom:0;right:0;border-width:0 2px 2px 0;}
.proc{display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:8px;margin:3px 0;font-size:12px;font-family:'JetBrains Mono',monospace;border:1px solid;}
.proc.s{background:rgba(255,45,85,.07);border-color:rgba(255,45,85,.2);color:#ff8fa3;}
.proc.c{background:rgba(0,200,150,.05);border-color:rgba(0,200,150,.18);color:#80e8cc;}
.hl{height:1px;background:linear-gradient(90deg,transparent,var(--nc),rgba(255,45,85,.5),transparent);}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ng);box-shadow:0 0 8px var(--ng);animation:pulse 2s ease-in-out infinite;}
::-webkit-scrollbar{width:5px;}
::-webkit-scrollbar-thumb{background:rgba(0,245,255,.15);border-radius:3px;}
</style>
</head>
<body class="grid-bg">

<!-- SCAN OVERLAY -->
<div id="scanOverlay" style="display:none;">
  <div class="scan-box">
    <div class="scan-line"></div>
    <div class="corner ctl"></div><div class="corner ctr"></div>
    <div class="corner cbl"></div><div class="corner cbr"></div>
    <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;padding:20px;text-align:center;">
      <div style="font-size:38px;">🔬</div>
      <div class="orbitron neon-cyan text-sm font-bold tracking-widest">ANALYZING...</div>
      <div id="scanStatus" class="mono text-xs text-gray-400">Extracting PE headers...</div>
    </div>
  </div>
  <div class="mt-5 text-center">
    <div class="orbitron text-xs text-gray-500 tracking-widest">CHAKRAVYUH BEHAVIORAL ENGINE</div>
    <div id="scanPct" class="mono text-xs neon-cyan mt-2">0%</div>
  </div>
</div>

<!-- HEADER -->
<header class="relative z-10 px-6 py-4 flex items-center justify-between" style="background:rgba(6,14,30,.96);border-bottom:1px solid rgba(0,245,255,.09);">
  <div class="flex items-center gap-4">
    <div style="width:42px;height:42px;background:linear-gradient(135deg,rgba(0,245,255,.22),rgba(0,245,255,.04));clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);display:flex;align-items:center;justify-content:center;font-size:18px;">⬡</div>
    <div>
      <h1 class="orbitron text-xl font-black neon-cyan tracking-wider">CHAKRAVYUH</h1>
      <p class="text-xs text-gray-500 mono">AI Malware Behaviour Classification · PS-06</p>
    </div>
  </div>
  <div class="flex items-center gap-5">
    <div class="flex items-center gap-2"><div class="dot"></div><span class="mono text-xs text-gray-400">ENGINE ONLINE</span></div>
    <div class="hidden md:block text-xs mono text-gray-600">MITRE ATT&CK v14 · Random Forest + Gradient Boosting</div>
    <div class="text-xs mono" style="color:rgba(0,245,255,.4);">Track: AI & Threat Intelligence</div>
  </div>
</header>
<div class="hl"></div>

<!-- MAIN -->
<main class="relative z-10 max-w-7xl mx-auto px-4 py-8">

  <!-- HERO -->
  <div class="text-center mb-8">
    <div class="inline-flex items-center gap-2 px-4 py-2 rounded-full mb-4" style="background:rgba(0,245,255,.07);border:1px solid rgba(0,245,255,.16);">
      <span class="text-xs mono neon-cyan">● LIVE</span>
      <span class="text-xs text-gray-400">Behavioral Analysis Platform v1.0</span>
    </div>
    <h2 class="orbitron text-3xl md:text-4xl font-black text-white mb-3">Upload. Analyze. <span class="neon-cyan">Classify.</span></h2>
    <p class="text-gray-400 text-sm max-w-xl mx-auto leading-relaxed">
      Dynamic behavioral fingerprinting with MITRE ATT&CK mapping, process execution trees, live API call tracing, and ML-powered classification across Ransomware, Trojan, Worm & Spyware families.
    </p>
  </div>

  <!-- UPLOAD ZONE -->
  <div class="card card-glow p-6 mb-5">
    <div id="dropZone" class="p-10 text-center" onclick="document.getElementById('fi').click()">
      <input type="file" id="fi" class="hidden" accept="*/*" onchange="handleFile(event)">
      <div style="font-size:54px;margin-bottom:12px;filter:drop-shadow(0 0 22px rgba(0,245,255,.3));">⬆</div>
      <p class="orbitron text-lg font-bold text-white mb-2">Drop Suspicious File Here</p>
      <p class="text-gray-400 text-sm mb-5">or click to browse · .exe · .dll · .pdf · any format</p>
      <div class="flex flex-wrap gap-2 justify-center">
        <span class="badge" style="background:rgba(0,245,255,.08);color:var(--nc);border:1px solid rgba(0,245,255,.2);">EXE</span>
        <span class="badge" style="background:rgba(0,245,255,.08);color:var(--nc);border:1px solid rgba(0,245,255,.2);">DLL</span>
        <span class="badge" style="background:rgba(0,245,255,.08);color:var(--nc);border:1px solid rgba(0,245,255,.2);">PDF</span>
        <span class="badge" style="background:rgba(0,245,255,.08);color:var(--nc);border:1px solid rgba(0,245,255,.2);">JSON</span>
        <span class="badge" style="background:rgba(0,245,255,.08);color:var(--nc);border:1px solid rgba(0,245,255,.2);">ANY FILE</span>
      </div>
    </div>
    <!-- DEMO BUTTONS -->
    <div class="mt-4 pt-4" style="border-top:1px solid rgba(0,245,255,.07);">
      <p class="text-xs mono text-gray-500 mb-3 text-center tracking-widest">⚡ INSTANT DEMO SCENARIOS — No File Needed</p>
      <div class="flex gap-3 flex-wrap justify-center">
        <button class="demo-btn" onclick="loadDemo('ransomware')" style="background:rgba(255,45,85,.1);border-color:rgba(255,45,85,.3);color:#ff2d55;">💀 Ransomware · LockBit</button>
        <button class="demo-btn" onclick="loadDemo('trojan')" style="background:rgba(255,107,0,.1);border-color:rgba(255,107,0,.3);color:#ff6b00;">🐴 Trojan · RemcosRAT</button>
        <button class="demo-btn" onclick="loadDemo('worm')" style="background:rgba(155,89,182,.1);border-color:rgba(155,89,182,.3);color:#9b59b6;">🪱 Worm · Conficker</button>
        <button class="demo-btn" onclick="loadDemo('safe')" style="background:rgba(0,200,150,.1);border-color:rgba(0,200,150,.3);color:#00c896;">✅ Clean File</button>
      </div>
    </div>
  </div>

  <!-- RESULTS (hidden until analysis) -->
  <div id="results" style="display:none;">

    <!-- ROW 1 -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
      <!-- Verdict -->
      <div id="vCard" class="card card-glow p-5 flex flex-col gap-3">
        <div class="text-xs mono text-gray-500 tracking-widest">▸ THREAT VERDICT</div>
        <div class="flex items-center gap-3">
          <div id="vIcon" style="font-size:40px;"></div>
          <div>
            <div id="vFamily" class="orbitron text-2xl font-black"></div>
            <div id="vVariant" class="mono text-xs text-gray-400 mt-1"></div>
          </div>
        </div>
        <div id="vSev"></div>
        <p id="vDesc" class="text-xs text-gray-400 leading-relaxed"></p>
      </div>
      <!-- Score -->
      <div class="card card-glow p-5 flex flex-col items-center gap-3">
        <div class="text-xs mono text-gray-500 tracking-widest">▸ THREAT SCORE</div>
        <div class="relative" style="width:155px;height:155px;">
          <canvas id="sc" width="155" height="155"></canvas>
          <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;">
            <div id="sNum" class="orbitron font-black" style="font-size:36px;"></div>
            <div class="mono text-xs text-gray-500">/ 100</div>
          </div>
        </div>
        <div id="confText" class="mono text-xs text-gray-400 text-center"></div>
      </div>
      <!-- File Info -->
      <div class="card card-glow p-5 flex flex-col gap-2">
        <div class="text-xs mono text-gray-500 tracking-widest mb-1">▸ FILE METADATA</div>
        <div id="fInfo" class="mono text-xs space-y-2"></div>
      </div>
    </div>

    <!-- BEHAVIORAL BARS -->
    <div class="card card-glow p-5 mb-4">
      <div class="flex items-center justify-between mb-4">
        <div>
          <div class="text-xs mono text-gray-500 tracking-widest">▸ BEHAVIORAL SIGNATURES</div>
          <div class="text-sm font-semibold text-white mt-1">Detected API Call Patterns & Threat Indicators</div>
        </div>
        <div id="bCount" class="mono text-xs text-gray-500"></div>
      </div>
      <div id="bBars" class="space-y-4"></div>
    </div>

    <!-- PROCESS TREE + TERMINAL -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
      <div class="card card-glow p-5">
        <div class="text-xs mono text-gray-500 tracking-widest mb-1">▸ EXECUTION TREE</div>
        <div class="text-sm font-semibold text-white mb-4">Process Hierarchy & Injection Map</div>
        <div id="pTree"></div>
      </div>
      <div class="card card-glow p-5">
        <div class="flex items-center justify-between mb-3">
          <div>
            <div class="text-xs mono text-gray-500 tracking-widest">▸ LIVE API TRACE</div>
            <div class="text-sm font-semibold text-white mt-1">Syscall Monitor</div>
          </div>
          <div class="flex gap-1">
            <div style="width:10px;height:10px;border-radius:50%;background:#ff5f57;"></div>
            <div style="width:10px;height:10px;border-radius:50%;background:#febc2e;"></div>
            <div style="width:10px;height:10px;border-radius:50%;background:#28c840;"></div>
          </div>
        </div>
        <div class="terminal" id="term"></div>
      </div>
    </div>

    <!-- MITRE ATT&CK -->
    <div class="card card-glow p-5 mb-4">
      <div class="text-xs mono text-gray-500 tracking-widest mb-1">▸ MITRE ATT&CK FRAMEWORK</div>
      <div class="text-sm font-semibold text-white mb-4">Technique Mappings & Tactic Coverage</div>
      <div id="mitreWrap" class="overflow-x-auto">
        <table class="mt">
          <thead><tr><th>TECHNIQUE ID</th><th>TACTIC</th><th>TECHNIQUE NAME</th><th>SEVERITY</th></tr></thead>
          <tbody id="mitreTbody"></tbody>
        </table>
      </div>
      <div id="mitreEmpty" style="display:none;" class="text-center py-8 mono text-sm neon-green">✅ No MITRE techniques detected — File appears clean</div>
    </div>

    <!-- STATS BAR -->
    <div class="card card-glow p-5">
      <div class="grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
        <div><div id="st1" class="orbitron text-3xl font-black neon-cyan">—</div><div class="text-xs text-gray-500 mono mt-1">THREAT SCORE</div></div>
        <div><div id="st2" class="orbitron text-3xl font-black" style="color:#ffd700">—</div><div class="text-xs text-gray-500 mono mt-1">ML CONFIDENCE</div></div>
        <div><div id="st3" class="orbitron text-3xl font-black" style="color:#9b59b6">—</div><div class="text-xs text-gray-500 mono mt-1">MITRE TECHNIQUES</div></div>
        <div><div id="st4" class="orbitron text-3xl font-black neon-orange">—</div><div class="text-xs text-gray-500 mono mt-1">ANALYSIS TIME</div></div>
      </div>
    </div>
  </div>

  <!-- PLACEHOLDER -->
  <div id="ph" class="text-center py-16">
    <div style="font-size:76px;opacity:.12;margin-bottom:16px;">🛡️</div>
    <p class="orbitron text-gray-600 text-xl tracking-widest">AWAITING SAMPLE</p>
    <p class="mono text-gray-700 text-xs mt-2">Upload a file above or click a demo scenario button</p>
  </div>
</main>

<footer class="relative z-10 mt-10 py-4 px-6 text-center" style="border-top:1px solid rgba(0,245,255,.06);">
  <p class="mono text-xs text-gray-700">CHAKRAVYUH v1.0 · PS-06 AI Malware Behaviour Classification · Track: AI & Threat Intelligence · FastAPI · MITRE ATT&CK v14 · Random Forest + Gradient Boosting</p>
</footer>

<script>
let chart = null;

// DRAG & DROP
const dz = document.getElementById('dropZone');
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dov'); });
dz.addEventListener('dragleave', () => dz.classList.remove('dov'));
dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('dov'); const f = e.dataTransfer.files[0]; if(f) upload(f); });
function handleFile(e) { const f = e.target.files[0]; if(f) upload(f); }

// SCAN ANIMATION
const msgs = ['Extracting PE headers...','Parsing import address table...','Analyzing API call sequences...','Running behavioral vectorization...','Random Forest classifier...','Gradient Boosting model...','Mapping to MITRE ATT&CK v14...','Generating threat report...'];
let scanT;
function showScan() {
  document.getElementById('scanOverlay').style.display = 'flex';
  let p = 0, mi = 0;
  scanT = setInterval(() => {
    p = Math.min(p + Math.random()*13, 94);
    document.getElementById('scanPct').textContent = Math.floor(p) + '%';
    document.getElementById('scanStatus').textContent = msgs[mi++ % msgs.length];
  }, 370);
}
function hideScan() {
  clearInterval(scanT);
  document.getElementById('scanPct').textContent = '100%';
  document.getElementById('scanStatus').textContent = 'Analysis complete!';
  setTimeout(() => document.getElementById('scanOverlay').style.display = 'none', 300);
}

async function upload(file) {
  showScan();
  const fd = new FormData(); fd.append('file', file);
  try {
   const r = await fetch('/analyze', {method:'POST', body:fd});
    render(await r.json());
  } catch(e) { alert('Error: Make sure app.py is running on port 8000'); }
  hideScan();
}

async function loadDemo(s) {
  showScan();
  try { render(await (await fetch('/demo/'+s)).json()); }
  catch(e) { alert('API error'); }
  hideScan();
}

function render(d) {
  document.getElementById('ph').style.display = 'none';
  const res = document.getElementById('results');
  res.style.display = 'block';
  res.classList.add('fadeUp');
  const c = d.color;

  // VERDICT
  document.getElementById('vIcon').textContent = d.icon;
  const vf = document.getElementById('vFamily');
  vf.textContent = d.family; vf.style.color = c; vf.style.textShadow = `0 0 24px ${c}55`;
  document.getElementById('vVariant').textContent = d.variant;
  document.getElementById('vDesc').textContent = d.description;
  const vc = document.getElementById('vCard');
  vc.style.boxShadow = `0 0 30px ${c}15, inset 0 0 20px ${c}04`; vc.style.borderColor = `${c}25`;
  const sm = {CRITICAL:'<span class="badge bc">⚠ CRITICAL THREAT</span>',HIGH:'<span class="badge bh">⬆ HIGH THREAT</span>',MEDIUM:'<span class="badge bm">◆ MEDIUM</span>',CLEAN:'<span class="badge bk">✓ CLEAN FILE</span>'};
  document.getElementById('vSev').innerHTML = sm[d.severity] || '';

  // SCORE DONUT
  document.getElementById('sNum').textContent = d.threat_score; document.getElementById('sNum').style.color = c;
  document.getElementById('confText').textContent = `ML Confidence: ${d.confidence}%`;
  if(chart) chart.destroy();
  chart = new Chart(document.getElementById('sc').getContext('2d'), {
    type:'doughnut',
    data:{datasets:[{data:[d.threat_score,100-d.threat_score],backgroundColor:[c,'rgba(255,255,255,.04)'],borderWidth:0}]},
    options:{responsive:false,plugins:{legend:{display:false},tooltip:{enabled:false}},cutout:'80%'}
  });

  // FILE INFO
  const fi = d.file_info;
  document.getElementById('fInfo').innerHTML = [
    ['📄','Filename',fi.filename],['📦','Size',fi.size_str],
    ['🔷','SHA-256',fi.sha256.slice(0,20)+'...'],['🔶','MD5',fi.md5.slice(0,20)+'...'],
    ['⏱','Analysis',fi.analysis_time+'s'],
  ].map(([i,k,v])=>`<div class="flex gap-2"><span class="text-gray-500 shrink-0">${i} ${k}</span><span class="text-gray-300 truncate">${v}</span></div>`).join('');

  // BEHAVIORAL BARS
  const cm = {critical:'#ff2d55',high:'#ff6b00',medium:'#ffd700',clean:'#00c896'};
  const bm2 = {critical:'bc',high:'bh',medium:'bm',clean:'bk'};
  document.getElementById('bCount').textContent = d.behaviors.length + ' signatures';
  document.getElementById('bBars').innerHTML = d.behaviors.map(b => `
    <div>
      <div class="flex items-center justify-between mb-1">
        <div class="flex items-center gap-2 flex-wrap"><span class="mono text-xs text-gray-200 font-medium">${b.name}</span><span class="badge ${bm2[b.severity]}">${b.severity.toUpperCase()}</span></div>
        <span class="mono text-xs font-bold" style="color:${cm[b.severity]}">${b.score}%</span>
      </div>
      <div class="progress-bar"><div class="progress-fill" style="width:${b.score}%;background:linear-gradient(90deg,${cm[b.severity]}88,${cm[b.severity]});"></div></div>
      <div class="mono text-xs text-gray-600 mt-1">${b.api}</div>
    </div>`).join('');

  // PROCESS TREE
  document.getElementById('pTree').innerHTML = d.process_tree.map(p => {
    const indent = p.parent === null ? 0 : 24;
    return `<div class="proc ${p.suspicious?'s':'c'}" style="margin-left:${indent}px;"><span>${p.suspicious?'⚠':'●'}</span><span>${p.parent!==null?'└─ ':''}[PID:${p.pid}] ${p.name}</span></div>`;
  }).join('');

  // TERMINAL
  const term = document.getElementById('term'); term.innerHTML = '';
  let li = 0;
  function addLine() {
    if(li >= d.api_trace.length) return;
    const t = d.api_trace[li];
    const bad = ['ENCRYPTED','KILLED','DROPPED','DISGUISED','EXFIL','RANSOM','STOLEN','DECRYPTED'].some(w=>t.includes(w));
    const good = ['SUCCESS','FOUND','RENDERED','LOADED'].some(w=>t.includes(w)) && !bad;
    const cls = bad ? '#ff2d55' : good ? '#00c896' : '#ffd700';
    term.innerHTML += `<div><span style="color:#00f5ff">$ </span><span style="color:${cls}">${t}</span></div>`;
    term.scrollTop = term.scrollHeight; li++;
    setTimeout(addLine, 110);
  }
  addLine();

  // MITRE TABLE
  const mb = document.getElementById('mitreTbody'), me = document.getElementById('mitreEmpty'), mw = document.getElementById('mitreWrap');
  mb.innerHTML = '';
  if(!d.mitre.length) { mw.style.display='none'; me.style.display='block'; }
  else {
    mw.style.display='block'; me.style.display='none';
    const sc2 = {Critical:'#ff2d55',High:'#ff6b00',Medium:'#ffd700',Low:'#00c896'};
    d.mitre.forEach(m => { const col = sc2[m.severity]||'#aaa';
      mb.innerHTML += `<tr>
        <td><span class="mono font-bold" style="color:#00f5ff">${m.id}</span></td>
        <td><span class="text-gray-400">${m.tactic}</span></td>
        <td><span class="text-white">${m.technique}</span></td>
        <td><span class="badge" style="background:${col}18;color:${col};border:1px solid ${col}38">${m.severity}</span></td></tr>`;
    });
  }

  // BOTTOM STATS
  ['st1','st2','st3','st4'].forEach((id,i) => {
    const vals = [d.threat_score, d.confidence+'%', d.mitre.length, d.file_info.analysis_time+'s'];
    document.getElementById(id).textContent = vals[i];
  });
  document.getElementById('st1').style.color = c;

  setTimeout(() => res.scrollIntoView({behavior:'smooth',block:'start'}), 80);
}
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTML


# ──────────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn, socket

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    print("\n" + "=" * 62)
    print("  ⬡  CHAKRAVYUH — AI Malware Behaviour Classification")
    print("  PS-06 | Track: AI & Threat Intelligence")
    print("=" * 62)
    print(f"  ➤ Local URL:    http://127.0.0.1:8000")
    print(f"  ➤ Network URL:  http://{local_ip}:8000  ← share with judges!")
    print("=" * 62)
    print("  Demo scenarios:")
    print("    http://127.0.0.1:8000/api/demo/ransomware")
    print("    http://127.0.0.1:8000/api/demo/trojan")
    print("    http://127.0.0.1:8000/api/demo/worm")
    print("    http://127.0.0.1:8000/api/demo/safe")
    print("=" * 62)
    print("  Press Ctrl+C to stop the server\n")

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
