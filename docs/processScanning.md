# FOSS tools for automated Windows security auditing

**The strongest open-source security toolkit for Windows combines six core tools: HollowsHunter for live process scanning, YARA for pattern-based malware detection, ClamAV for signature scanning, Hayabusa and Chainsaw for event log threat hunting, and Velociraptor to orchestrate it all.** Each is genuinely free and open-source, fully CLI-automatable, community-vetted, and designed to run with elevated privileges safely. Together they cover process analysis, log forensics, malware detection, and persistence auditing — forming a pipeline that can be scripted in PowerShell and scheduled via Task Scheduler. The critical caveat: Sysinternals tools (Autoruns, Sysmon, Sigcheck) are **not** open-source but are essential complements, and their Microsoft provenance makes them trustworthy enough to include in any serious workflow.

---

## Process scanning: HollowsHunter and PE-sieve catch what antivirus misses

The most critical gap in most security setups is detecting **in-memory malware** — process hollowing, reflective DLL injection, shellcode injection, and inline API hooks. Two tools from researcher hasherezade (Aleksandra Doniec) fill this gap exceptionally well.

**PE-sieve** scans a single process by PID for memory anomalies: hollowed modules, injected code, patched entry points, and suspicious threads. It operates passively (read-only, no interference with the target process), outputs JSON reports, and dumps suspicious artifacts for further analysis. **HollowsHunter** wraps PE-sieve to scan **all running processes** system-wide, and supports continuous monitoring via a `/loop` flag and ETW-triggered scanning via `/etw` mode. Both are BSD 2-Clause licensed, have **3,449 and 2,235 GitHub stars** respectively, and are actively maintained with the latest release (v0.4.1.1) shipping in February 2025 with Windows 11 fixes.

CLI automation is straightforward:
```
hollows_hunter.exe /loop /json /dir C:\SecurityLogs\hollows\
```

For traditional process monitoring, **System Informer** (formerly Process Hacker) is the premier open-source tool with **~13,300 GitHub stars** and an MIT license. It provides deep process trees, DLL inspection, network connection mapping, handle enumeration, and GPU/memory graphs. However, it is **GUI-only with no CLI support** — the maintainers have explicitly declined CLI feature requests citing security concerns. This makes it excellent for interactive investigation but unsuitable for automated pipelines. Use it as a manual complement alongside HollowsHunter's automated scanning.

**Fibratus** deserves attention as an ETW-based runtime detection engine. Licensed Apache 2.0 with **~2,330 stars**, it captures kernel events (process creation, network activity, file operations, registry changes) and applies YAML-based detection rules mapped to MITRE ATT&CK. It can output to Elasticsearch, AMQP, or files, and supports YARA memory scanning. Think of it as an open-source alternative to Sysmon that also does detection, not just logging.

---

## Malware and file scanning: ClamAV plus YARA covers signatures and custom patterns

**ClamAV** remains the only mature open-source antivirus engine. Licensed GPLv2 and maintained by Cisco Talos, it has **~6,000 GitHub stars** and receives signature database updates every four hours. The Windows CLI tools — `clamscan.exe` for on-demand scanning, `clamdscan.exe` for daemon-accelerated scanning, and `freshclam.exe` for signature updates — are fully scriptable. Detection rates sit around **60% for commodity malware** per a Splunk study, making ClamAV a useful baseline layer but not a standalone defense. It excels at catching known trojans, botnets, and malicious documents (DOCX, DOC, PDF), but struggles with RATs, info-stealers, and obfuscated payloads.

**YARA** fills the gap ClamAV leaves. Licensed BSD 3-Clause with **~9,300 GitHub stars**, YARA is a pattern-matching engine that lets analysts write rules describing malware families by their binary signatures, strings, hex patterns, and behavioral markers. It scans files and — critically — **running process memory** (`yara.exe rules.yar <pid>`). The successor **YARA-X**, a Rust rewrite also BSD 3-Clause, is battle-tested at VirusTotal scanning billions of files in production and offers better performance and error handling.

The power of YARA comes from community rule repositories:

- **SigmaHQ/sigma** — ~10,100 stars, the universal detection rule standard
- **Neo23x0/signature-base** — ~2,600 stars, Florian Roth's widely-used IOC/YARA database
- **Yara-Rules/rules** — GPLv2, large curated collection covering malware, exploits, packers, webshells
- **ReversingLabs YARA Rules** — MIT, ~810 stars, professionally tested on 10B+ binaries
- **InQuest/awesome-yara** — meta-repository listing dozens of sources

An automated scan combining both engines covers known signatures (ClamAV) and targeted patterns (YARA) in a single scheduled pipeline.

---

## Event log threat hunting: Hayabusa and Chainsaw are transformative

Two Rust-based tools have revolutionized Windows Event Log analysis, making what once required expensive SIEMs accessible from the command line.

**Hayabusa** (Yamato Security, AGPL-3.0, **~3,000 stars**, 4,886 commits) is the most feature-rich option. It generates forensic timelines from .evtx files, supports **live analysis** of the local system's logs (`--live-analysis`), and is the only open-source tool with **full Sigma v2 specification support** including correlation rules. It ships with **4,000+ curated detection rules** and outputs CSV or JSONL compatible with Timesketch, SOF-ELK, and Elastic Stack. Its companion tool **Takajō** performs result analysis including process tree generation, command-line stacking, and DNS/IP pivot analysis.

**Chainsaw** (WithSecure/F-Secure, GPL-3.0, **~3,400 stars**) takes a broader approach. Beyond .evtx files, it analyzes **MFT records, Shimcache, SRUM databases, and registry hives**. It natively loads Sigma rules and includes built-in detections for AV alert parsing, log clearing, brute force attacks, and suspicious logon patterns. Output formats include CSV, JSON, and JSONL.

The two tools are complementary rather than competing. Hayabusa excels at **deep timeline generation** and live analysis; Chainsaw excels at **broader artifact coverage** and forensic triage. Both integrate with Velociraptor for remote collection.

**DeepBlueCLI** (SANS, GPL-3.0, ~2,300 stars) is a simpler PowerShell alternative that detects password spraying, obfuscated PowerShell, credential dumping patterns, and event log clearing. It's ideal for quick triage but has been essentially unmaintained since October 2023, making Hayabusa and Chainsaw the preferred choices for production use.

---

## Sysmon and Sysinternals: not FOSS but indispensable

A critical distinction the user should understand: **Sysinternals tools including Sysmon are proprietary freeware**, not open-source. They are distributed under the Sysinternals Software License — free to use, but source code is unavailable and redistribution is prohibited. However, their provenance makes them uniquely trustworthy: created by Mark Russinovich (now CTO of Microsoft Azure), owned by Microsoft, signed by Microsoft, and endorsed by CISA, SANS, and virtually every security organization.

**Sysmon** is the foundation of Windows endpoint visibility. It logs **29 event types** — process creation with full command lines and hashes, network connections mapped to processes, DLL loading, registry modifications, DNS queries, file creation/deletion, remote thread creation, and process tampering — all written to the Windows Event Log. It installs as a boot-start driver, runs as a protected process, and is being **natively integrated into Windows 11 and Server 2025**. Configuration is fully CLI-driven via XML files, and community configs like **SwiftOnSecurity/sysmon-config** (~5,300 stars) and **olafhartong/sysmon-modular** provide ATT&CK-mapped baselines.

Sysmon generates the telemetry; Hayabusa and Chainsaw analyze it. This pairing gives you enterprise-grade visibility for free.

The CLI-capable Sysinternals tools essential for automated auditing are:

- **autorunsc.exe** — enumerates all persistence locations (Run keys, services, scheduled tasks, WMI, BHOs, drivers) with VirusTotal hash checking, digital signature verification, and CSV/XML output
- **sigcheck.exe** — verifies digital signatures and finds unsigned executables system-wide
- **listdlls.exe** — detects unsigned DLLs loaded into processes (DLL injection indicator)
- **handle.exe** — identifies which process holds locks on files/objects
- **procmon.exe** — captures real-time file system, registry, network, and process activity with CLI automation via `/BackingFile`, `/LoadConfig`, `/RunTime`, and `/Quiet` flags

---

## Velociraptor and Wazuh orchestrate everything at scale

**Velociraptor** (AGPLv3, **~3,680 stars**) is arguably the most important tool in this entire ecosystem. Developed by Velocidex (now part of Rapid7), it combines endpoint visibility, forensic collection, threat hunting, and continuous monitoring in a single Go binary. It runs as both client and server, handles **15,000+ endpoints** from one server, and uses VQL (Velociraptor Query Language) for fully scriptable operations. It natively integrates Sigma rules, YARA scanning, ETW monitoring, and has built-in artifacts for running Sysinternals Autoruns, Chainsaw, and Hayabusa remotely. For a single machine, the `velociraptor gui` command launches a local instance; for fleets, it scales to enterprise deployment. Current version v0.75.6 shipped December 2025 with extremely active development.

**Wazuh** (GPLv2, **~14,100 stars** — the highest of any tool discussed) is a full XDR/SIEM platform offering agent-based monitoring, file integrity monitoring, vulnerability detection, security configuration assessment, and compliance reporting. Its Windows agent collects event logs, monitors the registry, ingests Sysmon data, and performs rootkit detection. The tradeoff: Wazuh requires deploying a manager, indexer, and dashboard stack (Linux-based), making it heavyweight for a single machine but ideal for any multi-endpoint environment. It provides a REST API for full programmatic control and integrates with TheHive, MISP, VirusTotal, and SOAR platforms.

For a single Windows machine, **Velociraptor in local mode** is the better orchestrator. For a network, **Wazuh** provides continuous monitoring while Velociraptor handles on-demand hunting and forensics.

---

## Building an automated scanning pipeline

Here is a concrete, fully scriptable pipeline using the tools above, ordered by execution priority:

**Layer 1 — Continuous telemetry (install once, runs always):**
Deploy Sysmon with the SwiftOnSecurity or sysmon-modular config. This generates the raw event data everything else depends on. Add Wazuh agent if you need continuous alerting.

**Layer 2 — Scheduled scanning (daily via Task Scheduler):**

| Step | Tool | Command | Purpose |
|------|------|---------|---------|
| 1 | freshclam | `freshclam.exe` | Update ClamAV signatures |
| 2 | ClamAV | `clamscan.exe -r --log=scan.log C:\Users` | Signature-based file scan |
| 3 | YARA-X | `yr.exe scan rules/ C:\Users --output=yara.json` | Pattern-based malware scan |
| 4 | HollowsHunter | `hollows_hunter.exe /json /dir results\` | Scan all processes for implants |
| 5 | Hayabusa | `hayabusa.exe csv-timeline -l -m medium -o timeline.csv` | Live event log threat hunting |
| 6 | autorunsc | `autorunsc64.exe -a * -c -h -s -m -vt -accepteula` | Persistence mechanism audit |
| 7 | sigcheck | `sigcheck64.exe -u -e -s C:\Windows\System32` | Find unsigned system binaries |
| 8 | listdlls | `listdlls64.exe -u` | Detect unsigned DLL injection |

**Layer 3 — On-demand forensics (incident response):**
Use Chainsaw for broad artifact triage (EVTX + MFT + Shimcache + SRUM), Volatility 3 for memory dump analysis (note: its custom VSL license is **not** standard FOSS, though the older Volatility 2 was GPL-2.0), and Eric Zimmerman's MIT-licensed CLI tools (MFTECmd, EvtxECmd, AmcacheParser, PECmd) for targeted artifact parsing.

---

## Complete tool reference with trust indicators

| Tool | License | FOSS? | GitHub ★ | CLI? | Maintained? | Primary use |
|------|---------|-------|----------|------|-------------|-------------|
| **HollowsHunter** | BSD 2-Clause | ✅ | 2,235 | ✅ Full | ✅ Active | Process implant detection |
| **PE-sieve** | BSD 2-Clause | ✅ | 3,449 | ✅ Full | ✅ Active | Single-process memory scan |
| **YARA / YARA-X** | BSD 3-Clause | ✅ | 9,300 / 942 | ✅ Full | ✅ Active | Pattern-based malware detection |
| **ClamAV** | GPLv2 | ✅ | 6,000 | ✅ Full | ✅ Active | Signature-based AV scanning |
| **Hayabusa** | AGPL-3.0 | ✅ | 3,000 | ✅ Full | ✅ Very active | Event log threat hunting/timeline |
| **Chainsaw** | GPL-3.0 | ✅ | 3,400 | ✅ Full | ✅ Active | Multi-artifact forensic triage |
| **Velociraptor** | AGPLv3 | ✅ | 3,680 | ✅ Full | ✅ Very active | Endpoint visibility/orchestration |
| **Wazuh** | GPLv2 | ✅ | 14,100 | ✅ API+CLI | ✅ Very active | Continuous XDR/SIEM monitoring |
| **Fibratus** | Apache 2.0 | ✅ | 2,330 | ✅ Full | ✅ Active | ETW-based runtime detection |
| **System Informer** | MIT | ✅ | 13,300 | ❌ GUI only | ✅ Active | Interactive process investigation |
| **Sigma Rules** | DRL 1.1 | ✅ | 10,100 | N/A | ✅ Very active | Universal detection rule format |
| **DeepBlueCLI** | GPL-3.0 | ✅ | 2,300 | ✅ Full | ⚠️ Stale | Quick PowerShell log triage |
| **Volatility 3** | VSL (custom) | ⚠️ | 3,800 | ✅ Full | ✅ Active | Memory forensics |
| **Sysmon** | Proprietary freeware | ❌ | N/A | ✅ Config | ✅ Active | Endpoint telemetry generation |
| **Sysinternals CLI tools** | Proprietary freeware | ❌ | N/A | ✅ Full | ✅ Active | Persistence/signature auditing |
| **Eric Zimmerman tools** | MIT (mostly) | ✅ | Various | ✅ Full | ✅ Very active | Windows artifact forensics |

---

## Conclusion

The Windows FOSS security landscape is stronger than most users realize. **HollowsHunter + YARA + ClamAV** covers file and process-level malware detection across three complementary methods (memory anomaly, pattern matching, and signature scanning). **Hayabusa + Chainsaw + Sysmon** delivers event log threat hunting that rivals commercial SIEM capabilities. **Velociraptor** ties everything together as an orchestration layer. The only significant gap is that the two most essential process-level tools — Sysmon for telemetry and Sysinternals CLI tools for persistence auditing — are proprietary freeware rather than FOSS. Their Microsoft provenance and universal security community endorsement make this an acceptable tradeoff. The complete pipeline described above can be implemented in a single PowerShell script, scheduled via Task Scheduler, and run with no commercial licenses — giving a single Windows machine or a small fleet enterprise-grade security monitoring at zero cost.