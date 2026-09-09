# NexusLFI 🛡️

**NexusLFI** is a high-performance Python security utility designed for automated Path Traversal and Local File Inclusion (LFI) vulnerability discovery. Built with a multi-threaded execution engine and intelligent response matching, NexusLFI efficiently crawls web applications, discovers sub-paths, and tests parameters against sensitive system file signatures to streamline web penetration testing and bug bounty workflows.

---

## 🚀 Features

- **Automated Link Crawling:** Automatically extracts and scopes sub-paths from the target index page within the same domain.
- **Multi-threaded Scanning:** Utilizes Python's `ThreadPoolExecutor` for concurrent execution and high-speed fuzzing (up to 50–100 workers).
- **Smart Response Matching:** Evaluates response bodies against predefined signatures (e.g., `root:x:`, `[extensions]`) to eliminate false positives.
- **Dual-Mode Testing & Comprehensive Vectors:** Supports URL parameter-based scanning, POST parameter injection, HTTP Header testing (`X-Forwarded-For`, `User-Agent`, `Referer`, `Cookie`, etc.), and Direct Path Traversal.
- **Extensive Payloads Repository:** Includes built-in default payloads alongside a dedicated `payloads.txt` file for deep fuzzing modes, covering Linux/Windows LFI paths, wrapper techniques (`php://filter`), and encoding variations.
- **Interactive Terminal UI:** Features a clean ASCII banner, real-time status counters, and color-coded HTTP status tracking.
---

## 📋 Requirements

- Python 3.x
- `requests` library

---

## Disclaimer
NexusLFI is intended strictly for authorized security research, ethical hacking, and bug bounty programs. The author assumes no liability and is not responsible for any misuse, unauthorized scanning, or damage caused by this software. Users must ensure they have explicit permission from the system owners before conducting any security testing.
