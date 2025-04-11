# 🛡️ PodZV - CVE Fix Verifier

**PodZV** is a lightweight, terminal-based security tool that checks if known CVEs have an available fix. It queries multiple trusted sources — NVD, OSV.dev, and Red Hat — and aggregates information about fix status, references, and severity.

---

## 🚀 Features

- ✅ CVE fix availability checker
- 🌐 Queries **NVD**, **OSV.dev**, and **Red Hat Security API**
- 📊 Outputs results to **CSV** and **PDF**
- 🔍 Optional debug output for raw API responses

---

## 📦 Requirements

Install dependencies with:

```bash
pip install -r requirements.txt

```
**Syntax**

`python3 PodZV.py --cve-list <cves.txt> [--output <output.csv>] [--pdf <report.pdf>] [--debug] [--quiet]`


```bash

# Basic usage
python PodZV.py --cve-list cves.txt

# Output to CSV
python PodZV.py --cve-list cves.txt --output results.csv

# Output to PDF
python PodZV.py --cve-list cves.txt --pdf report.pdf

# Full usage with all options
python PodZV.py --cve-list cves.txt --output results.csv --pdf report.pdf --debug

# Quiet mode (no printing to terminal)
python PodZV.py --cve-list cves.txt --quiet

```
<div align="center">
Built By Neo
</div>
