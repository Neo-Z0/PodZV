import argparse
import httpx
import csv
import json
from time import sleep
from rich.console import Console
from rich.text import Text
from rich.table import Table
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table as PdfTable
from reportlab.lib.styles import getSampleStyleSheet

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
OSV_API = "https://api.osv.dev/v1/query"
REDHAT_API = "https://access.redhat.com/labs/securitydataapi/cve/"
USER_AGENT = {'User-Agent': 'cve-verifier/1.0'}

console = Console()

FIX_KEYWORDS = [
    "patch", "fix", "advisory", "release", "commit", "hotfix", "bugzilla",
    "resolved", "changelog", "security-update", "mitigation", "rpm", "update"
]

def print_typing_banner():
    ascii_art = r"""
 ______    _____   _____    _______  _    _ 
(_____ \  / ___ \ (____ \  (_______)| |  | |
 _____) )| |   | | _   \ \    __    | |  | |
|  ____/ | |   | || |   | |  / /     \ \/ / 
| |      | |___| || |__/ /  / /____   \  /  
|_|       \_____/ |_____/  (_______)   \/   
                                            
              V1.0 By Neo
"""
    banner = Text(ascii_art, style="bold green", no_wrap=True, overflow="ignore")
    console.print(banner)
    sleep(1)

def fetch_cve_nvd(cve_id):
    url = f"{NVD_API}{cve_id}"
    try:
        response = httpx.get(url, headers=USER_AGENT, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"NVD error: Status {response.status_code}"}
    except Exception as e:
        return {"error": f"NVD error fetching {cve_id}: {e}"}

def fetch_cve_osv(cve_id):
    try:
        response = httpx.post(OSV_API, json={"cve_id": cve_id}, headers=USER_AGENT, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"OSV error: Status {response.status_code}"}
    except Exception as e:
        return {"error": f"OSV error fetching {cve_id}: {e}"}

def fetch_cve_redhat(cve_id):
    try:
        response = httpx.get(f"{REDHAT_API}{cve_id}.json", headers=USER_AGENT, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Red Hat error: Status {response.status_code}"}
    except Exception as e:
        return {"error": f"Red Hat error fetching {cve_id}: {e}"}

def url_has_fix_keywords(url):
    return any(kw in url.lower() for kw in FIX_KEYWORDS)

def parse_nvd(cve_json):
    if "error" in cve_json:
        return None
    try:
        cve_item = cve_json.get("vulnerabilities", [])[0].get("cve")
        cve_id = cve_item.get("id")
        description = cve_item.get("descriptions", [{}])[0].get("value", "")
        severity = cve_item.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
        references = [r.get("url") for r in cve_item.get("references", []) if r.get("url")]

        fix_refs = [ref for ref in references if url_has_fix_keywords(ref)]
        fix_available = len(fix_refs) > 0

        return {
            "source": "NVD",
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "references": references,
            "fix_available": fix_available,
            "fix_references": fix_refs
        }
    except:
        return None

def parse_osv(osv_json):
    if not osv_json or "error" in osv_json:
        return None

    references = [r.get("url") for r in osv_json.get("references", []) if r.get("url")]
    fix_refs = [r for r in references if url_has_fix_keywords(r)]
    fix_available = len(fix_refs) > 0

    for affected in osv_json.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if event.get("fixed"):
                    fix_available = True
                    fix_refs.append(event.get("fixed"))

    return {
        "source": "OSV",
        "cve_id": osv_json.get("id", ""),
        "description": osv_json.get("summary", ""),
        "severity": "UNKNOWN",
        "references": references,
        "fix_available": fix_available,
        "fix_references": list(set(fix_refs))
    }

def parse_redhat(redhat_json):
    if not redhat_json or "error" in redhat_json:
        return None

    references = redhat_json.get("references", [])
    fix_refs = [r for r in references if url_has_fix_keywords(r)]
    fix_available = len(fix_refs) > 0

    for pkg in redhat_json.get("package_state", []):
        if pkg.get("fix_state") == "Fixed":
            fix_available = True
            if pkg.get("package_name"):
                fix_refs.append(pkg.get("package_name"))

    return {
        "source": "RedHat",
        "cve_id": redhat_json.get("CVE", ""),
        "description": redhat_json.get("bugzilla_description", ""),
        "severity": redhat_json.get("cvss3_score", "UNKNOWN"),
        "references": references,
        "fix_available": fix_available,
        "fix_references": list(set(fix_refs))
    }

def print_result(entry):
    table = Table(title=f"CVE Report: {entry['cve_id']}", show_lines=True)
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="magenta")
    table.add_column("Fix Available", style="green")
    table.add_column("Fix References", style="yellow")

    table.add_row(
        entry['cve_id'],
        entry['severity'],
        str(entry['fix_available']),
        "\n".join(entry['fix_references']) or "-"
    )
    console.print(table)

def generate_pdf_report(results, pdf_file):
    doc = SimpleDocTemplate(pdf_file, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [Paragraph("CVE Fix Availability Report", styles['Title']), Spacer(1, 12)]

    for entry in results:
        story.append(Paragraph(f"<b>CVE ID:</b> {entry['cve_id']}", styles['Heading3']))
        story.append(Paragraph(f"<b>Severity:</b> {entry['severity']}", styles['Normal']))
        story.append(Paragraph(f"<b>Fix Available:</b> {entry['fix_available']}", styles['Normal']))
        story.append(Paragraph(f"<b>Fix References:</b>", styles['Normal']))
        refs = entry['fix_references'] or ['-']
        story.extend([Paragraph(ref, styles['Code']) for ref in refs])
        story.append(Spacer(1, 12))

    doc.build(story)
    print(f"[+] PDF report written to {pdf_file}")

def process_cve_list(cve_list_file, output_csv=None, output_pdf=None, show_debug=False, quiet=False):
    with open(cve_list_file, 'r') as f:
        cves = [line.strip() for line in f if line.strip()]

    results = []
    for cve in cves:
        if not quiet:
            print(f"[*] Checking {cve}...")
        entry = {
            "cve_id": cve,
            "description": "",
            "severity": "UNKNOWN",
            "references": [],
            "fix_available": False,
            "fix_references": []
        }

        for name, source_fn, parser_fn in [
            ("NVD", fetch_cve_nvd, parse_nvd),
            ("OSV", fetch_cve_osv, parse_osv),
            ("RedHat", fetch_cve_redhat, parse_redhat)
        ]:
            data = source_fn(cve)
            if show_debug and not quiet:
                print(f"[DEBUG] Raw {name} response for {cve}:", json.dumps(data, indent=2) if data else "No data")
            if data:
                parsed = parser_fn(data)
                if parsed:
                    entry["description"] = entry["description"] or parsed["description"]
                    entry["severity"] = parsed["severity"] if entry["severity"] == "UNKNOWN" else entry["severity"]
                    entry["references"].extend(parsed["references"])
                    if parsed.get("fix_available"):
                        entry["fix_available"] = True
                        entry["fix_references"].extend(parsed.get("fix_references", []))

        entry['references'] = list(set(entry['references']))
        entry['fix_references'] = list(set(entry['fix_references']))
        results.append(entry)
        if not quiet:
            print_result(entry)
        sleep(1.5)

    if output_csv:
        with open(output_csv, 'w', newline='') as csvfile:
            fieldnames = ["cve_id", "description", "severity", "fix_available", "fix_references", "references"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for item in results:
                writer.writerow({
                    "cve_id": item['cve_id'],
                    "description": item['description'],
                    "severity": item['severity'],
                    "fix_available": item['fix_available'],
                    "fix_references": " | ".join(item['fix_references']),
                    "references": " | ".join(item['references'])
                })
        print(f"[+] Output written to {output_csv}")

    if output_pdf:
        generate_pdf_report(results, output_pdf)

if __name__ == '__main__':
    print_typing_banner()

    parser = argparse.ArgumentParser(description="CVE Fix Verifier using NVD, OSV.dev, and Red Hat")
    parser.add_argument('--cve-list', help='File containing list of CVEs (one per line)')
    parser.add_argument('--output', help='CSV output file (optional)', default=None)
    parser.add_argument('--pdf', help='PDF output file (optional)', default=None)
    parser.add_argument('--debug', action='store_true', help='Print raw API responses')
    parser.add_argument('--quiet', action='store_true', help='Suppress status and API debug output')
    args = parser.parse_args()

    if args.cve_list:
        process_cve_list(args.cve_list, args.output, args.pdf, args.debug, args.quiet)
    else:
        print("[!] Please provide --cve-list to proceed.")
