cd ~/scans
cat > reporter.py <<'EOF'
#!/usr/bin/env python3
import xml.etree.ElementTree as ET
from datetime import datetime
import html
import sys

def parse_nmap_xml(path):
    tree = ET.parse(path)
    root = tree.getroot()
    hosts = []
    for host in root.findall('host'):
        addr_el = host.find('address')
        addr = addr_el.get('addr') if addr_el is not None else 'unknown'
        ports = []
        ports_el = host.find('ports')
        if ports_el is not None:
            for p in ports_el.findall('port'):
                portnum = p.get('portid')
                proto = p.get('protocol')
                state_el = p.find('state')
                state = state_el.get('state') if state_el is not None else ''
                svc = p.find('service')
                svcname = svc.get('name') if svc is not None else ''
                version = svc.get('product') if svc is not None and 'product' in svc.attrib else ''
                ports.append({'port':portnum, 'proto':proto, 'state':state, 'service':svcname, 'version':version})
        hosts.append({'addr':addr, 'ports':ports})
    return hosts

def parse_nikto_txt(path):
    issues = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line=line.strip()
                if line:
                    issues.append(line)
    except FileNotFoundError:
        pass
    return issues

def severity_guess(port, service, nikto_issues):
    if any(s for s in nikto_issues if '500' in s or 'XSS' in s.upper() or 'SQL' in s.upper()):
        return 'High'
    if service in ('ftp','telnet','smtp') or port in ('21','23','25'):
        return 'Medium'
    return 'Low'

def make_html_report(hosts, nikto, outpath='report.html'):
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    html_lines = [f"<html><head><meta charset='utf-8'><title>Scan Report</title></head><body>",
                  f"<h1>Automated Scan Report</h1><p>Generated: {now}</p>"]
    for h in hosts:
        html_lines.append(f"<h2>Host: {html.escape(h['addr'])}</h2>")
        if not h['ports']:
            html_lines.append("<p>No open ports found.</p>")
        else:
            html_lines.append("<table border='1' cellpadding='6'><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Severity</th></tr>")
            for p in h['ports']:
                sev = severity_guess(p['port'], p['service'], nikto)
                html_lines.append("<tr>"
                                  f"<td>{html.escape(p['port'])}</td>"
                                  f"<td>{html.escape(p['proto'])}</td>"
                                  f"<td>{html.escape(p['state'])}</td>"
                                  f"<td>{html.escape(p['service'])} {html.escape(p['version'])}</td>"
                                  f"<td>{sev}</td></tr>")
            html_lines.append("</table>")
    if nikto:
        html_lines.append("<h3>Nikto Findings</h3><ul>")
        for it in nikto:
            html_lines.append(f"<li>{html.escape(it)}</li>")
        html_lines.append("</ul>")
    html_lines.append("<p>End of report.</p></body></html>")
    with open(outpath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html_lines))
    print(f"Report written to {outpath}")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python reporter.py nmap_scan.xml nikto_output.txt [report.html]")
        sys.exit(1)
    nmap_xml = sys.argv[1]
    nikto_txt = sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else 'report.html'
    hosts = parse_nmap_xml(nmap_xml)
    nik = parse_nikto_txt(nikto_txt)
    make_html_report(hosts, nik, out)
EOF
chmod +x reporter.py