import datetime
import io

from jinja2 import Template
from sqlalchemy.orm import Session

from app.models.device import Device

REPORT_TEMPLATE = Template("""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>IoT Vulnerability Report — {{ manufacturer }}</title>
<style>
body{font-family:system-ui,sans-serif;margin:2em;color:#1a1a1a}
h1{color:#d32f2f}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px;text-align:left}
th{background:#f5f5f5}.critical{color:#d32f2f;font-weight:700}
.high{color:#e65100}.medium{color:#f9a825}.low{color:#2e7d32}
</style></head>
<body>
<h1>IoT Vulnerability Report</h1>
<p><strong>Manufacturer:</strong> {{ manufacturer }}</p>
<p><strong>Generated:</strong> {{ date }}</p>
<p><strong>Total devices found:</strong> {{ devices | length }}</p>
<p><strong>Purpose:</strong> This report identifies potentially vulnerable devices manufactured
by {{ manufacturer }} that were found exposed on the public internet. We recommend reviewing
these findings and issuing firmware updates or security advisories as appropriate.</p>

<h2>Affected Devices</h2>
<table>
<tr><th>IP</th><th>Port</th><th>Model</th><th>Firmware</th><th>Country</th><th>Vuln Score</th><th>CVEs</th></tr>
{% for d in devices %}
<tr>
  <td>{{ d.ip }}</td><td>{{ d.port }}</td>
  <td>{{ d.model or 'N/A' }}</td><td>{{ d.firmware_version or 'N/A' }}</td>
  <td>{{ d.country_code }}</td>
  <td>{{ d.vulnerability_score or 0 }}</td>
  <td>{% for v in d.vulnerabilities %}<span class="{{ v.severity.value }}">{{ v.cve_id }} ({{ v.cvss_score }})</span>{% if not loop.last %}, {% endif %}{% endfor %}</td>
</tr>
{% endfor %}
</table>

<h2>CVE Summary</h2>
<table>
<tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>
{% for cve in cves %}
<tr>
  <td>{{ cve.cve_id }}</td>
  <td class="{{ cve.severity.value }}">{{ cve.severity.value | upper }}</td>
  <td>{{ cve.cvss_score }}</td>
  <td>{{ cve.description or '' }}</td>
</tr>
{% endfor %}
</table>
</body></html>
""")


class ReportGenerator:
    def generate_html(self, db: Session, manufacturer: str) -> str:
        devices = (
            db.query(Device)
            .filter(Device.manufacturer.ilike(f"%{manufacturer}%"))
            .order_by(Device.vulnerability_score.desc())
            .limit(500)
            .all()
        )
        seen_cves = {}
        for d in devices:
            for v in d.vulnerabilities:
                if v.cve_id not in seen_cves:
                    seen_cves[v.cve_id] = v

        return REPORT_TEMPLATE.render(
            manufacturer=manufacturer,
            date=datetime.date.today().isoformat(),
            devices=devices,
            cves=sorted(seen_cves.values(), key=lambda v: v.cvss_score or 0, reverse=True),
        )
