import logging
import re

import httpx

from app.models.device import Severity, Vulnerability

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEMapper:
    def __init__(self):
        self._cache: dict[str, list[dict]] = {}

    def map_device(self, raw: dict) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        shodan_vulns = (raw.get("raw_data") or {}).get("vulns", {})
        for cve_id in shodan_vulns:
            if re.match(r"CVE-\d{4}-\d+", cve_id):
                detail = self._fetch_cve(cve_id)
                if detail:
                    vulns.append(self._to_model(cve_id, detail, "banner"))

        cpes = (raw.get("raw_data") or {}).get("cpe", [])
        if cpes:
            cpe_vulns = self._search_by_cpe(cpes[0] if isinstance(cpes, list) else cpes)
            for cv in cpe_vulns:
                if cv["cve_id"] not in {v.cve_id for v in vulns}:
                    vulns.append(self._to_model(cv["cve_id"], cv, "cpe"))

        return vulns

    def _fetch_cve(self, cve_id: str) -> dict | None:
        if cve_id in self._cache:
            cached = self._cache[cve_id]
            return cached[0] if cached else None

        try:
            resp = httpx.get(
                NVD_API,
                params={"cveId": cve_id},
                timeout=15,
            )
            resp.raise_for_status()
            items = resp.json().get("vulnerabilities", [])
            if not items:
                self._cache[cve_id] = []
                return None
            parsed = self._parse_nvd(items[0]["cve"])
            self._cache[cve_id] = [parsed]
            return parsed
        except Exception as e:
            logger.warning("NVD lookup failed for %s: %s", cve_id, e)
            return None

    def _search_by_cpe(self, cpe: str) -> list[dict]:
        try:
            resp = httpx.get(
                NVD_API,
                params={"cpeName": cpe, "resultsPerPage": 20},
                timeout=20,
            )
            resp.raise_for_status()
            items = resp.json().get("vulnerabilities", [])
            return [self._parse_nvd(i["cve"]) for i in items]
        except Exception as e:
            logger.warning("NVD CPE search failed for %s: %s", cpe, e)
            return []

    def _parse_nvd(self, cve: dict) -> dict:
        metrics = cve.get("metrics", {})
        cvss31 = metrics.get("cvssMetricV31", [{}])
        cvss_data = cvss31[0].get("cvssData", {}) if cvss31 else {}
        score = cvss_data.get("baseScore", 0)
        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )
        refs = [r.get("url", "") for r in cve.get("references", [])[:5]]

        return {
            "cve_id": cve.get("id", ""),
            "cvss_score": score,
            "description": desc[:500],
            "references": refs,
            "severity": self._score_to_severity(score),
        }

    def _to_model(self, cve_id: str, detail: dict, matched_by: str) -> Vulnerability:
        return Vulnerability(
            cve_id=cve_id,
            severity=detail.get("severity", Severity.INFO),
            cvss_score=detail.get("cvss_score"),
            description=detail.get("description"),
            references=detail.get("references"),
            matched_by=matched_by,
        )

    def _score_to_severity(self, score: float) -> Severity:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score >= 0.1:
            return Severity.LOW
        return Severity.INFO
