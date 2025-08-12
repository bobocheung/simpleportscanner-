import csv
import json
from typing import List, Dict


def export_results(results: List[Dict], path: str, fmt: str) -> None:
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        return

    if fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["主機", "IP", "連接埠", "狀態", "服務", "橫幅", "CVE 清單"])
            for host_result in results:
                host = host_result.get("host", "")
                ip = host_result.get("ip", "")
                for p in host_result.get("ports", []):
                    vulns = p.get("vulns", [])
                    vuln_text = ";".join(v.get("id", "") for v in vulns) if vulns else ""
                    writer.writerow([
                        host,
                        ip,
                        p.get("port", ""),
                        p.get("state", ""),
                        p.get("service", ""),
                        (p.get("banner", "") or "").replace("\n", " ").strip(),
                        vuln_text,
                    ])
        return

    raise ValueError(f"Unsupported export format: {fmt}")