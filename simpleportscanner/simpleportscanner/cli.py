import argparse
import asyncio
import sys
from typing import Dict, List, Optional

from .ports import parse_ports
from .exporters import export_results
from .scans import async_connect_scan_host, syn_scan_host
from .services import async_detect_banners_for_host
from .vuln import check_vulnerabilities


def _parse_hosts(hosts_str: str) -> List[str]:
    return [h.strip() for h in hosts_str.split(",") if h.strip()]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="simpleportscanner",
        description="簡易非同步連接埠掃描器，支援 SYN 半開掃描與服務橫幅識別。",
    )
    parser.add_argument(
        "--hosts",
        "-H",
        required=False,
        help="以逗號分隔的主機清單（IP 或網域）。GUI 模式可省略。",
    )
    parser.add_argument(
        "--ports",
        "-p",
        default="1-1024",
        help="掃描的連接埠，例如 '1-1024,3306,8080'",
    )
    parser.add_argument(
        "--scan",
        choices=["connect", "syn"],
        default="connect",
        help="掃描方式：connect 為 TCP 連線，syn 為半開 SYN（需系統管理員權限）",
    )
    parser.add_argument(
        "--concurrency",
        "-c",
        type=int,
        default=500,
        help="非同步連線的最大併發數",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=float,
        default=1.0,
        help="逾時（秒）",
    )
    parser.add_argument(
        "--version-detect",
        "-s",
        action="store_true",
        help="對開放連接埠嘗試服務/版本橫幅識別",
    )
    parser.add_argument(
        "--vuln-check",
        "-v",
        action="store_true",
        help="使用 NVD API 進行漏洞資料庫查詢（依橫幅/服務關鍵字）",
    )
    parser.add_argument(
        "--vuln-max",
        type=int,
        default=3,
        help="每個服務最多顯示的 CVE 筆數",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="將結果輸出至檔案（JSON 或 CSV）",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "csv"],
        default="json",
        help="輸出格式，當指定 --output 時生效",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="啟動圖形使用者介面",
    )
    return parser


async def _run_connect_scan(
    hosts: List[str],
    ports: List[int],
    timeout: float,
    concurrency: int,
    do_version_detect: bool,
) -> List[Dict]:
    tasks = [
        async_connect_scan_host(host, ports, timeout=timeout, concurrency=concurrency)
        for host in hosts
    ]
    host_results = await asyncio.gather(*tasks)

    if do_version_detect:
        banner_tasks = [
            async_detect_banners_for_host(
                host_result["host"],
                [p for p in host_result["ports"] if p.get("state") == "open"],
                timeout=timeout,
                concurrency=concurrency,
            )
            for host_result in host_results
        ]
        banners_per_host = await asyncio.gather(*banner_tasks)
        for host_result, banner_map in zip(host_results, banners_per_host):
            for port_info in host_result["ports"]:
                if port_info.get("state") == "open":
                    banner = banner_map.get(port_info["port"])
                    if banner:
                        port_info.update(banner)

    return host_results


def _run_syn_scan(
    hosts: List[str],
    ports: List[int],
    timeout: float,
    do_version_detect: bool,
) -> List[Dict]:
    results: List[Dict] = []
    for host in hosts:
        host_result = syn_scan_host(host, ports, timeout=timeout)
        if do_version_detect:
            open_ports = [p for p in host_result["ports"] if p.get("state") == "open"]
            banner_map = asyncio.run(
                async_detect_banners_for_host(
                    host_result["host"],
                    open_ports,
                    timeout=timeout,
                    concurrency=max(32, len(open_ports)),
                )
            )
            for port_info in host_result["ports"]:
                if port_info.get("state") == "open":
                    banner = banner_map.get(port_info["port"])
                    if banner:
                        port_info.update(banner)
        results.append(host_result)
    return results


async def _run_vuln_checks(host_results: List[Dict], timeout: float, max_results: int, concurrency: int) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def do_one(port_info: Dict) -> None:
        async with sem:
            vulns = await asyncio.to_thread(
                check_vulnerabilities,
                port_info.get("service"),
                port_info.get("banner"),
                timeout=timeout,
                max_results=max_results,
            )
            if vulns:
                port_info["vulns"] = vulns

    tasks = []
    for host_result in host_results:
        for p in host_result.get("ports", []):
            if p.get("state") == "open" and (p.get("service") or p.get("banner")):
                tasks.append(do_one(p))
    if tasks:
        await asyncio.gather(*tasks)


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.gui:
        from .gui import launch_gui
        launch_gui()
        return

    hosts = _parse_hosts(args.hosts or "")
    ports = parse_ports(args.ports)

    if not hosts:
        print("未提供主機。")
        sys.exit(1)
    if not ports:
        print("未提供連接埠。")
        sys.exit(1)

    if args.scan == "connect":
        results = asyncio.run(
            _run_connect_scan(
                hosts=hosts,
                ports=ports,
                timeout=args.timeout,
                concurrency=args.concurrency,
                do_version_detect=args.version_detect,
            )
        )
        if args.vuln_check:
            asyncio.run(_run_vuln_checks(results, args.timeout, args.vuln_max, args.concurrency))
    else:
        try:
            results = _run_syn_scan(
                hosts=hosts,
                ports=ports,
                timeout=args.timeout,
                do_version_detect=args.version_detect,
            )
            if args.vuln_check:
                asyncio.run(_run_vuln_checks(results, args.timeout, args.vuln_max, max(32, args.concurrency)))
        except PermissionError:
            print(
                "[!] SYN 掃描需要系統管理員(原始套接字)權限。可改用：python -m simpleportscanner --scan connect ...",
                file=sys.stderr,
            )
            sys.exit(1)
        except Exception as ex:
            print(
                f"[!] SYN 掃描失敗：{ex}。建議改用 --scan connect。",
                file=sys.stderr,
            )
            sys.exit(1)

    for host_result in results:
        print(f"主機: {host_result['host']} (IP: {host_result.get('ip','?')})")
        for p in sorted(host_result["ports"], key=lambda x: x["port"]):
            line = f"  {p['port']}/tcp {p['state']}"
            if p.get("service"):
                line += f" 服務:{p['service']}"
            if p.get("banner"):
                line += " | 橫幅: " + (p['banner'][:80].replace("\n", " "))
            if p.get("vulns"):
                cves = ", ".join(v.get("id", "") for v in p["vulns"])[:80]
                line += f" | CVE: {cves}"
            print(line)

    if args.output:
        export_results(results, args.output, args.format)
        print(f"\n已將結果儲存至 {args.output} ({args.format})。")


if __name__ == "__main__":
    main()