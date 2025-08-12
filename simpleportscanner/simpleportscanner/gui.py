import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List

from .ports import parse_ports
from .scans import async_connect_scan_host, syn_scan_host
from .services import async_detect_banners_for_host
from .vuln import check_vulnerabilities
from .exporters import export_results
import asyncio


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("簡易連接埠掃描器")
        self.geometry("900x600")
        self._build_ui()
        self.results = []

    def _build_ui(self) -> None:
        frm = ttk.Frame(self)
        frm.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Inputs
        row = 0
        ttk.Label(frm, text="主機 (以逗號分隔)").grid(row=row, column=0, sticky=tk.W)
        self.hosts_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.hosts_var, width=60).grid(row=row, column=1, columnspan=3, sticky=tk.EW)
        row += 1

        ttk.Label(frm, text="連接埠 (例如 1-1024,80,443)").grid(row=row, column=0, sticky=tk.W)
        self.ports_var = tk.StringVar(value="1-1024")
        ttk.Entry(frm, textvariable=self.ports_var).grid(row=row, column=1, sticky=tk.W)

        ttk.Label(frm, text="掃描方式").grid(row=row, column=2, sticky=tk.E)
        self.scan_var = tk.StringVar(value="connect")
        ttk.Combobox(frm, textvariable=self.scan_var, values=["connect", "syn"], width=10).grid(row=row, column=3, sticky=tk.W)
        row += 1

        ttk.Label(frm, text="併發數").grid(row=row, column=0, sticky=tk.W)
        self.conc_var = tk.IntVar(value=500)
        ttk.Entry(frm, textvariable=self.conc_var, width=10).grid(row=row, column=1, sticky=tk.W)

        ttk.Label(frm, text="逾時 (秒)").grid(row=row, column=2, sticky=tk.E)
        self.timeout_var = tk.DoubleVar(value=1.0)
        ttk.Entry(frm, textvariable=self.timeout_var, width=10).grid(row=row, column=3, sticky=tk.W)
        row += 1

        self.version_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="服務版本識別", variable=self.version_var).grid(row=row, column=0, sticky=tk.W)
        self.vuln_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="漏洞資料庫檢查 (NVD)", variable=self.vuln_var).grid(row=row, column=1, sticky=tk.W)
        ttk.Label(frm, text="每項最多 CVE").grid(row=row, column=2, sticky=tk.E)
        self.vuln_max_var = tk.IntVar(value=3)
        ttk.Entry(frm, textvariable=self.vuln_max_var, width=6).grid(row=row, column=3, sticky=tk.W)
        row += 1

        # Buttons
        ttk.Button(frm, text="開始掃描", command=self.on_start).grid(row=row, column=0, sticky=tk.W)
        ttk.Button(frm, text="匯出結果", command=self.on_export).grid(row=row, column=1, sticky=tk.W)
        row += 1

        # Treeview
        columns = ("host", "ip", "port", "state", "service", "banner", "vulns")
        self.tree = ttk.Treeview(frm, columns=columns, show="headings")
        for col, text in zip(columns, ["主機", "IP", "連接埠", "狀態", "服務", "橫幅", "CVE 清單"]):
            self.tree.heading(col, text=text)
            self.tree.column(col, stretch=True, anchor=tk.W, width=100)
        self.tree.grid(row=row, column=0, columnspan=4, sticky=tk.NSEW, pady=(8,0))
        frm.rowconfigure(row, weight=1)
        for c in range(4):
            frm.columnconfigure(c, weight=1)

        self.status_var = tk.StringVar(value="就緒")
        ttk.Label(self, textvariable=self.status_var).pack(fill=tk.X, padx=8, pady=4)

    def on_start(self) -> None:
        hosts = [h.strip() for h in self.hosts_var.get().split(',') if h.strip()]
        ports = parse_ports(self.ports_var.get())
        if not hosts or not ports:
            messagebox.showwarning("提示", "請輸入主機與連接埠")
            return
        scan = self.scan_var.get()
        conc = max(1, self.conc_var.get())
        timeout = max(0.1, float(self.timeout_var.get()))
        do_version = self.version_var.get()
        do_vuln = self.vuln_var.get()
        vuln_max = max(1, self.vuln_max_var.get())

        self.status_var.set("掃描中……")
        self.tree.delete(*self.tree.get_children())

        def worker() -> None:
            try:
                if scan == "connect":
                    results = asyncio.run(self._run_connect(hosts, ports, timeout, conc, do_version))
                else:
                    results = self._run_syn(hosts, ports, timeout, do_version)

                if do_vuln:
                    asyncio.run(self._run_vuln(results, timeout, vuln_max, conc))

                self.results = results
                self._populate_tree(results)
                self.status_var.set("完成")
            except Exception as ex:
                self.status_var.set(f"錯誤: {ex}")

        threading.Thread(target=worker, daemon=True).start()

    def _populate_tree(self, results: List[dict]) -> None:
        self.tree.delete(*self.tree.get_children())
        for host_result in results:
            for p in sorted(host_result.get("ports", []), key=lambda x: x.get("port", 0)):
                vulns = p.get("vulns", [])
                vuln_text = ", ".join(v.get("id", "") for v in vulns) if vulns else ""
                self.tree.insert("", tk.END, values=(
                    host_result.get("host"),
                    host_result.get("ip"),
                    p.get("port"),
                    p.get("state"),
                    p.get("service", ""),
                    (p.get("banner", "") or "")[:120],
                    vuln_text,
                ))

    async def _run_connect(self, hosts, ports, timeout, conc, do_version):
        tasks = [async_connect_scan_host(h, ports, timeout=timeout, concurrency=conc) for h in hosts]
        host_results = await asyncio.gather(*tasks)
        if do_version:
            banner_tasks = [
                async_detect_banners_for_host(
                    r["host"],
                    [p for p in r["ports"] if p.get("state") == "open"],
                    timeout=timeout,
                    concurrency=conc,
                ) for r in host_results
            ]
            banners = await asyncio.gather(*banner_tasks)
            for r, bmap in zip(host_results, banners):
                for p in r["ports"]:
                    if p.get("state") == "open":
                        b = bmap.get(p["port"])
                        if b:
                            p.update(b)
        return host_results

    def _run_syn(self, hosts, ports, timeout, do_version):
        results = []
        for h in hosts:
            r = syn_scan_host(h, ports, timeout=timeout)
            if do_version:
                open_ports = [p for p in r["ports"] if p.get("state") == "open"]
                bmap = asyncio.run(async_detect_banners_for_host(r["host"], open_ports, timeout=timeout, concurrency=max(32, len(open_ports))))
                for p in r["ports"]:
                    if p.get("state") == "open":
                        b = bmap.get(p["port"])
                        if b:
                            p.update(b)
            results.append(r)
        return results

    async def _run_vuln(self, results, timeout, vuln_max, conc):
        sem = asyncio.Semaphore(conc)
        async def do_one(port_info: dict):
            async with sem:
                vulns = await asyncio.to_thread(
                    check_vulnerabilities,
                    port_info.get("service"),
                    port_info.get("banner"),
                    timeout=timeout,
                    max_results=vuln_max,
                )
                if vulns:
                    port_info["vulns"] = vulns

        tasks = []
        for host_result in results:
            for p in host_result.get("ports", []):
                if p.get("state") == "open" and (p.get("service") or p.get("banner")):
                    tasks.append(do_one(p))
        if tasks:
            await asyncio.gather(*tasks)

    def on_export(self) -> None:
        if not self.results:
            messagebox.showinfo("提示", "尚無結果可匯出")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", ".json"), ("CSV", ".csv")])
        if not path:
            return
        fmt = "csv" if path.lower().endswith(".csv") else "json"
        try:
            export_results(self.results, path, fmt)
            messagebox.showinfo("完成", f"已儲存至 {path}")
        except Exception as ex:
            messagebox.showerror("錯誤", str(ex))


def launch_gui() -> None:
    app = App()
    app.mainloop()