### 簡易連接埠掃描器（simpleportscanner）

功能：
- 非同步 TCP 連線掃描
- SYN 半開掃描（需系統管理員/原始套接字權限）
- 基本服務/版本橫幅識別（含 HTTP 狀態、Server 標頭與首頁標題）
- 漏洞資料庫檢查（NVD API）
- 結果匯出（JSON/CSV）
- 可調逾時與併發
- 圖形使用者介面（GUI，Tkinter）

### 安裝

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

SYN 半開掃描需以系統管理員權限執行（例如 macOS 用 `sudo`），並已安裝 `scapy`。

### CLI 使用

```bash
python -m simpleportscanner \
  --hosts 192.168.1.10,scanme.nmap.org \
  --ports 1-1024,3306,8080 \
  --scan syn \
  --concurrency 500 \
  --timeout 1.0 \
  --version-detect \
  --vuln-check --vuln-max 3 \
  --output results.json \
  --format json
```

- `--scan` 可為 `connect` 或 `syn`。
- `--version-detect` 對開放連接埠嘗試服務/版本橫幅識別。
- `--vuln-check` 依服務/橫幅關鍵字呼叫 NVD API 查詢 CVE。
- `--timeout` 單位為秒（浮點數）。

若 `syn` 掃描因權限失敗，請改用 `--scan connect`。

### GUI 使用

```bash
python -m simpleportscanner --gui
```

GUI 模式中可直接輸入主機與連接埠，不需要在命令列提供 `--hosts`。