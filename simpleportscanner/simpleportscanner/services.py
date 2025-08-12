import asyncio
import re
from typing import Dict, List


COMMON_HTTP_PORTS = {80, 8080, 8000, 8888, 443}


async def _probe_banner(host: str, port: int, timeout: float) -> Dict[str, str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except Exception:
        return {}

    service = None
    banner_bytes = b""
    http_status = None
    http_server = None
    http_title = None

    try:
        if port in COMMON_HTTP_PORTS:
            probe = b"HEAD / HTTP/1.0\r\nHost: %b\r\nConnection: close\r\n\r\n" % host.encode()
            writer.write(probe)
            await writer.drain()
            try:
                # Read headers only
                headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
            except Exception:
                headers = b""
            banner_bytes = headers
            if headers:
                try:
                    header_text = headers.decode(errors="ignore")
                    lines = header_text.split("\r\n")
                    if lines and lines[0].startswith("HTTP/"):
                        parts = lines[0].split(" ", 2)
                        if len(parts) >= 2 and parts[1].isdigit():
                            http_status = int(parts[1])
                    for line in lines[1:]:
                        if line.lower().startswith("server:"):
                            http_server = line.split(":", 1)[1].strip()
                            break
                except Exception:
                    pass
            # Try a GET to capture title if cheap
            try:
                writer.write(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
                await writer.drain()
                page = await asyncio.wait_for(reader.read(2048), timeout=timeout)
                banner_bytes += page
                m = re.search(br"<title>(.*?)</title>", page, flags=re.I|re.S)
                if m:
                    http_title = m.group(1).decode(errors="ignore").strip()
            except Exception:
                pass
            service = "http(s)" if port == 443 else "http"
        else:
            writer.write(b"\r\n")
            await writer.drain()
            try:
                banner_bytes = await asyncio.wait_for(reader.read(512), timeout=timeout)
            except Exception:
                banner_bytes = b""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    banner_str = banner_bytes.decode(errors="ignore").strip()

    if not service and banner_str:
        low = banner_str.lower()
        if "ssh" in low:
            service = "ssh"
        elif "ftp" in low:
            service = "ftp"
        elif "smtp" in low:
            service = "smtp"
        elif "imap" in low:
            service = "imap"
        elif "pop3" in low:
            service = "pop3"
        elif "redis" in low:
            service = "redis"
        elif "mysql" in low:
            service = "mysql"
        elif "postgres" in low or "postgresql" in low:
            service = "postgresql"
        elif "http" in low:
            service = "http"

    result: Dict[str, str] = {}
    if service:
        result["service"] = service
    if banner_str:
        result["banner"] = banner_str
    if http_status is not None:
        result["http_status"] = str(http_status)
    if http_server:
        result["http_server"] = http_server
    if http_title:
        result["http_title"] = http_title
    return result


async def async_detect_banners_for_host(
    host: str, open_ports: List[Dict], timeout: float, concurrency: int
) -> Dict[int, Dict[str, str]]:
    semaphore = asyncio.Semaphore(concurrency)
    banner_map: Dict[int, Dict[str, str]] = {}

    async def grab(port: int) -> None:
        async with semaphore:
            details = await _probe_banner(host, port, timeout)
            if details:
                banner_map[port] = details

    await asyncio.gather(*(grab(p["port"]) for p in open_ports))
    return banner_map