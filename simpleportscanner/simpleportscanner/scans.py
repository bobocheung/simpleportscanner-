import asyncio
import socket
from typing import Dict, List


async def _try_connect(host: str, port: int, timeout: float) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def async_connect_scan_host(
    host: str, ports: List[int], timeout: float, concurrency: int
) -> Dict:
    semaphore = asyncio.Semaphore(concurrency)

    results: List[Dict] = []

    async def scan_one(p: int) -> None:
        async with semaphore:
            is_open = await _try_connect(host, p, timeout)
            results.append({
                "port": p,
                "state": "open" if is_open else "closed",
            })

    await asyncio.gather(*(scan_one(p) for p in ports))

    ip_address = None
    try:
        ip_address = socket.gethostbyname(host)
    except Exception:
        pass

    return {
        "host": host,
        "ip": ip_address or host,
        "ports": results,
    }


def syn_scan_host(host: str, ports: List[int], timeout: float) -> Dict:
    try:
        from scapy.all import IP, TCP, sr
    except Exception as ex:
        raise RuntimeError(f"Scapy not available: {ex}")

    packet = IP(dst=host)/TCP(dport=ports, flags="S")

    answered, _ = sr(
        packet,
        timeout=timeout,
        verbose=0,
    )

    open_ports = set()
    closed_ports = set()

    for send_pkt, recv_pkt in answered:
        if recv_pkt.haslayer(TCP):
            flags = int(recv_pkt[TCP].flags)
            if flags & 0x12 == 0x12:
                open_ports.add(int(send_pkt[TCP].dport))
            elif flags & 0x14 == 0x14:
                closed_ports.add(int(send_pkt[TCP].dport))

    sent_ports = set(ports)
    answered_ports = open_ports | closed_ports
    filtered_ports = sent_ports - answered_ports

    results: List[Dict] = []
    for p in ports:
        if p in open_ports:
            results.append({"port": p, "state": "open"})
        elif p in closed_ports:
            results.append({"port": p, "state": "closed"})
        else:
            results.append({"port": p, "state": "filtered"})

    ip_address = None
    try:
        ip_address = socket.gethostbyname(host)
    except Exception:
        pass

    return {
        "host": host,
        "ip": ip_address or host,
        "ports": results,
    }