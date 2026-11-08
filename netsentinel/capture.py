"""Packet sources: offline pcap files and live interfaces (via scapy)."""
from __future__ import annotations

from typing import Iterator

from .flows import ICMP, TCP, UDP, Packet


def _convert(pkt) -> Packet | None:
    from scapy.all import ICMP as SICMP, IP, IPv6, TCP as STCP, UDP as SUDP
    ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    if ip is None:
        return None
    ts, length = float(pkt.time), len(ip)
    if STCP in pkt:
        l4 = pkt[STCP]
        return Packet(ts, ip.src, ip.dst, l4.sport, l4.dport, TCP, length, str(l4.flags), len(bytes(l4.payload)))
    if SUDP in pkt:
        l4 = pkt[SUDP]
        return Packet(ts, ip.src, ip.dst, l4.sport, l4.dport, UDP, length, "", len(bytes(l4.payload)))
    if SICMP in pkt:
        return Packet(ts, ip.src, ip.dst, 0, 0, ICMP, length, "", len(bytes(pkt[SICMP].payload)))
    return None


def read_pcap(path: str) -> Iterator[Packet]:
    from scapy.all import PcapReader
    with PcapReader(path) as reader:
        for pkt in reader:
            p = _convert(pkt)
            if p:
                yield p


def sniff_live(iface: str | None = None, bpf: str = "ip", count: int = 0) -> Iterator[Packet]:
    """Live capture. Needs root / CAP_NET_RAW (or Npcap on Windows)."""
    import queue
    import threading

    from scapy.all import sniff
    q: queue.Queue = queue.Queue(maxsize=10000)
    threading.Thread(target=lambda: sniff(iface=iface, filter=bpf, prn=lambda x: q.put(x), store=False, count=count),
                     daemon=True).start()
    while True:
        p = _convert(q.get())
        if p:
            yield p
