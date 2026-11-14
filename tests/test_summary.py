from netsentinel.flows import Packet
from netsentinel.summary import format_summary, summarize


def pk(ts, src, dst, dport, length, proto=6, flags="A"):
    return Packet(ts=ts, src=src, dst=dst, sport=40000, dport=dport, proto=proto, length=length, flags=flags)


PACKETS = [
    pk(0.0, "10.0.0.5", "93.184.216.34", 443, 1500),
    pk(0.5, "10.0.0.5", "93.184.216.34", 443, 1500),
    pk(1.0, "93.184.216.34", "10.0.0.5", 40000, 600),
    pk(1.5, "10.0.0.7", "10.0.0.1", 53, 80, proto=17),
    pk(2.0, "203.0.113.9", "10.0.0.5", 22, 60, flags="S"),
    pk(4.0, "203.0.113.9", "10.0.0.5", 23, 60, flags="S"),
]


def test_totals_and_rates():
    s = summarize(PACKETS)
    assert s["packets"] == 6 and s["bytes"] == 3800
    assert s["duration_s"] == 4.0 and s["avg_bps"] == 7600.0
    assert s["unique_hosts"] == 5
    assert s["tcp_syn_only_packets"] == 2


def test_rankings_and_direction():
    s = summarize(PACKETS, top=2)
    assert s["top_sources"][0] == {"ip": "10.0.0.5", "bytes": 3000, "internal": True}
    assert len(s["top_sources"]) == 2
    assert s["top_ports"][0]["service"] == "https"
    assert s["top_conversations"][0]["bytes"] == 3600
    assert s["direction_bytes"]["internal→external"] == 3000
    assert s["direction_bytes"]["external→internal"] == 720
    assert {p["protocol"] for p in s["protocols"]} == {"TCP", "UDP"}


def test_custom_home_net_changes_direction():
    s = summarize(PACKETS, home_net="93.184.216.0/24")
    assert s["direction_bytes"]["internal→external"] == 600


def test_format_and_empty():
    text = format_summary(summarize(PACKETS))
    assert "Top talkers" in text and "tcp" not in text.lower().split("protocols:")[0]
    assert "SYN-only" in text
    assert format_summary(summarize([])) == "No IP packets in this capture."
