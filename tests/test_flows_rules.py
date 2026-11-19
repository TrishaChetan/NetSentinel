from netsentinel.flows import TCP, FlowAssembler, Packet, assemble
from netsentinel.rules import RuleEngine
from netsentinel.simulator import Sim


def test_bidirectional_flow_and_close():
    s = Sim(1)
    pkts = s.http_session(0.0, client="10.0.0.10", server="10.0.0.5")
    flows = list(assemble(pkts))
    assert len(flows) == 1
    f = flows[0]
    assert f.fwd and f.bwd and f.src == "10.0.0.10"
    feats = f.features()
    assert feats["syn_cnt"] == 2 and feats["fin_cnt"] == 2 and feats["dst_port"] in (80, 443)


def test_idle_timeout_splits_flows():
    fa = FlowAssembler(idle_timeout=5)
    a = Packet(0, "10.0.0.1", "10.0.0.2", 1111, 80, TCP, 60, "S")
    b = Packet(100, "10.0.0.1", "10.0.0.2", 1111, 80, TCP, 60, "A")
    assert fa.push(a) == []
    done = fa.push(b)
    assert len(done) == 1 and len(fa.table) == 1


def _run_rules(pkts):
    eng, hits = RuleEngine(), []
    for f in assemble(pkts):
        hits += eng.observe(f)
    return {h.attack for h in hits}


def test_rules_detect_aggregate_attacks():
    s = Sim(2)
    assert "PortScan" in _run_rules(s.port_scan(0))
    assert "DoS-SYNFlood" in _run_rules(s.syn_flood(0))
    assert "SSH-BruteForce" in _run_rules(s.ssh_bruteforce(0))
    assert "DNS-Tunneling" in _run_rules(s.dns_tunnel(0))


def test_rules_quiet_on_benign():
    pkts = Sim(3).scenario(duration=300, attacks=[])
    assert _run_rules(pkts) == set()


def test_exfil_rule_needs_rare_destination():
    s = Sim(4)
    benign = Sim(4).scenario(duration=200, attacks=[])
    assert "Exfiltration" in _run_rules(sorted(benign + s.exfiltration(1_700_000_150), key=lambda p: p.ts))


def _hits(pkts, **kw):
    eng, hits = RuleEngine(**kw), []
    for f in assemble(pkts):
        hits += eng.observe(f)
    return hits


def test_beacon_detected_once_per_hour():
    s = Sim(5)
    benign = Sim(5).scenario(duration=900, attacks=[])
    pkts = sorted(benign + s.c2_beacon(1_700_000_010, beats=14, interval=60), key=lambda p: p.ts)
    beacons = [h for h in _hits(pkts) if h.rule == "R6-BEACON"]
    assert len(beacons) == 1                       # keeps beating, but one alert
    assert beacons[0].src.startswith("10.0.0.") and "every 60s" in beacons[0].detail


def test_beacon_needs_steady_timing():
    s = Sim(6)
    # same server, same count, but human-like random gaps -> no alert
    jittery = s.c2_beacon(1_700_000_000, beats=14, interval=60, jitter=0.6)
    assert "C2-Beacon" not in {h.attack for h in _hits(jittery)}
    # too few check-ins -> no alert
    assert "C2-Beacon" not in {h.attack for h in _hits(Sim(6).c2_beacon(1_700_000_000, beats=6))}
    # internal-to-internal timers (e.g. monitoring polling the DB) are not C2
    s = Sim(7)
    inside = [p for p in s.c2_beacon(1_700_000_000, beats=14)]
    for p in inside:
        p.src, p.dst = ("10.0.0.20", "10.0.0.7") if p.src.startswith("10.") else ("10.0.0.7", "10.0.0.20")
    assert "C2-Beacon" not in {h.attack for h in _hits(inside)}


def test_scenario_can_include_beacons():
    pkts = Sim(8).scenario(duration=900, attacks=["C2-Beacon"], attack_count=1)
    assert "C2-Beacon" in _run_rules(pkts)
