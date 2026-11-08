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
