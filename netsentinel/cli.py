"""NetSentinel command line.

    python -m netsentinel.cli simulate --out samples/demo.pcap --duration 300
    python -m netsentinel.cli analyze samples/demo.pcap [--json alerts.json]
    python -m netsentinel.cli analyze samples/demo.pcap --export alerts.jsonl --min-severity high
    sudo python -m netsentinel.cli live --iface eth0

Set your internal ranges with --home-net "10.0.0.0/8,100.64.0.0/10" or the
NETSENTINEL_HOME_NET environment variable (default: RFC 1918).
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime

from .capture import read_pcap, sniff_live
from .detector import Detector, analyse_packets
from .export import SEVERITY_ORDER, filter_alerts, format_from_path, render
from .notify import WebhookNotifier
from .rules import RuleEngine, parse_home_net
from .simulator import ATTACK_TYPES, Sim, write_pcap

SEV_COLOR = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[92m"}


def show(a: dict):
    t = datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S")
    c = SEV_COLOR.get(a["severity"], "")
    print(f"{t} {c}{a['severity'].upper():<8}\033[0m {a['attack']:<15} {a['src']:>15} -> {a['dst']:<15} "
          f"[{a['mitre_id']}] ({a['source']}) {a['detail']}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="netsentinel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("simulate", help="write a labelled synthetic pcap")
    s.add_argument("--out", default="samples/demo.pcap"); s.add_argument("--duration", type=int, default=300)
    s.add_argument("--attacks", nargs="*", default=ATTACK_TYPES); s.add_argument("--seed", type=int, default=7)
    a = sub.add_parser("analyze", help="analyse a pcap file")
    a.add_argument("pcap"); a.add_argument("--json")
    a.add_argument("--export", metavar="FILE", help="write alerts as .csv or .jsonl (SIEM-ready)")
    a.add_argument("--min-severity", choices=list(SEVERITY_ORDER), help="only export alerts at or above this level")
    lv = sub.add_parser("live", help="sniff a live interface (root required)")
    lv.add_argument("--iface"); lv.add_argument("--bpf", default="ip")
    for p in (a, lv):
        p.add_argument("--home-net", default=os.environ.get("NETSENTINEL_HOME_NET"),
                       help="internal networks, e.g. '10.0.0.0/8,100.64.0.0/10' (default: RFC 1918)")
    args = ap.parse_args(argv)

    if args.cmd == "simulate":
        pkts = Sim(args.seed).scenario(duration=args.duration, attacks=args.attacks, attack_count=1)
        write_pcap(pkts, args.out)
        print(f"wrote {len(pkts)} packets -> {args.out}")
        return

    try:
        home_net = parse_home_net(args.home_net)
    except ValueError as e:
        ap.error(f"invalid --home-net: {e}")
    print("HOME_NET:", ", ".join(map(str, home_net)))

    det = Detector.load()
    if args.cmd == "analyze":
        r = analyse_packets(det, read_pcap(args.pcap), rules=RuleEngine(home_net=home_net))
        for al in r["alerts"]:
            show(al)
        print(f"\n{r['flows']} flows, {len(r['alerts'])} alerts in {r['seconds']} s")
        if args.json:
            json.dump(r, open(args.json, "w"), indent=2)
        if args.export:
            rows = filter_alerts(r["alerts"], args.min_severity)
            fmt = format_from_path(args.export)
            with open(args.export, "w", encoding="utf-8", newline="") as fh:
                fh.write(render(rows, fmt))
            print(f"exported {len(rows)} alert(s) as {fmt} -> {args.export}")
    else:
        notifier = WebhookNotifier()
        print(f"sniffing {args.iface or 'default interface'} … Ctrl+C to stop")
        if notifier.enabled:
            print("webhook notifications on (NETSENTINEL_WEBHOOK_URL)")
        for _, _, al in det.run(sniff_live(args.iface, args.bpf), batch=16, rules=RuleEngine(home_net=home_net)):
            if al:
                show(al.to_dict())
                notifier.notify(al.to_dict())


if __name__ == "__main__":
    main()
