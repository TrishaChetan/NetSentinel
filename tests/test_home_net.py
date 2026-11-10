import pytest

from netsentinel.rules import DEFAULT_HOME_NET, RuleEngine, parse_home_net


def test_default_is_rfc1918():
    eng = RuleEngine()
    assert [str(n) for n in eng.home_net] == list(DEFAULT_HOME_NET)
    assert eng._internal("192.168.1.10")
    assert not eng._internal("8.8.8.8")


@pytest.mark.parametrize("spec", [
    "10.0.0.0/8,100.64.0.0/10",
    "[10.0.0.0/8, 100.64.0.0/10]",
    "10.0.0.0/8 100.64.0.0/10",
    ["10.0.0.0/8", "100.64.0.0/10"],
])
def test_parse_formats(spec):
    assert [str(n) for n in parse_home_net(spec)] == ["10.0.0.0/8", "100.64.0.0/10"]


def test_custom_home_net_changes_direction():
    eng = RuleEngine(home_net="100.64.0.0/10")
    assert eng._internal("100.70.1.2")
    assert not eng._internal("10.1.1.1")


def test_single_ip_and_ipv6():
    eng = RuleEngine(home_net="203.0.113.5, fd00::/8")
    assert eng._internal("203.0.113.5")
    assert eng._internal("fd00::1")
    assert not eng._internal("203.0.113.6")


@pytest.mark.parametrize("bad", ["not-a-net", "10.0.0.0/33", ""])
def test_invalid_home_net(bad):
    with pytest.raises(ValueError):
        parse_home_net(bad)
