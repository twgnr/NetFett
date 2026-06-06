"""Tests für die Pro-Host-Statistik und die Subnetz-Berechnung."""
from __future__ import annotations

from netfett.core.hoststats import HostMonitor
from netfett.core.models import Packet
from netfett.core.scan import subnet_hosts


def _pkt(src, dst, length):
    return Packet(number=1, ts=1.0, raw=b"", direction="?", src=src, dst=dst,
                  length=length)


def test_subnet_hosts_24():
    hosts = subnet_hosts("192.168.0.10", 24)
    assert len(hosts) == 254
    assert "192.168.0.1" in hosts and "192.168.0.254" in hosts
    assert "192.168.0.0" not in hosts and "192.168.0.255" not in hosts


def test_subnet_hosts_limit():
    hosts = subnet_hosts("10.0.0.1", 16, limit=100)
    assert len(hosts) == 100


def test_subnet_invalid():
    assert subnet_hosts("nicht-ip") == []


def test_host_monitor_in_out():
    m = HostMonitor(window=5)
    m.add(_pkt("192.168.0.10", "1.1.1.1", 100))     # 10 sendet → out, 1.1.1.1 in
    m.add(_pkt("1.1.1.1", "192.168.0.10", 40))      # 1.1.1.1 sendet → out
    local = m.get("192.168.0.10")
    remote = m.get("1.1.1.1")
    assert local.total_out == 100 and local.total_in == 40
    assert remote.total_out == 40 and remote.total_in == 100
    assert local.packets == 2 and remote.packets == 2


def test_host_monitor_tick_history():
    m = HostMonitor(window=5)
    m.add(_pkt("192.168.0.10", "1.1.1.1", 100))
    m.tick()
    h = m.get("192.168.0.10")
    assert h.out_bps[-1] == 100 and h.in_bps[-1] == 0
    m.tick()
    assert h.out_bps[-1] == 0                         # zurückgesetzt nach tick


def test_host_monitor_sorted_by_volume():
    m = HostMonitor()
    m.add(_pkt("a", "b", 10))
    m.add(_pkt("a", "c", 1000))
    order = [h.ip for h in m.hosts()]
    assert order[0] == "a"                            # a hat das meiste Volumen
