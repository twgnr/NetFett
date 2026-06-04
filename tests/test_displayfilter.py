"""Tests des Anzeigefilters."""
from __future__ import annotations

from netfett.core.displayfilter import compile_filter
from netfett.core.models import DIR_IN, DIR_OUT, Packet


def mk(src="192.168.0.10", dst="1.1.1.1", proto="TCP", l4="TCP",
       sp=50000, dp=443, direction=DIR_OUT, info="") -> Packet:
    return Packet(number=1, ts=0.0, raw=b"", direction=direction, src=src,
                  dst=dst, protocol=proto, l4=l4, src_port=sp, dst_port=dp,
                  info=info or f"{sp} → {dp}")


def test_empty_filter_is_none():
    assert compile_filter("") is None
    assert compile_filter("   ") is None


def test_protocol_keyword():
    f = compile_filter("tcp")
    assert f(mk(proto="TCP"))
    assert not f(mk(proto="UDP", l4="UDP"))


def test_https_keyword_matches_tls_or_443():
    f = compile_filter("https")
    assert f(mk(proto="TLS", dp=443))
    assert f(mk(proto="TCP", dp=443))
    assert not f(mk(proto="TCP", dp=80))


def test_host_src_dst_and_port():
    assert compile_filter("host 1.1.1.1")(mk())
    assert compile_filter("src 192.168.0.10")(mk())
    assert not compile_filter("src 1.1.1.1")(mk())
    assert compile_filter("dst port 443")(mk())
    assert not compile_filter("src port 443")(mk())
    assert compile_filter("port 50000")(mk())


def test_and_combination():
    f = compile_filter("tcp dst port 443")
    assert f(mk())
    assert not f(mk(dp=80))


def test_not_and_or():
    f = compile_filter("tcp not src 1.1.1.1")
    assert f(mk())
    assert not f(mk(src="1.1.1.1"))
    g = compile_filter("dns or icmp")
    assert g(mk(proto="DNS", l4="UDP"))
    assert g(mk(proto="ICMP", l4="ICMP"))
    assert not g(mk(proto="TCP"))


def test_direction_and_freetext():
    assert compile_filter("out")(mk(direction=DIR_OUT))
    assert not compile_filter("in")(mk(direction=DIR_OUT))
    assert compile_filter("example")(mk(info="DNS query example.com"))
