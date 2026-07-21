"""Tests für das ETW-Capture-Backend (Struktur-Layout und Fragment-Aufbau).

Die eigentliche Erfassung braucht Windows *und* Administratorrechte und läuft
deshalb nicht in der Testsuite – geprüft wird die reine Logik plus das
ctypes-Layout, das auf einem falsch definierten Struct sofort auffliegen würde.
"""
from __future__ import annotations

import sys

import pytest

etw = pytest.importorskip("netfett.core.etw")

KW_START = etw.KW_PACKET_START
KW_END = etw.KW_PACKET_END
KW_SEND = etw.KW_SEND_PATH


# --- Struktur-Layout -------------------------------------------------------- #
@pytest.mark.skipif(sys.platform != "win32", reason="nur Windows")
def test_layout_matches_win32_abi():
    etw._check_layout()          # wirft bei Abweichung


@pytest.mark.skipif(sys.platform != "win32", reason="nur Windows")
def test_provider_guid_parses():
    guid = etw.GUID.from_string(etw.NDISCAP_PROVIDER_GUID)
    assert guid.Data1 == 0x2ED6006E
    assert guid.Data2 == 0x4729


def test_default_keywords_cover_both_directions():
    assert etw.DEFAULT_KEYWORDS & etw.KW_SEND_PATH
    assert etw.DEFAULT_KEYWORDS & etw.KW_RECEIVE_PATH
    assert etw.DEFAULT_KEYWORDS & etw.KW_ETHERNET_8023


# --- Fragment-Zusammenbau --------------------------------------------------- #
def test_single_fragment_is_complete_frame():
    asm = etw.FragmentAssembler()
    assert asm.add(0, KW_START | KW_END | KW_SEND, b"abc") == b"abc"
    assert asm.pending == 0


def test_multi_fragment_reassembles_in_order():
    asm = etw.FragmentAssembler()
    assert asm.add(0, KW_START, b"AAA") is None
    assert asm.pending == 1
    assert asm.add(0, 0, b"BBB") is None
    assert asm.add(0, KW_END, b"CCC") == b"AAABBBCCC"
    assert asm.pending == 0


def test_processors_are_buffered_independently():
    asm = etw.FragmentAssembler()
    asm.add(0, KW_START, b"cpu0-")
    asm.add(1, KW_START, b"cpu1-")
    assert asm.pending == 2
    assert asm.add(1, KW_END, b"end1") == b"cpu1-end1"
    assert asm.add(0, KW_END, b"end0") == b"cpu0-end0"


def test_new_start_discards_incomplete_frame():
    """Ein verlorenes End-Event darf den nächsten Frame nicht verunreinigen."""
    asm = etw.FragmentAssembler()
    asm.add(0, KW_START, b"verwaist")
    assert asm.add(0, KW_START | KW_END, b"frisch") == b"frisch"


def test_fragment_without_start_after_clear_is_kept():
    """Session-Start mitten im Frame: das Bruchstück beginnt einen neuen Puffer."""
    asm = etw.FragmentAssembler()
    assert asm.add(3, 0, b"mitte") is None
    assert asm.add(3, KW_END, b"-ende") == b"mitte-ende"


def test_clear_drops_pending_buffers():
    asm = etw.FragmentAssembler()
    asm.add(0, KW_START, b"x")
    asm.clear()
    assert asm.pending == 0
