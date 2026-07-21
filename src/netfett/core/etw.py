"""Capture-Backend über ETW: ``Microsoft-Windows-NDIS-PacketCapture``.

Im Gegensatz zum Raw-Socket (:mod:`netfett.core.capture`) liefert dieser Weg
**vollständige Ethernet-Frames** – inklusive MAC-Adressen, ARP, VLAN-Tags und
Nicht-IP-Protokollen. Der Provider steckt in Windows selbst; es wird **kein**
Fremdtreiber (Npcap/WinPcap) installiert. Wie beim Raw-Socket sind aber
Administratorrechte nötig: ETW-Real-Time-Sessions sind privilegiert.

Umgesetzt ist nur, was fürs Mitschneiden gebraucht wird: eine Real-Time-Session
starten, den Provider scharfschalten und die Roh-Events selbst zerlegen. Das
Payload-Layout von Event 1001 ist fest (drei ``UINT32`` + Fragment-Bytes),
deshalb kommt das Modul ohne TDH (``tdh.dll``) aus.

Referenz fürs Event-Format: Microsofts ``etl2pcapng``
(https://github.com/microsoft/etl2pcapng).

Grenzen gegenüber Npcap: Loopback-Verkehr (127.0.0.1) läuft nicht über NDIS und
bleibt daher unsichtbar; Pakete senden/injizieren kann ETW grundsätzlich nicht.
"""
from __future__ import annotations

import ctypes
import struct
import sys
import threading
import time
from collections.abc import Callable
from ctypes import POINTER, byref, sizeof
from ctypes.wintypes import (
    BYTE, DWORD, HANDLE, LARGE_INTEGER, LONG, LPWSTR, ULONG, USHORT, WCHAR,
)

ULONGLONG = ctypes.c_ulonglong
ULONG64 = ctypes.c_ulonglong
UCHAR = ctypes.c_ubyte

__all__ = ["EtwCaptureError", "EtwPacketCapture", "NDISCAP_PROVIDER_GUID"]


class EtwCaptureError(RuntimeError):
    pass


# --- Provider-Kennung und Keywords (per ``logman query providers`` bestätigt) --
NDISCAP_PROVIDER_GUID = "{2ED6006E-4729-4609-B423-3EE7BCD678EF}"

KW_ETHERNET_8023 = 0x0000000000000001
KW_WIRELESS_WAN = 0x0000000000000200
KW_TUNNEL = 0x0000000000008000
KW_NATIVE_802_11 = 0x0000000000010000
KW_VMSWITCH = 0x0000000001000000
KW_PACKET_TRUNCATED = 0x0000000002000000
KW_PACKET_START = 0x0000000040000000
KW_PACKET_END = 0x0000000080000000
KW_SEND_PATH = 0x0000000100000000
KW_RECEIVE_PATH = 0x0000000200000000

#: Medien + beide Richtungen + Fragment-Marker – alles, was Frames liefert.
DEFAULT_KEYWORDS = (
    KW_ETHERNET_8023 | KW_WIRELESS_WAN | KW_TUNNEL | KW_NATIVE_802_11
    | KW_VMSWITCH | KW_PACKET_TRUNCATED | KW_PACKET_START | KW_PACKET_END
    | KW_SEND_PATH | KW_RECEIVE_PATH
)

EVENT_ID_PACKET_FRAGMENT = 1001

# --- Win32-Konstanten --------------------------------------------------------
WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_TRACE_CONTROL_STOP = 1
TRACE_LEVEL_VERBOSE = 5

ERROR_SUCCESS = 0
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183
ERROR_WMI_INSTANCE_NOT_FOUND = 4201
ERROR_CTX_CLOSE_PENDING = 7007

INVALID_PROCESSTRACE_HANDLE = ctypes.c_ulonglong(0xFFFFFFFFFFFFFFFF).value

#: FILETIME-Epoche (1601-01-01) → Unix-Epoche, in 100-ns-Einheiten.
_FILETIME_UNIX_EPOCH = 116444736000000000


# --- Strukturen --------------------------------------------------------------
class GUID(ctypes.Structure):
    _fields_ = [("Data1", DWORD), ("Data2", USHORT), ("Data3", USHORT),
                ("Data4", BYTE * 8)]

    @classmethod
    def from_string(cls, text: str) -> "GUID":
        guid = cls()
        # CLSIDFromString erwartet die geschweifte Schreibweise.
        hres = ctypes.oledll.ole32.CLSIDFromString(ctypes.c_wchar_p(text),
                                                   byref(guid))
        if hres != 0:                       # oledll wirft schon bei != S_OK
            raise ValueError(f"ungültige GUID: {text}")
        return guid


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", ULONG), ("ProviderId", ULONG),
                ("HistoricalContext", ULONG64), ("TimeStamp", LARGE_INTEGER),
                ("Guid", GUID), ("ClientContext", ULONG), ("Flags", ULONG)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", ULONG), ("MinimumBuffers", ULONG),
        ("MaximumBuffers", ULONG), ("MaximumFileSize", ULONG),
        ("LogFileMode", ULONG), ("FlushTimer", ULONG), ("EnableFlags", ULONG),
        ("AgeLimit", LONG), ("NumberOfBuffers", ULONG), ("FreeBuffers", ULONG),
        ("EventsLost", ULONG), ("BuffersWritten", ULONG),
        ("LogBuffersLost", ULONG), ("RealTimeBuffersLost", ULONG),
        ("LoggerThreadId", HANDLE), ("LogFileNameOffset", ULONG),
        ("LoggerNameOffset", ULONG),
    ]


class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Id", USHORT), ("Version", UCHAR), ("Channel", UCHAR),
                ("Level", UCHAR), ("Opcode", UCHAR), ("Task", USHORT),
                ("Keyword", ULONGLONG)]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [("Size", USHORT), ("HeaderType", USHORT), ("Flags", USHORT),
                ("EventProperty", USHORT), ("ThreadId", ULONG),
                ("ProcessId", ULONG), ("TimeStamp", LARGE_INTEGER),
                ("ProviderId", GUID), ("EventDescriptor", EVENT_DESCRIPTOR),
                ("ProcessorTime", ULONG64), ("ActivityId", GUID)]


class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [("ProcessorNumber", UCHAR), ("Alignment", UCHAR),
                ("LoggerId", USHORT)]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [("EventHeader", EVENT_HEADER),
                ("BufferContext", ETW_BUFFER_CONTEXT),
                ("ExtendedDataCount", USHORT), ("UserDataLength", USHORT),
                ("ExtendedData", ctypes.c_void_p),
                ("UserData", ctypes.c_void_p),
                ("UserContext", ctypes.c_void_p)]


class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [("Size", USHORT), ("FieldTypeFlags", USHORT),
                ("Version", ULONG), ("ThreadId", ULONG), ("ProcessId", ULONG),
                ("TimeStamp", LARGE_INTEGER), ("Guid", GUID),
                ("ProcessorTime", ULONG64)]


class EVENT_TRACE(ctypes.Structure):
    _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", ULONG),
                ("ParentInstanceId", ULONG), ("ParentGuid", GUID),
                ("MofData", ctypes.c_void_p), ("MofLength", ULONG),
                ("BufferContext", ETW_BUFFER_CONTEXT)]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [(n, USHORT) for n in
                ("wYear", "wMonth", "wDayOfWeek", "wDay", "wHour", "wMinute",
                 "wSecond", "wMilliseconds")]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [("Bias", LONG), ("StandardName", WCHAR * 32),
                ("StandardDate", SYSTEMTIME), ("StandardBias", LONG),
                ("DaylightName", WCHAR * 32), ("DaylightDate", SYSTEMTIME),
                ("DaylightBias", LONG)]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", ULONG), ("Version", ULONG), ("ProviderVersion", ULONG),
        ("NumberOfProcessors", ULONG), ("EndTime", LARGE_INTEGER),
        ("TimerResolution", ULONG), ("MaximumFileSize", ULONG),
        ("LogFileMode", ULONG), ("BuffersWritten", ULONG),
        ("LogInstanceGuid", GUID), ("LoggerName", LPWSTR),
        ("LogFileName", LPWSTR), ("TimeZone", TIME_ZONE_INFORMATION),
        ("BootTime", LARGE_INTEGER), ("PerfFreq", LARGE_INTEGER),
        ("StartTime", LARGE_INTEGER), ("ReservedFlags", ULONG),
        ("BuffersLost", ULONG),
    ]


EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, POINTER(EVENT_RECORD))
EVENT_TRACE_BUFFER_CALLBACK = ctypes.WINFUNCTYPE(ULONG, ctypes.c_void_p)


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [
        ("LogFileName", LPWSTR), ("LoggerName", LPWSTR),
        ("CurrentTime", LARGE_INTEGER), ("BuffersRead", ULONG),
        ("ProcessTraceMode", ULONG), ("CurrentEvent", EVENT_TRACE),
        ("LogfileHeader", TRACE_LOGFILE_HEADER),
        ("BufferCallback", EVENT_TRACE_BUFFER_CALLBACK),
        ("BufferSize", ULONG), ("Filled", ULONG), ("EventsLost", ULONG),
        ("EventRecordCallback", EVENT_RECORD_CALLBACK),
        ("IsKernelTrace", ULONG), ("Context", ctypes.c_void_p),
    ]


# Ein falsches Feld-Layout würde stillschweigend fremden Speicher lesen –
# deshalb die bekannten x64-Größen hart prüfen, sobald das Modul lädt.
_EXPECTED_SIZES = {
    "GUID": (GUID, 16),
    "WNODE_HEADER": (WNODE_HEADER, 48),
    "EVENT_TRACE_PROPERTIES": (EVENT_TRACE_PROPERTIES, 120),
    "EVENT_DESCRIPTOR": (EVENT_DESCRIPTOR, 16),
    "EVENT_HEADER": (EVENT_HEADER, 80),
    "ETW_BUFFER_CONTEXT": (ETW_BUFFER_CONTEXT, 4),
    "EVENT_RECORD": (EVENT_RECORD, 112),
    "EVENT_TRACE_HEADER": (EVENT_TRACE_HEADER, 48),
    "EVENT_TRACE": (EVENT_TRACE, 88),
    "TIME_ZONE_INFORMATION": (TIME_ZONE_INFORMATION, 172),
    "TRACE_LOGFILE_HEADER": (TRACE_LOGFILE_HEADER, 280),
    "EVENT_TRACE_LOGFILEW": (EVENT_TRACE_LOGFILEW, 448),
}


def _check_layout() -> None:
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise EtwCaptureError("ETW-Backend unterstützt nur 64-Bit-Python.")
    bad = [f"{name}: {sizeof(typ)} statt {want}"
           for name, (typ, want) in _EXPECTED_SIZES.items()
           if sizeof(typ) != want]
    if bad:
        raise EtwCaptureError("Struktur-Layout passt nicht: " + "; ".join(bad))


# --- API-Bindungen -----------------------------------------------------------
if sys.platform == "win32":
    _advapi = ctypes.windll.advapi32

    _advapi.StartTraceW.argtypes = [POINTER(ULONG64), LPWSTR,
                                    POINTER(EVENT_TRACE_PROPERTIES)]
    _advapi.StartTraceW.restype = ULONG

    _advapi.ControlTraceW.argtypes = [ULONG64, LPWSTR,
                                      POINTER(EVENT_TRACE_PROPERTIES), ULONG]
    _advapi.ControlTraceW.restype = ULONG

    _advapi.EnableTraceEx2.argtypes = [ULONG64, POINTER(GUID), ULONG, UCHAR,
                                       ULONGLONG, ULONGLONG, ULONG,
                                       ctypes.c_void_p]
    _advapi.EnableTraceEx2.restype = ULONG

    _advapi.OpenTraceW.argtypes = [POINTER(EVENT_TRACE_LOGFILEW)]
    _advapi.OpenTraceW.restype = ULONG64

    _advapi.ProcessTrace.argtypes = [POINTER(ULONG64), ULONG,
                                     ctypes.c_void_p, ctypes.c_void_p]
    _advapi.ProcessTrace.restype = ULONG

    _advapi.CloseTrace.argtypes = [ULONG64]
    _advapi.CloseTrace.restype = ULONG
else:                                        # pragma: no cover - nur Windows
    _advapi = None


def _alloc_properties(session_name: str, realtime: bool = True
                      ) -> tuple[ctypes.Array, EVENT_TRACE_PROPERTIES]:
    """Puffer für EVENT_TRACE_PROPERTIES samt angehängtem Session-Namen."""
    # ControlTrace schreibt beide Namen zurück – Platz für Logfile *und* Logger.
    extra = 2 * (len(session_name) + 1) * ctypes.sizeof(WCHAR) + 1024
    total = sizeof(EVENT_TRACE_PROPERTIES) + extra
    buf = (ctypes.c_byte * total)()
    props = ctypes.cast(buf, POINTER(EVENT_TRACE_PROPERTIES)).contents
    props.Wnode.BufferSize = total
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
    props.Wnode.ClientContext = 1            # 1 = QPC → hohe Zeitauflösung
    props.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES)
    if realtime:
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        # 64 KB puffert genug für Lastspitzen, ohne die Latenz hochzutreiben.
        props.BufferSize = 64
        props.MinimumBuffers = 8
        props.MaximumBuffers = 64
        props.FlushTimer = 1                 # Sekunden – Obergrenze der Latenz
    return buf, props


class FragmentAssembler:
    """Setzt die Fragment-Events des Providers zu ganzen Frames zusammen.

    Große Frames verteilt NDIS auf mehrere Events; ``PacketStart``/``PacketEnd``
    im Keyword markieren erstes und letztes Stück. Fragmente eines Frames kommen
    nacheinander auf demselben Prozessor an – deshalb wird pro Prozessornummer
    gepuffert. Reine Logik, kein I/O: so bleibt sie testbar.
    """

    def __init__(self) -> None:
        self._buf: dict[int, bytearray] = {}

    def add(self, processor: int, keyword: int, fragment: bytes) -> bytes | None:
        """Fragment einsortieren; gibt den Frame zurück, sobald er komplett ist."""
        buf = self._buf.get(processor)
        if keyword & KW_PACKET_START or buf is None:
            buf = bytearray()
            self._buf[processor] = buf
        buf += fragment
        if not keyword & KW_PACKET_END:
            return None
        frame = bytes(buf)
        del self._buf[processor]
        return frame

    def clear(self) -> None:
        self._buf.clear()

    @property
    def pending(self) -> int:
        """Anzahl angefangener, noch unvollständiger Frames."""
        return len(self._buf)


class EtwPacketCapture:
    """Liest Ethernet-Frames live über eine ETW-Real-Time-Session.

    Der Callback bekommt ``(zeitstempel, frame, metadaten)``; ``frame`` ist der
    vollständige Ethernet-Frame, ``metadaten`` enthält ``if_index`` und
    ``outbound``. Er läuft im ETW-Consumer-Thread – dort möglichst wenig tun.
    """

    def __init__(self, on_frame: Callable[[float, bytes, dict], None],
                 on_error: Callable[[str], None] | None = None,
                 session_name: str = "NetFettCapture",
                 keywords: int = DEFAULT_KEYWORDS,
                 if_index: int | None = None) -> None:
        self._on_frame = on_frame
        self._on_error = on_error or (lambda _m: None)
        self.session_name = session_name
        self.keywords = keywords
        self.if_index = if_index

        self._session = ULONG64(0)
        self._consumer = ULONG64(INVALID_PROCESSTRACE_HANDLE)
        self._thread: threading.Thread | None = None
        self._running = False
        self._cb_ref: EVENT_RECORD_CALLBACK | None = None   # gegen GC schützen
        self._logfile: EVENT_TRACE_LOGFILEW | None = None
        self._frag = FragmentAssembler()
        self.frames = 0
        self.events_lost = 0

    @property
    def running(self) -> bool:
        return self._running

    # --- Lebenszyklus ------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        if sys.platform != "win32":
            raise EtwCaptureError("ETW gibt es nur unter Windows.")
        _check_layout()

        self._start_session()
        try:
            self._enable_provider()
            self._open_consumer()
        except Exception:
            self._stop_session()
            raise

        self._running = True
        self._thread = threading.Thread(target=self._process, daemon=True,
                                        name="netfett-etw")
        self._thread.start()

    def _start_session(self) -> None:
        buf, props = _alloc_properties(self.session_name)
        rc = _advapi.StartTraceW(byref(self._session), self.session_name,
                                 ctypes.cast(buf, POINTER(EVENT_TRACE_PROPERTIES)))
        if rc == ERROR_ALREADY_EXISTS:
            # Reste eines abgestürzten Laufs – abräumen und genau einmal neu.
            self._stop_stale_session()
            buf, props = _alloc_properties(self.session_name)
            rc = _advapi.StartTraceW(
                byref(self._session), self.session_name,
                ctypes.cast(buf, POINTER(EVENT_TRACE_PROPERTIES)))
        if rc == ERROR_ACCESS_DENIED:
            raise EtwCaptureError(
                "Zugriff verweigert – ETW-Mitschnitt erfordert Administratorrechte.")
        if rc != ERROR_SUCCESS:
            raise EtwCaptureError(f"StartTrace fehlgeschlagen (Fehler {rc}).")
        self._props_buf = buf

    def _stop_stale_session(self) -> None:
        buf, _ = _alloc_properties(self.session_name)
        _advapi.ControlTraceW(
            ULONG64(0), self.session_name,
            ctypes.cast(buf, POINTER(EVENT_TRACE_PROPERTIES)),
            EVENT_TRACE_CONTROL_STOP)

    def _enable_provider(self) -> None:
        guid = GUID.from_string(NDISCAP_PROVIDER_GUID)
        rc = _advapi.EnableTraceEx2(
            self._session, byref(guid), EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE, self.keywords, 0, 0, None)
        if rc != ERROR_SUCCESS:
            raise EtwCaptureError(f"EnableTraceEx2 fehlgeschlagen (Fehler {rc}).")

    def _open_consumer(self) -> None:
        self._cb_ref = EVENT_RECORD_CALLBACK(self._on_event)
        logfile = EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = self.session_name
        logfile.ProcessTraceMode = (PROCESS_TRACE_MODE_REAL_TIME
                                    | PROCESS_TRACE_MODE_EVENT_RECORD)
        logfile.EventRecordCallback = self._cb_ref
        self._logfile = logfile              # muss die Session überleben
        handle = _advapi.OpenTraceW(byref(logfile))
        if handle == INVALID_PROCESSTRACE_HANDLE:
            err = ctypes.GetLastError()
            raise EtwCaptureError(f"OpenTrace fehlgeschlagen (Fehler {err}).")
        self._consumer = ULONG64(handle)

    def _process(self) -> None:
        handles = (ULONG64 * 1)(self._consumer.value)
        rc = _advapi.ProcessTrace(handles, 1, None, None)
        # Beim Stoppen kehrt ProcessTrace regulär zurück – nur melden, wenn der
        # Aufrufer gar nicht stoppen wollte.
        if rc != ERROR_SUCCESS and self._running:
            self._on_error(f"ProcessTrace endete mit Fehler {rc}.")
        self._running = False

    # --- Event-Verarbeitung ------------------------------------------------
    def _on_event(self, record_ptr) -> None:
        try:
            rec = record_ptr.contents
            desc = rec.EventHeader.EventDescriptor
            if desc.Id != EVENT_ID_PACKET_FRAGMENT:
                return
            length = rec.UserDataLength
            if length < 12 or not rec.UserData:
                return
            payload = ctypes.string_at(rec.UserData, length)
            if_index, _lower_if, frag_size = struct.unpack_from("<III", payload)
            fragment = payload[12:12 + frag_size]
            if len(fragment) < frag_size:     # abgeschnittenes Event
                return
            if self.if_index is not None and if_index != self.if_index:
                return

            keyword = desc.Keyword
            frame = self._frag.add(rec.BufferContext.ProcessorNumber, keyword,
                                   fragment)
            if frame is None:
                return                        # weitere Fragmente folgen
            self.frames += 1
            ts = (rec.EventHeader.TimeStamp - _FILETIME_UNIX_EPOCH) / 1e7
            self._on_frame(ts, frame, {
                "if_index": if_index,
                "outbound": bool(keyword & KW_SEND_PATH),
                "truncated": bool(keyword & KW_PACKET_TRUNCATED),
            })
        except Exception as exc:              # niemals in den Kernel zurückwerfen
            self._on_error(f"Event-Verarbeitung: {exc}")

    # --- Abbau -------------------------------------------------------------
    def stop(self) -> None:
        self._running = False
        self._disable_provider()
        self._stop_session()
        # CloseTrace beendet das blockierende ProcessTrace; bis dahin läuft der
        # Consumer-Thread weiter, deshalb erst schließen, dann joinen.
        if self._consumer.value != INVALID_PROCESSTRACE_HANDLE:
            _advapi.CloseTrace(self._consumer)
            self._consumer = ULONG64(INVALID_PROCESSTRACE_HANDLE)
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._cb_ref = None
        self._logfile = None
        self._frag.clear()

    def _disable_provider(self) -> None:
        if not self._session.value:
            return
        try:
            guid = GUID.from_string(NDISCAP_PROVIDER_GUID)
            _advapi.EnableTraceEx2(self._session, byref(guid),
                                   EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                                   0, 0, 0, 0, None)
        except OSError:
            pass

    def _stop_session(self) -> None:
        if not self._session.value:
            return
        buf, _ = _alloc_properties(self.session_name)
        props_ptr = ctypes.cast(buf, POINTER(EVENT_TRACE_PROPERTIES))
        _advapi.ControlTraceW(self._session, None, props_ptr,
                              EVENT_TRACE_CONTROL_STOP)
        self.events_lost = props_ptr.contents.EventsLost
        self._session = ULONG64(0)


def _selftest(seconds: float = 10.0) -> int:
    """Durchsatz-Test: zählt Frames und zeigt den ersten an."""
    state = {"first": None}
    counter = {"n": 0, "bytes": 0, "out": 0}

    def on_frame(ts: float, frame: bytes, meta: dict) -> None:
        counter["n"] += 1
        counter["bytes"] += len(frame)
        if meta["outbound"]:
            counter["out"] += 1
        if state["first"] is None:
            state["first"] = (ts, frame, meta)

    cap = EtwPacketCapture(on_frame, on_error=lambda m: print(f"  [Fehler] {m}"))
    print(f"Starte ETW-Session '{cap.session_name}' für {seconds:.0f} s ...")
    try:
        cap.start()
    except EtwCaptureError as exc:
        print(f"FEHLER: {exc}")
        return 1

    t0 = time.monotonic()
    try:
        while time.monotonic() - t0 < seconds:
            time.sleep(0.5)
            n = counter["n"]
            print(f"\r  {n} Frames  {counter['bytes'] / 1e6:.2f} MB  "
                  f"{n / max(time.monotonic() - t0, 1e-9):.0f} pps", end="")
    except KeyboardInterrupt:
        pass
    finally:
        elapsed = time.monotonic() - t0
        cap.stop()

    n = counter["n"]
    print(f"\n\nErgebnis nach {elapsed:.1f} s:")
    print(f"  Frames gesamt   : {n}  ({n / max(elapsed, 1e-9):.0f} pps)")
    print(f"  davon ausgehend : {counter['out']}")
    print(f"  Bytes           : {counter['bytes'] / 1e6:.2f} MB")
    print(f"  ETW-Verluste    : {cap.events_lost}")
    first = state["first"]
    if first is None:
        print("\n  Keine Frames empfangen – läuft Traffic über die Schnittstelle?")
        return 2
    ts, frame, meta = first
    dst = ":".join(f"{b:02x}" for b in frame[0:6])
    src = ":".join(f"{b:02x}" for b in frame[6:12])
    ethertype = int.from_bytes(frame[12:14], "big") if len(frame) >= 14 else 0
    print(f"\n  Erster Frame: {len(frame)} Bytes, if_index={meta['if_index']}, "
          f"{'aus' if meta['outbound'] else 'ein'}")
    print(f"    MAC {src} → {dst}   EtherType 0x{ethertype:04x}")
    print(f"    {frame[:32].hex(' ')}")
    return 0


if __name__ == "__main__":
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    raise SystemExit(_selftest(secs))
