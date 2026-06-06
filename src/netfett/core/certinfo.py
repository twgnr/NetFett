"""X.509-Zertifikat-Zusammenfassung (Aussteller/Subject/Gültigkeit).

Nutzt die ``cryptography``-Bibliothek; fehlt sie, liefert :func:`summarize` ein
leeres Dict. Die DER-Bytes stammen aus der TLS-Certificate-Handshake-Nachricht
(im Klartext bei TLS 1.2, sonst nach Entschlüsselung).
"""
from __future__ import annotations

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    HAVE = True
except ImportError:                                # pragma: no cover
    HAVE = False


def _common_name(name) -> str:
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return attrs[0].value
    except Exception:
        pass
    try:
        return name.rfc4514_string()
    except Exception:
        return ""


def summarize(der: bytes) -> dict[str, str]:
    """(subject, issuer, not_before, not_after) eines DER-Zertifikats oder {}."""
    if not HAVE or not der:
        return {}
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return {}
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return {
        "subject": _common_name(cert.subject),
        "issuer": _common_name(cert.issuer),
        "not_before": nb.strftime("%Y-%m-%d"),
        "not_after": na.strftime("%Y-%m-%d"),
    }
