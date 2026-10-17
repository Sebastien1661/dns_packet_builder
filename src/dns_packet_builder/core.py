"""Build DNS wire-format packets from structured record definitions.

Only what is needed to emit a correct query or response packet is implemented.
No parsing, no EDNS, no TSIG, no DNSSEC. The supported rdata types are the ones
that show up constantly: A, AAAA, CNAME, MX, TXT, NS, PTR, SOA, SRV. Anything
else raises NotImplementedError so callers fail loudly rather than silently
producing corrupt packets.
"""

from __future__ import annotations

import io
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, ClassVar

# Type codes we know how to serialise. Keeping this as a module-level constant
# makes the "do we support this?" check explicit and easy to audit.
_SUPPORTED_TYPES = frozenset(
    {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SOA", "SRV"}
)

# DNS RR type numbers (RFC 1035 + RFC 2782).
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33

_TYPE_TO_NUMBER = {
    "A": TYPE_A,
    "AAAA": TYPE_AAAA,
    "CNAME": TYPE_CNAME,
    "MX": TYPE_MX,
    "TXT": TYPE_TXT,
    "NS": TYPE_NS,
    "PTR": TYPE_PTR,
    "SOA": TYPE_SOA,
    "SRV": TYPE_SRV,
}
_NUMBER_TO_TYPE = {v: k for k, v in _TYPE_TO_NUMBER.items()}

# DNS RR class numbers.
CLASS_IN = 1


def _type_name(rrtype: Any) -> str:
    """Normalise an rrtype argument to a canonical upper-case name string.

    Accepts strings (case-insensitive) and the numeric type codes we support.
    Everything else is an error: accepting unknown integers would let callers
    build packets with a type field set to a value whose rdata layout we do
    not understand, which is how corrupt packets get produced.
    """
    if isinstance(rrtype, str):
        name = rrtype.upper()
        if name not in _SUPPORTED_TYPES:
            raise NotImplementedError(f"unsupported rrtype: {rrtype!r}")
        return name
    if isinstance(rrtype, int):
        if rrtype not in _NUMBER_TO_TYPE:
            raise NotImplementedError(f"unsupported rtype code: {rrtype!r}")
        return _NUMBER_TO_TYPE[rrtype]
    raise TypeError(f"rrtype must be str or int, got {type(rrtype).__name__}")


def _encode_name(name: str) -> bytes:
    """Serialise a domain name in DNS message-format (RFC 1035 §4.1.4).

    Labels are length-prefixed with a single byte, the list terminates with a
    zero-length label. No name compression is emitted: compression requires
    keeping a dictionary of previously-seen name offsets and matching suffixes,
    and for a builder whose job is to turn a small record list into bytes, the
    added complexity is not worth it. Uncompressed packets are always valid;
    they are just a few bytes larger.
    """
    if not isinstance(name, str):
        raise TypeError(f"name must be str, got {type(name).__name__}")
    if name == "" or name == ".":
        return b"\x00"
    if name.endswith("."):
        name = name[:-1]
    out = bytearray()
    for label in name.split("."):
        if label == "":
            raise ValueError(f"empty label in name: {name!r}")
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"label too long ({len(encoded)} > 63): {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def _decode_name(buf: bytes, offset: int) -> tuple[str, int]:
    """Decode a message-format name starting at offset.

    Follows compression pointers (RFC 1035 §4.1.4). Returns (name, next_offset).
    Used only by Question.parse for round-trip tests.
    """
    labels: list[str] = []
    pos = offset
    jumped = False
    after_pointer = offset
    visited: set[int] = set()
    while True:
        if pos >= len(buf):
            raise ValueError("truncated name")
        length = buf[pos]
        if length == 0:
            pos += 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(buf):
                raise ValueError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | buf[pos + 1]
            if pointer in visited:
                raise ValueError("compression loop")
            visited.add(pointer)
            if not jumped:
                after_pointer = pos + 2
                jumped = True
            pos = pointer
            continue
        if (length & 0xC0) != 0:
            raise ValueError("invalid label length flags")
        pos += 1
        if pos + length > len(buf):
            raise ValueError("truncated label")
        labels.append(buf[pos : pos + length].decode("ascii"))
        pos += length
    name = ".".join(labels)
    return name, (after_pointer if jumped else pos)


@dataclass(frozen=True)
class Header:
    """DNS message header (RFC 1035 §4.1.1).

    The id should be a random 16-bit value chosen by the caller for query
    packets. We do not generate it here: the caller knows whether this packet
    needs a fresh id (a new query) or a specific one (matching a response to a
    query), and forcing the library to pick would make tests non-deterministic.
    """

    id: int = 0
    flags: int = 0
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    def to_bytes(self) -> bytes:
        if not 0 <= self.id <= 0xFFFF:
            raise ValueError(f"id out of range: {self.id}")
        if not 0 <= self.flags <= 0xFFFF:
            raise ValueError(f"flags out of range: {self.flags}")
        return struct.pack(
            "!HHHHHH",
            self.id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @classmethod
    def parse(cls, buf: bytes, offset: int = 0) -> "Header":
        if offset + 12 > len(buf):
            raise ValueError("truncated header")
        id_, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", buf, offset)
        return cls(id_, flags, qd, an, ns, ar)


@dataclass(frozen=True)
class Question:
    """A DNS question entry (RFC 1035 §4.1.2)."""

    qname: str
    qtype: Any  # str like "A" or int like 1
    qclass: int = CLASS_IN

    def __post_init__(self) -> None:
        object.__setattr__(self, "qtype", _type_name(self.qtype))

    def to_bytes(self) -> bytes:
        return (
            _encode_name(self.qname)
            + struct.pack("!HH", _TYPE_TO_NUMBER[self.qtype], self.qclass)
        )

    @classmethod
    def parse(cls, buf: bytes, offset: int) -> tuple["Question", int]:
        name, pos = _decode_name(buf, offset)
        if pos + 4 > len(buf):
            raise ValueError("truncated question fixed fields")
        qtype_num, qclass = struct.unpack_from("!HH", buf, pos)
        rrtype = _type_name(qtype_num)
        return cls(name, rrtype, qclass), pos + 4


@dataclass(frozen=True)
class ResourceRecord:
    """A DNS resource record (RFC 1035 §4.1.3).

    rdata is a typed rdata value (RdataA, RdataMX, etc.) whose class matches
    rtype. Holding rdata as a structured object rather than raw bytes means we
    can validate the fields at construction time and the serialiser never has to
    guess the layout.
    """

    name: str
    rtype: Any
    rdata: Any
    rclass: int = CLASS_IN
    ttl: int = 0

    def __post_init__(self) -> None:
        rtype = _type_name(self.rtype)
        object.__setattr__(self, "rtype", rtype)
        expected = _RDATA_TYPES[rtype]
        if not isinstance(self.rdata, expected):
            raise TypeError(
                f"rdata for {rtype} must be {expected.__name__}, "
                f"got {type(self.rdata).__name__}"
            )

    def to_bytes(self) -> bytes:
        rdata_bytes = self.rdata.to_bytes()
        return (
            _encode_name(self.name)
            + struct.pack(
                "!HHIH",
                _TYPE_TO_NUMBER[self.rtype],
                self.rclass,
                self.ttl,
                len(rdata_bytes),
            )
            + rdata_bytes
        )


# ---------------------------------------------------------------------------
# Rdata value types. Each one validates in __post_init__ and serialises in
# to_bytes. Keeping them as separate small classes (rather than one bag with
# a type tag) means the type checker and ResourceRecord can both verify the
# rdata matches its rtype.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RdataA:
    """A record rdata: a single IPv4 address."""

    address: str

    def __post_init__(self) -> None:
        try:
            packed = socket.inet_aton(self.address)
        except OSError as exc:
            raise ValueError(f"invalid IPv4 address: {self.address!r}") from exc
        object.__setattr__(self, "_packed", packed)

    def to_bytes(self) -> bytes:
        return self._packed


@dataclass(frozen=True)
class RdataAAAA:
    """AAAA record rdata: a single IPv6 address."""

    address: str

    def __post_init__(self) -> None:
        try:
            packed = socket.inet_pton(socket.AF_INET6, self.address)
        except OSError as exc:
            raise ValueError(f"invalid IPv6 address: {self.address!r}") from exc
        object.__setattr__(self, "_packed", packed)

    def to_bytes(self) -> bytes:
        return self._packed


@dataclass(frozen=True)
class RdataCNAME:
    """CNAME record rdata: a target domain name."""

    cname: str

    def to_bytes(self) -> bytes:
        return _encode_name(self.cname)


@dataclass(frozen=True)
class RdataNS:
    """NS record rdata: a nameserver name."""

    nsname: str

    def to_bytes(self) -> bytes:
        return _encode_name(self.nsname)


@dataclass(frozen=True)
class RdataPTR:
    """PTR record rdata: a pointer name."""

    ptrname: str

    def to_bytes(self) -> bytes:
        return _encode_name(self.ptrname)


@dataclass(frozen=True)
class RdataMX:
    """MX record rdata: preference and mail exchange name."""

    preference: int
    exchange: str

    def __post_init__(self) -> None:
        if not 0 <= self.preference <= 0xFFFF:
            raise ValueError(f"preference out of range: {self.preference}")

    def to_bytes(self) -> bytes:
        return struct.pack("!H", self.preference) + _encode_name(self.exchange)


@dataclass(frozen=True)
class RdataTXT:
    """TXT record rdata: one or more character-strings (RFC 1035 §3.3.14).

    Each string is length-prefixed with a single byte. We enforce the 255-byte
    per-string limit here so the failure happens at construction, not deep in
    the serialiser. Multiple strings are preserved as distinct entries because
    that is how TXT is meant to work; concatenating them into one would change
    the semantics for receivers that care about the boundaries.
    """

    strings: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if isinstance(self.strings, str):
            # Common mistake: passing a single string. Treat it as one entry
            # rather than letting it blow up later with a confusing type error.
            object.__setattr__(self, "strings", (self.strings,))
        for s in self.strings:
            if not isinstance(s, str):
                raise TypeError(
                    f"txt string must be str, got {type(s).__name__}"
                )
            if len(s.encode("utf-8")) > 255:
                raise ValueError("txt string exceeds 255 bytes")

    def to_bytes(self) -> bytes:
        out = bytearray()
        for s in self.strings:
            encoded = s.encode("utf-8")
            out.append(len(encoded))
            out.extend(encoded)
        return bytes(out)


@dataclass(frozen=True)
class RdataSOA:
    """SOA record rdata (RFC 1035 §3.3.13)."""

    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    def __post_init__(self) -> None:
        for field_name in (
            "serial",
            "refresh",
            "retry",
            "expire",
            "minimum",
        ):
            value = getattr(self, field_name)
            if not 0 <= value <= 0xFFFFFFFF:
                raise ValueError(f"{field_name} out of range: {value}")

    def to_bytes(self) -> bytes:
        return (
            _encode_name(self.mname)
            + _encode_name(self.rname)
            + struct.pack(
                "!IIIII",
                self.serial,
                self.refresh,
                self.retry,
                self.expire,
                self.minimum,
            )
        )


@dataclass(frozen=True)
class RdataSRV:
    """SRV record rdata (RFC 2782)."""

    priority: int
    weight: int
    port: int
    target: str

    def __post_init__(self) -> None:
        if not 0 <= self.priority <= 0xFFFF:
            raise ValueError(f"priority out of range: {self.priority}")
        if not 0 <= self.weight <= 0xFFFF:
            raise ValueError(f"weight out of range: {self.weight}")
        if not 0 <= self.port <= 0xFFFF:
            raise ValueError(f"port out of range: {self.port}")

    def to_bytes(self) -> bytes:
        return (
            struct.pack("!HHH", self.priority, self.weight, self.port)
            + _encode_name(self.target)
        )


# Type alias table used by ResourceRecord to check rdata/rtype consistency.
_RDATA_TYPES = {
    "A": RdataA,
    "AAAA": RdataAAAA,
    "CNAME": RdataCNAME,
    "NS": RdataNS,
    "PTR": RdataPTR,
    "MX": RdataMX,
    "TXT": RdataTXT,
    "SOA": RdataSOA,
    "SRV": RdataSRV,
}


# Convenience aliases so callers can write ARecord(name, "203.0.113.1", ttl=300)
# without separately importing RdataA. These are thin wrappers; they exist only
# to make the common path one line shorter.

class _RRBuilder:
    _rtype: ClassVar[str] = ""
    _rdata_cls: ClassVar[type] = object

    name: str
    rdata: Any
    rclass: int
    ttl: int

    def __init__(self, name: str, *args: Any, ttl: int = 0, **kwargs: Any) -> None:
        self.name = name
        self.ttl = ttl
        self.rclass = CLASS_IN
        self.rdata = self._rdata_cls(*args, **kwargs)

    @property
    def rtype(self) -> str:
        return self._rtype

    def to_bytes(self) -> bytes:
        return ResourceRecord(
            name=self.name,
            rtype=self._rtype,
            rdata=self.rdata,
            rclass=self.rclass,
            ttl=self.ttl,
        ).to_bytes()


class ARecord(_RRBuilder):
    _rtype = "A"
    _rdata_cls = RdataA


class AAAARecord(_RRBuilder):
    _rtype = "AAAA"
    _rdata_cls = RdataAAAA


class CNAMERecord(_RRBuilder):
    _rtype = "CNAME"
    _rdata_cls = RdataCNAME


class NSRecord(_RRBuilder):
    _rtype = "NS"
    _rdata_cls = RdataNS


class PTRRecord(_RRBuilder):
    _rtype = "PTR"
    _rdata_cls = RdataPTR


class MXRecord(_RRBuilder):
    _rtype = "MX"
    _rdata_cls = RdataMX


class TXTRecord(_RRBuilder):
    _rtype = "TXT"
    _rdata_cls = RdataTXT


class SOARecord(_RRBuilder):
    _rtype = "SOA"
    _rdata_cls = RdataSOA


class SRVRecord(_RRBuilder):
    _rtype = "SRV"
    _rdata_cls = RdataSRV


def build_query(
    questions: list[Question],
    id: int = 0,
    flags: int = 0x0100,
) -> bytes:
    """Build a DNS query packet.

    Default flags 0x0100 sets RD (recursion desired), the usual default for a
    client-side query. The caller overrides flags for anything else.
    """
    if not questions:
        raise ValueError("query must have at least one question")
    header = Header(id=id, flags=flags, qdcount=len(questions))
    body = bytearray()
    for q in questions:
        body.extend(q.to_bytes())
    return header.to_bytes() + bytes(body)


def build_response(
    questions: list[Question],
    answers: list[Any] | None = None,
    authorities: list[Any] | None = None,
    additionals: list[Any] | None = None,
    id: int = 0,
    flags: int = 0x8180,
) -> bytes:
    """Build a DNS response packet.

    Default flags 0x8180 sets QR=1 and RA=1 with RCODE=0 (NOERROR), matching
    a typical successful recursive response. The caller can override flags for
    NXDOMAIN, REFUSED, or any other RCODE.

    Each entry in answers/authorities/additionals may be a ResourceRecord or any
    of the convenience record classes (ARecord, MXRecord, etc.). Both expose
    to_bytes(), so no isinstance check is needed at the call site.
    """
    answers = answers or []
    authorities = authorities or []
    additionals = additionals or []

    header = Header(
        id=id,
        flags=flags,
        qdcount=len(questions),
        ancount=len(answers),
        nscount=len(authorities),
        arcount=len(additionals),
    )
    body = bytearray()
    for q in questions:
        body.extend(q.to_bytes())
    for rr in answers + authorities + additionals:
        body.extend(rr.to_bytes())
    return header.to_bytes() + bytes(body)
