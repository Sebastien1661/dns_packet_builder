# dns_packet_builder

Construct DNS wire-format packets from structured record definitions, for both query and response messages. Standard library only — no dependencies.

```python
from dns_packet_builder import (
    Question, build_query, build_response,
    ARecord, MXRecord, TXTRecord, NSRecord, SOARecord,
    ResourceRecord, RdataA, RdataCNAME,
)

# Build a query packet
query = build_query(
    [Question("service.example", "A")],
    id=0x1234,
)

# Build a response packet with answers, authority, and additional sections
response = build_response(
    questions=[Question("service.example", "A")],
    answers=[ARecord("service.example", "203.0.113.10", ttl=300)],
    authorities=[NSRecord("example", "ns1.example")],
    additionals=[ARecord("ns1.example", "203.0.113.53")],
    id=0x1234,
)

# Or construct a record from its rdata value directly
rr = ResourceRecord("alias.example", "CNAME", RdataCNAME("target.example"), ttl=60)
response = build_response(
    questions=[Question("alias.example", "CNAME")],
    answers=[rr],
)
```

## Why this exists

Producing a DNS packet by hand is a matter of knowing the layout and not getting the byte order wrong — work that belongs in a small, auditable function rather than a framework. This library covers exactly that: structured records in, `bytes` out, no I/O, no parsing, no caching, no EDNS, no DNSSEC.

The trade-off is that it does not do name compression. Compression requires tracking previously emitted name offsets and matching suffixes, which adds state and complexity for a few saved bytes per packet. Uncompressed packets are always valid wire format; they are just slightly larger. If you are generating packets near the 512-byte UDP limit and need compression, this is not the right tool.

## Edge cases you will hit

- **Unsupported rdata types.** Only A, AAAA, CNAME, MX, TXT, NS, PTR, SOA, and SRV are implemented. Passing any other type (string or numeric code) raises `NotImplementedError` immediately, so you find out at construction rather than producing a corrupt packet.
- **Type mismatch.** `ResourceRecord` verifies that its `rdata` value matches its `rtype`; `ResourceRecord("x", "A", RdataAAAA("::1"))` raises `TypeError`.
- **Oversized TXT strings.** Each TXT character-string is limited to 255 bytes (RFC 1035). Strings exceeding that are rejected at construction. Multiple strings are kept as separate length-prefixed entries rather than concatenated.
- **Integer range checks.** Header `id`/`flags`, MX preference, SOA serial/refresh/retry/expire/minimum, and SRV priority/weight/port are all range-checked.
- **Label length.** Domain labels longer than 63 bytes or empty labels (e.g., `"a..b"`) raise `ValueError`.
- **IPv4/IPv6 validation.** Addresses are validated via the standard library `socket` module; invalid forms raise `ValueError`.
