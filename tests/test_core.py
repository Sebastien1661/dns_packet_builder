import struct
import unittest
import socket

from dns_packet_builder import (
    Question,
    ResourceRecord,
    RdataA,
    RdataAAAA,
    RdataCNAME,
    RdataMX,
    RdataTXT,
    RdataNS,
    RdataPTR,
    RdataSOA,
    RdataSRV,
    ARecord,
    AAAARecord,
    CNAMERecord,
    MXRecord,
    TXTRecord,
    NSRecord,
    PTRRecord,
    SOARecord,
    SRVRecord,
    build_query,
    build_response,
)


class TestNameEncoding(unittest.TestCase):
    def test_simple_name(self):
        self.assertEqual(_encode_name_local("example.test"), b"\x07example\x04test\x00")

    def test_root(self):
        self.assertEqual(_encode_name_local(""), b"\x00")
        self.assertEqual(_encode_name_local("."), b"\x00")

    def test_trailing_dot_stripped(self):
        self.assertEqual(_encode_name_local("a.b."), _encode_name_local("a.b"))

    def test_empty_label_rejected(self):
        with self.assertRaises(ValueError):
            _encode_name_local("a..b")

    def test_oversized_label_rejected(self):
        with self.assertRaises(ValueError):
            _encode_name_local("x" * 64)


class TestHeader(unittest.TestCase):
    from dns_packet_builder.core import Header

    def test_pack_roundtrip(self):
        h = self.Header(id=0x1234, flags=0x8180, qdcount=1, ancount=2)
        packed = h.to_bytes()
        parsed = self.Header.parse(packed)
        self.assertEqual(parsed, h)

    def test_bad_id(self):
        from dns_packet_builder.core import Header
        with self.assertRaises(ValueError):
            Header(id=0x10000).to_bytes()


class TestQuestion(unittest.TestCase):
    def test_a_question_bytes(self):
        q = Question("example.test", "A")
        self.assertEqual(
            q.to_bytes(),
            b"\x07example\x04test\x00" + struct.pack("!HH", 1, 1),
        )

    def test_type_normalised_to_string(self):
        q = Question("example.test", 28)
        self.assertEqual(q.qtype, "AAAA")

    def test_lowercase_type_accepted(self):
        q = Question("example.test", "mx")
        self.assertEqual(q.qtype, "MX")

    def test_parse_roundtrip(self):
        q = Question("example.test", "A")
        raw = q.to_bytes()
        parsed, off = Question.parse(raw, 0)
        self.assertEqual(parsed.qname, "example.test")
        self.assertEqual(parsed.qtype, "A")
        self.assertEqual(parsed.qclass, 1)
        self.assertEqual(off, len(raw))

    def test_unknown_type_string_rejected(self):
        with self.assertRaises(NotImplementedError):
            Question("example.test", "NAPTR")

    def test_unknown_type_code_rejected(self):
        with self.assertRaises(NotImplementedError):
            Question("example.test", 999)


class TestRecordA(unittest.TestCase):
    def test_a_record_bytes(self):
        rr = ResourceRecord("example.test", "A", RdataA("203.0.113.5"), ttl=300)
        self.assertEqual(
            rr.to_bytes(),
            b"\x07example\x04test\x00"
            + struct.pack("!HHIH", 1, 1, 300, 4)
            + socket.inet_aton("203.0.113.5"),
        )

    def test_a_record_via_alias(self):
        rr = ARecord("example.test", "203.0.113.5", ttl=300)
        expected = ResourceRecord(
            "example.test", "A", RdataA("203.0.113.5"), ttl=300
        ).to_bytes()
        self.assertEqual(rr.to_bytes(), expected)

    def test_bad_ipv4_rejected(self):
        with self.assertRaises(ValueError):
            RdataA("not.an.ip")


class TestRecordAAAA(unittest.TestCase):
    def test_aaaa_record_bytes(self):
        rr = ResourceRecord("example.test", "AAAA", RdataAAAA("2001:db8::1"))
        rdata = rr.to_bytes()
        # name + fixed(10) + 16-byte address
        self.assertEqual(len(rdata), len(b"\x07example\x04test\x00") + 10 + 16)

    def test_bad_ipv6_rejected(self):
        with self.assertRaises(ValueError):
            RdataAAAA("::g")


class TestRecordCNAME(unittest.TestCase):
    def test_cname_bytes(self):
        rr = CNAMERecord("alias.test", "target.test")
        self.assertEqual(
            rr.to_bytes(),
            b"\x05alias\x04test\x00"
            + struct.pack("!HHIH", 5, 1, 0, len(b"\x06target\x04test\x00"))
            + b"\x06target\x04test\x00",
        )


class TestRecordMX(unittest.TestCase):
    def test_mx_bytes(self):
        rr = MXRecord("example.test", 10, "mail.example.test")
        rdata = b"\x00\x0a" + b"\x04mail\x07example\x04test\x00"
        self.assertEqual(
            rr.to_bytes(),
            b"\x07example\x04test\x00"
            + struct.pack("!HHIH", 15, 1, 0, len(rdata))
            + rdata,
        )

    def test_preference_overflow(self):
        with self.assertRaises(ValueError):
            RdataMX(0x10000, "mail.test")


class TestRecordTXT(unittest.TestCase):
    def test_single_string(self):
        rd = RdataTXT(("hello",))
        self.assertEqual(rd.to_bytes(), b"\x05hello")

    def test_multiple_strings_preserved(self):
        rd = RdataTXT(("aa", "bbbb"))
        self.assertEqual(rd.to_bytes(), b"\x02aa\x04bbbb")

    def test_string_passes_as_bare_str(self):
        rd = RdataTXT("hello")
        self.assertEqual(rd.to_bytes(), b"\x05hello")

    def test_oversize_string_rejected(self):
        with self.assertRaises(ValueError):
            RdataTXT(("x" * 256,))

    def test_non_string_rejected(self):
        with self.assertRaises(TypeError):
            RdataTXT((123,))


class TestRecordNS(unittest.TestCase):
    def test_ns_bytes(self):
        rr = NSRecord("example.test", "ns1.example.test")
        self.assertIn(b"\x03ns1", rr.to_bytes())


class TestRecordPTR(unittest.TestCase):
    def test_ptr_bytes(self):
        rr = PTRRecord("1.0.0.10.in-addr.arpa", "host.test")
        self.assertIn(b"\x04host\x04test\x00", rr.to_bytes())


class TestRecordSOA(unittest.TestCase):
    def test_soa_bytes(self):
        rd = RdataSOA("ns.test", "admin.test", 2021010101, 3600, 900, 1209600, 86400)
        rr = SOARecord("test", rd.mname, rd.rname, rd.serial, rd.refresh, rd.retry, rd.expire, rd.minimum)
        rdata = rd.to_bytes()
        self.assertEqual(
            rr.to_bytes(),
            b"\x04test\x00" + struct.pack("!HHIH", 6, 1, 0, len(rdata)) + rdata,
        )

    def test_serial_overflow(self):
        with self.assertRaises(ValueError):
            RdataSOA("ns.test", "admin.test", 0x100000000, 1, 1, 1, 1)


class TestRecordSRV(unittest.TestCase):
    def test_srv_bytes(self):
        rd = RdataSRV(10, 60, 5060, "sip.test")
        rr = SRVRecord("_sip._tcp.test", rd.priority, rd.weight, rd.port, rd.target)
        rdata = struct.pack("!HHH", 10, 60, 5060) + b"\x03sip\x04test\x00"
        self.assertEqual(
            rr.to_bytes(),
            b"\x04_sip\x04_tcp\x04test\x00"
            + struct.pack("!HHIH", 33, 1, 0, len(rdata))
            + rdata,
        )

    def test_port_overflow(self):
        with self.assertRaises(ValueError):
            RdataSRV(0, 0, 0x10000, "t.test")


class TestRdataTypeMismatch(unittest.TestCase):
    def test_mismatch_rejected(self):
        with self.assertRaises(TypeError):
            ResourceRecord("example.test", "A", RdataAAAA("::1"))


class TestBuildQuery(unittest.TestCase):
    def test_query_packet(self):
        pkt = build_query([Question("example.test", "A")], id=0xABCD)
        # header
        self.assertEqual(pkt[:12], struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0))
        # question
        self.assertEqual(
            pkt[12:],
            b"\x07example\x04test\x00" + struct.pack("!HH", 1, 1),
        )

    def test_empty_questions_rejected(self):
        with self.assertRaises(ValueError):
            build_query([])


class TestBuildResponse(unittest.TestCase):
    def test_response_with_answer(self):
        q = Question("example.test", "A")
        ans = ARecord("example.test", "203.0.113.1", ttl=60)
        pkt = build_response([q], [ans], id=0x1234)
        self.assertEqual(pkt[:12], struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0))

    def test_response_with_multiple_sections(self):
        q = Question("example.test", "A")
        ans = ARecord("example.test", "203.0.113.1")
        auth = NSRecord("example.test", "ns1.example.test")
        add = ARecord("ns1.example.test", "203.0.113.9")
        pkt = build_response([q], [ans], [auth], [add])
        self.assertEqual(pkt[:12], struct.pack("!HHHHHH", 0, 0x8180, 1, 1, 1, 1))

    def test_empty_answer_ok(self):
        q = Question("example.test", "A")
        pkt = build_response([q], [])
        self.assertEqual(pkt[:12], struct.pack("!HHHHHH", 0, 0x8180, 1, 0, 0, 0))


def _encode_name_local(name):
    from dns_packet_builder.core import _encode_name
    return _encode_name(name)


if __name__ == "__main__":
    unittest.main()
