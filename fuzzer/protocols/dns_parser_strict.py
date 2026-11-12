"""
Strict RFC 1035 DNS Wire Parser (Parser Alpha)
Enforces strict pointer bounds, recursion limits, label length constraints,
and prohibits forward compression references or trailing padding.
"""
import struct
from typing import Tuple, List, Dict, Any


class DNSParserError(Exception):
    pass


class DNSStrictParser:
    """Strict RFC 1035 Reference Implementation Parser."""
    NAME = "StrictParser-Alpha"

    @classmethod
    def parse_name(cls, data: bytes, offset: int) -> Tuple[str, int]:
        labels = []
        original_offset = offset
        jumped = False
        bytes_consumed = 0
        jumps = 0
        visited_offsets = set()

        while True:
            if offset >= len(data):
                raise DNSParserError("Unexpected EOF while parsing QNAME label")

            b = data[offset]
            if b == 0:
                offset += 1
                if not jumped:
                    bytes_consumed += 1
                break

            # Check compression pointer (top 2 bits set: 1100 0000 = 0xC0)
            if (b & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    raise DNSParserError("Malformed 2-byte compression pointer at EOF")

                ptr_target = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
                # Strict RFC requirement: Pointer must point to an offset strictly preceding the pointer
                if ptr_target >= offset:
                    raise DNSParserError(f"Strict violation: Forward or self compression pointer ({ptr_target} >= {offset})")

                if ptr_target in visited_offsets:
                    raise DNSParserError("Pointer loop cycle detected in DNS compression")
                visited_offsets.add(ptr_target)

                jumps += 1
                if jumps > 5:
                    raise DNSParserError("Exceeded strict pointer jump recursion limit (5)")

                if not jumped:
                    bytes_consumed += 2
                    jumped = True

                offset = ptr_target
            else:
                length = b
                if length > 63:
                    raise DNSParserError(f"Label length {length} exceeds RFC 1035 maximum limit of 63 bytes")

                offset += 1
                if not jumped:
                    bytes_consumed += 1

                if offset + length > len(data):
                    raise DNSParserError("Label extends beyond packet buffer")

                label_bytes = data[offset:offset + length]
                try:
                    labels.append(label_bytes.decode("ascii"))
                except UnicodeDecodeError:
                    raise DNSParserError("Invalid non-ASCII characters in label")

                offset += length
                if not jumped:
                    bytes_consumed += length

        domain = ".".join(labels)
        if len(domain) > 255:
            raise DNSParserError("Total domain name length exceeds 255 bytes")

        return domain, bytes_consumed

    @classmethod
    def parse(cls, raw: bytes) -> Dict[str, Any]:
        """Parses a raw DNS byte buffer strictly."""
        if len(raw) < 12:
            raise DNSParserError("Packet smaller than 12-byte mandatory DNS header")

        header_fields = struct.unpack("!HHHHHH", raw[:12])
        msg_id, flags, qdcount, ancount, nscount, arcount = header_fields

        qr = (flags >> 15) & 0x01
        opcode = (flags >> 11) & 0x0F
        aa = (flags >> 10) & 0x01
        tc = (flags >> 9) & 0x01
        rd = (flags >> 8) & 0x01
        ra = (flags >> 7) & 0x01
        z = (flags >> 4) & 0x07
        rcode = flags & 0x0F

        if z != 0:
            raise DNSParserError(f"Reserved flag bits non-zero: z={z}")

        offset = 12
        questions = []
        for _ in range(qdcount):
            domain, consumed = cls.parse_name(raw, offset)
            offset += consumed
            if offset + 4 > len(raw):
                raise DNSParserError("Truncated question section")
            qtype, qclass = struct.unpack("!HH", raw[offset:offset + 4])
            offset += 4
            questions.append({"qname": domain, "qtype": qtype, "qclass": qclass})

        # Strict: disallow trailing unparsed bytes if ancount == 0
        if ancount == 0 and nscount == 0 and arcount == 0:
            if offset != len(raw):
                raise DNSParserError(f"Strict violation: {len(raw) - offset} unparsed trailing trailing bytes")

        return {
            "status": "VALID",
            "id": msg_id,
            "qr": qr,
            "opcode": opcode,
            "rcode": rcode,
            "questions": questions,
            "qdcount": qdcount,
            "ancount": ancount,
        }
