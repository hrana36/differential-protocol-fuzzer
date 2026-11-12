"""
Lenient DNS Wire Parser (Parser Beta)
Modeled after permissive legacy / embedded implementations. Tolerates forward pointers,
trailing padding, non-zero reserved bits, and arbitrary label byte encodings.
"""
import struct
from typing import Tuple, List, Dict, Any


class DNSLenientError(Exception):
    pass


class DNSLenientParser:
    """Lenient / Permissive DNS Parser Implementation."""
    NAME = "LenientParser-Beta"

    @classmethod
    def parse_name(cls, data: bytes, offset: int) -> Tuple[str, int]:
        labels = []
        original_offset = offset
        jumped = False
        bytes_consumed = 0
        jumps = 0

        while True:
            if offset >= len(data):
                break

            b = data[offset]
            if b == 0:
                offset += 1
                if not jumped:
                    bytes_consumed += 1
                break

            # Check compression pointer (0xC0)
            if (b & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break

                ptr_target = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
                # Lenient: allows forward references within packet buffer
                if ptr_target >= len(data):
                    raise DNSLenientError(f"Pointer target {ptr_target} outside buffer length {len(data)}")

                jumps += 1
                if jumps > 20:
                    raise DNSLenientError("Recursion depth limit exceeded (20)")

                if not jumped:
                    bytes_consumed += 2
                    jumped = True

                offset = ptr_target
            else:
                length = b
                offset += 1
                if not jumped:
                    bytes_consumed += 1

                # Lenient: clamp to available remaining buffer
                avail = max(0, len(data) - offset)
                actual_len = min(length, avail)
                label_bytes = data[offset:offset + actual_len]

                # Lenient decoding with replacement
                labels.append(label_bytes.decode("ascii", errors="replace"))

                offset += actual_len
                if not jumped:
                    bytes_consumed += actual_len

                if actual_len < length:
                    break

        domain = ".".join(labels)
        return domain, bytes_consumed

    @classmethod
    def parse(cls, raw: bytes) -> Dict[str, Any]:
        """Parses a raw DNS byte buffer leniently."""
        if len(raw) < 12:
            raise DNSLenientError("Buffer shorter than 12 bytes")

        header_fields = struct.unpack("!HHHHHH", raw[:12])
        msg_id, flags, qdcount, ancount, nscount, arcount = header_fields

        qr = (flags >> 15) & 0x01
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F
        # Lenient: ignores reserved flags (z)

        offset = 12
        questions = []
        for _ in range(qdcount):
            if offset >= len(raw):
                break
            domain, consumed = cls.parse_name(raw, offset)
            offset += consumed
            if offset + 4 <= len(raw):
                qtype, qclass = struct.unpack("!HH", raw[offset:offset + 4])
                offset += 4
                questions.append({"qname": domain, "qtype": qtype, "qclass": qclass})
            else:
                break

        # Lenient: ignores any unparsed trailing padding bytes

        return {
            "status": "VALID",
            "id": msg_id,
            "qr": qr,
            "opcode": opcode,
            "rcode": rcode,
            "questions": questions,
            "qdcount": len(questions),
            "ancount": ancount,
        }
