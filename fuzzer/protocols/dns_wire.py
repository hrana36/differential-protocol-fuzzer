"""
DNS Wire Format (RFC 1035) Data Structures & Packet Serialization
"""
import struct
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DNSHeader:
    id: int = 0x1234
    qr: int = 0         # 0 = query, 1 = response
    opcode: int = 0     # 0 = standard query
    aa: int = 0         # Authoritative Answer
    tc: int = 0         # TrunCation
    rd: int = 1         # Recursion Desired
    ra: int = 0         # Recursion Available
    z: int = 0          # Reserved (zero)
    rcode: int = 0      # Response code
    qdcount: int = 1    # Number of questions
    ancount: int = 0    # Number of answers
    nscount: int = 0    # Number of authority records
    arcount: int = 0    # Number of additional records

    def pack(self) -> bytes:
        flags = (
            (self.qr << 15)
            | (self.opcode << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.z << 4)
            | (self.rcode & 0x0F)
        )
        return struct.pack("!HHHHHH", self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount)


@dataclass
class DNSQuestion:
    qname: str
    qtype: int = 1      # 1 = A, 28 = AAAA, 15 = MX
    qclass: int = 1     # 1 = IN (Internet)

    def pack(self) -> bytes:
        data = bytearray()
        for part in self.qname.strip(".").split("."):
            data.append(len(part))
            data.extend(part.encode("ascii", errors="replace"))
        data.append(0)  # Terminal root label
        data.extend(struct.pack("!HH", self.qtype, self.qclass))
        return bytes(data)


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes


@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSRecord] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        buf = bytearray(self.header.pack())
        for q in self.questions:
            buf.extend(q.pack())
        return bytes(buf)


def build_seed_packet(domain: str = "example.com", qtype: int = 1) -> bytes:
    """Builds a standard valid RFC 1035 DNS Query byte string."""
    header = DNSHeader(id=0xABCD, qdcount=1)
    question = DNSQuestion(qname=domain, qtype=qtype)
    packet = DNSPacket(header=header, questions=[question])
    return packet.to_bytes()
