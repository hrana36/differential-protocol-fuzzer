"""
Coverage and Grammar-Guided Mutation Engine for Differential Protocol Fuzzing
Generates bit, byte, structural, and grammar-aware mutations targeting protocol parsers.
"""
import random
import struct
from typing import List, Callable


class ProtocolMutator:
    """
    Applies stochastic and grammar-aware mutations to byte sequences.
    """

    MAGIC_BYTES = [
        b"\x00", b"\x01", b"\xff", b"\x7f", b"\x80",
        b"\xc0\x0c",  # DNS compression pointer pointing to standard offset 12
        b"\xc0\x00",  # Pointer to header ID
        b"\xc0\xff",  # Pointer beyond buffer
        b"\x3f",      # Max valid label length (63)
        b"\x40",      # Boundary overflow label length (64)
        b"\x00\x00",  # Null QTYPE/QCLASS
    ]

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.mutation_operators: List[Callable[[bytearray], None]] = [
            self._mutate_bit_flip,
            self._mutate_byte_replace,
            self._mutate_magic_bytes,
            self._mutate_trailing_padding,
            self._mutate_dns_reserved_flags,
            self._mutate_pointer_loop,
            self._mutate_forward_pointer,
            self._mutate_label_length_overflow,
            self._mutate_qdcount_desync,
        ]

    def _mutate_bit_flip(self, buf: bytearray):
        if not buf:
            return
        pos = self.rng.randint(0, len(buf) - 1)
        bit = 1 << self.rng.randint(0, 7)
        buf[pos] ^= bit

    def _mutate_byte_replace(self, buf: bytearray):
        if not buf:
            return
        pos = self.rng.randint(0, len(buf) - 1)
        buf[pos] = self.rng.randint(0, 255)

    def _mutate_magic_bytes(self, buf: bytearray):
        if len(buf) < 4:
            return
        magic = self.rng.choice(self.MAGIC_BYTES)
        pos = self.rng.randint(0, len(buf) - len(magic))
        buf[pos:pos + len(magic)] = magic

    def _mutate_trailing_padding(self, buf: bytearray):
        pad_len = self.rng.randint(1, 16)
        padding = bytes([self.rng.randint(0, 255) for _ in range(pad_len)])
        buf.extend(padding)

    def _mutate_dns_reserved_flags(self, buf: bytearray):
        if len(buf) >= 4:
            # Set reserved 'z' bits (offset 3, bits 4-6)
            buf[3] |= 0x70

    def _mutate_pointer_loop(self, buf: bytearray):
        """Injects a self-referencing compression pointer cycle (offset 12 -> 12)."""
        if len(buf) >= 14:
            # Target offset 12 (start of QNAME)
            buf[12] = 0xC0
            buf[13] = 0x0C

    def _mutate_forward_pointer(self, buf: bytearray):
        """Injects a forward compression pointer pointing ahead in the buffer."""
        if len(buf) >= 16:
            buf[12] = 0xC0
            buf[13] = len(buf) - 2  # Points to near end of packet

    def _mutate_label_length_overflow(self, buf: bytearray):
        """Sets QNAME first label length to 64+ bytes (> 63 byte RFC 1035 limit)."""
        if len(buf) > 12:
            buf[12] = self.rng.randint(64, 127)

    def _mutate_qdcount_desync(self, buf: bytearray):
        """Sets QDCOUNT in header higher than actual questions serialized."""
        if len(buf) >= 6:
            buf[4] = 0x00
            buf[5] = self.rng.randint(2, 10)

    def mutate(self, seed: bytes, num_mutations: int = 1) -> bytes:
        """Applies N random mutation operators to input seed payload."""
        buf = bytearray(seed)
        for _ in range(num_mutations):
            op = self.rng.choice(self.mutation_operators)
            op(buf)
        return bytes(buf)
