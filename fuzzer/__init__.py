"""
Differential Protocol Fuzzing Framework
"""
from fuzzer.protocols.dns_wire import DNSHeader, DNSQuestion, DNSPacket, build_seed_packet
from fuzzer.protocols.dns_parser_strict import DNSStrictParser, DNSParserError
from fuzzer.protocols.dns_parser_lenient import DNSLenientParser, DNSLenientError
from fuzzer.mutator import ProtocolMutator
from fuzzer.divergence_detector import (
    DifferentialDivergenceDetector,
    DivergenceRecord,
    DivergenceType,
    DivergenceSeverity,
)
from fuzzer.engine import DifferentialFuzzerEngine

__all__ = [
    "DNSHeader",
    "DNSQuestion",
    "DNSPacket",
    "build_seed_packet",
    "DNSStrictParser",
    "DNSParserError",
    "DNSLenientParser",
    "DNSLenientError",
    "ProtocolMutator",
    "DifferentialDivergenceDetector",
    "DivergenceRecord",
    "DivergenceType",
    "DivergenceSeverity",
    "DifferentialFuzzerEngine",
]
