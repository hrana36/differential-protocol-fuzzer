"""
Unit & Differential Test Suite for Differential Protocol Fuzzer
"""
import os
import sys

repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_dir not in sys.path:
    sys.path.insert(0, repo_dir)

import pytest
from fuzzer.protocols.dns_wire import build_seed_packet
from fuzzer.protocols.dns_parser_strict import DNSStrictParser, DNSParserError
from fuzzer.protocols.dns_parser_lenient import DNSLenientParser, DNSLenientError
from fuzzer.mutator import ProtocolMutator
from fuzzer.divergence_detector import (
    DifferentialDivergenceDetector,
    DivergenceType,
    DivergenceSeverity,
)
from fuzzer.engine import DifferentialFuzzerEngine


def test_seed_packet_validity():
    pkt = build_seed_packet("test.example.com", qtype=1)
    res_a = DNSStrictParser.parse(pkt)
    res_b = DNSLenientParser.parse(pkt)

    assert res_a["status"] == "VALID"
    assert res_b["status"] == "VALID"
    assert res_a["questions"][0]["qname"] == "test.example.com"
    assert res_b["questions"][0]["qname"] == "test.example.com"

    # Evaluator should find NO divergence on valid seed
    divergence = DifferentialDivergenceDetector.evaluate(pkt, (True, res_a), (True, res_b))
    assert divergence is None


def test_pointer_cycle_strict_rejection():
    seed = bytearray(build_seed_packet("loop.org"))
    # Inject self-referencing pointer at offset 12 -> 12
    seed[12] = 0xC0
    seed[13] = 0x0C

    with pytest.raises(DNSParserError):
        DNSStrictParser.parse(bytes(seed))


def test_forward_pointer_differential_desync():
    pkt = bytearray(build_seed_packet("sub.target.net"))
    # In strict parser, pointer target must be < current offset (12).
    # We construct a buffer with a pointer at offset 12 pointing ahead to offset 18
    pkt[12] = 0xC0
    pkt[13] = 18

    # Strict parser must reject
    strict_ok = True
    try:
        res_a = DNSStrictParser.parse(bytes(pkt))
    except DNSParserError as e:
        strict_ok = False
        res_a = str(e)

    # Lenient parser tolerates forward references
    lenient_ok = True
    try:
        res_b = DNSLenientParser.parse(bytes(pkt))
    except DNSLenientError as e:
        lenient_ok = False
        res_b = str(e)

    record = DifferentialDivergenceDetector.evaluate(bytes(pkt), (strict_ok, res_a), (lenient_ok, res_b))
    assert record is not None
    assert record.divergence_type in (DivergenceType.ACCEPT_REJECT_DESYNC, DivergenceType.SEMANTIC_FIELD_MISMATCH)


def test_trailing_padding_desync():
    valid = build_seed_packet("valid.domain.io")
    padded = valid + b"\xde\xad\xbe\xef\x00\x01"

    # Strict rejects trailing unparsed bytes
    with pytest.raises(DNSParserError):
        DNSStrictParser.parse(padded)

    # Lenient ignores trailing padding
    res_b = DNSLenientParser.parse(padded)
    assert res_b["status"] == "VALID"

    record = DifferentialDivergenceDetector.evaluate(
        padded,
        (False, "Strict violation: 6 unparsed trailing trailing bytes"),
        (True, res_b),
    )
    assert record is not None
    assert record.divergence_type == DivergenceType.ACCEPT_REJECT_DESYNC
    assert record.severity == DivergenceSeverity.CRITICAL


def test_mutator_changes_payload():
    seed = build_seed_packet("test.corp")
    mutator = ProtocolMutator(seed=999)

    mutated = mutator.mutate(seed, num_mutations=2)
    assert mutated != seed


def test_fuzzer_engine_mini_campaign():
    engine = DifferentialFuzzerEngine(random_seed=42)
    report = engine.run_campaign(max_iterations=500)

    assert report["iterations_executed"] == 500
    assert report["unique_divergences_discovered"] > 0
    assert "ACCEPT_REJECT_DESYNC" in report["divergence_breakdown_by_type"]
