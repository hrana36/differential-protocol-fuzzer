"""
Differential Divergence Detector
Compares execution traces, validation states, and parsed AST structures between dual protocol parsers.
"""
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, Tuple


class DivergenceSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DivergenceType(str, Enum):
    ACCEPT_REJECT_DESYNC = "ACCEPT_REJECT_DESYNC"      # One parser accepted, other rejected
    SEMANTIC_FIELD_MISMATCH = "SEMANTIC_FIELD_MISMATCH"  # Both accepted, but parsed fields differ
    EXCEPTION_ASYMMETRY = "EXCEPTION_ASYMMETRY"        # Both rejected with divergent error classes
    UNHANDLED_CRASH = "UNHANDLED_CRASH"                # Fatal exception (IndexError, MemoryError)


@dataclass
class DivergenceRecord:
    divergence_id: str
    divergence_type: DivergenceType
    severity: DivergenceSeverity
    raw_payload_hex: str
    payload_len: int
    parser_a_result: Dict[str, Any]
    parser_b_result: Dict[str, Any]
    description: str


class DifferentialDivergenceDetector:
    """
    Analyzes and classifies execution discrepancies between dual protocol parsers.
    """

    @classmethod
    def compute_payload_id(cls, raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()[:16]

    @classmethod
    def evaluate(
        cls,
        raw_payload: bytes,
        result_a: Tuple[bool, Any],
        result_b: Tuple[bool, Any],
    ) -> Optional[DivergenceRecord]:
        """
        result_a: (is_success, dict_data_or_error_msg)
        result_b: (is_success, dict_data_or_error_msg)
        """
        ok_a, data_a = result_a
        ok_b, data_b = result_b

        payload_id = cls.compute_payload_id(raw_payload)
        payload_hex = raw_payload.hex()

        # Case 1: Accept/Reject Desync (One accepted, other rejected)
        if ok_a != ok_b:
            acceptor = "Parser-Alpha" if ok_a else "Parser-Beta"
            rejector = "Parser-Beta" if ok_a else "Parser-Alpha"
            err = data_b if ok_a else data_a

            desc = f"Desynchronization: {acceptor} accepted payload as valid, whereas {rejector} rejected with error: '{err}'"
            return DivergenceRecord(
                divergence_id=payload_id,
                divergence_type=DivergenceType.ACCEPT_REJECT_DESYNC,
                severity=DivergenceSeverity.CRITICAL,
                raw_payload_hex=payload_hex,
                payload_len=len(raw_payload),
                parser_a_result={"valid": ok_a, "data": str(data_a)},
                parser_b_result={"valid": ok_b, "data": str(data_b)},
                description=desc,
            )

        # Case 2: Both accepted -> Check for semantic field mismatch
        if ok_a and ok_b:
            # Check question count
            if data_a.get("qdcount") != data_b.get("qdcount"):
                desc = f"Semantic drift: QDCOUNT mismatch (Alpha={data_a.get('qdcount')}, Beta={data_b.get('qdcount')})"
                return DivergenceRecord(
                    divergence_id=payload_id,
                    divergence_type=DivergenceType.SEMANTIC_FIELD_MISMATCH,
                    severity=DivergenceSeverity.HIGH,
                    raw_payload_hex=payload_hex,
                    payload_len=len(raw_payload),
                    parser_a_result=data_a,
                    parser_b_result=data_b,
                    description=desc,
                )

            # Check extracted QNAMEs
            qs_a = data_a.get("questions", [])
            qs_b = data_b.get("questions", [])
            if len(qs_a) == len(qs_b) and len(qs_a) > 0:
                for idx, (qa, qb) in enumerate(zip(qs_a, qs_b)):
                    if qa.get("qname") != qb.get("qname"):
                        desc = f"Semantic drift: QNAME mismatch at index {idx} ('{qa.get('qname')}' vs '{qb.get('qname')}')"
                        return DivergenceRecord(
                            divergence_id=payload_id,
                            divergence_type=DivergenceType.SEMANTIC_FIELD_MISMATCH,
                            severity=DivergenceSeverity.HIGH,
                            raw_payload_hex=payload_hex,
                            payload_len=len(raw_payload),
                            parser_a_result=data_a,
                            parser_b_result=data_b,
                            description=desc,
                        )

        # No behavioral divergence detected
        return None
