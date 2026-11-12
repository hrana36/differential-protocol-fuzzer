"""
Differential Fuzzing Engine Orchestrator
Coordinates seed corpus management, test case dispatch, divergence isolation, and telemetry.
"""
import time
import os
import json
from typing import List, Dict, Any, Optional
from fuzzer.protocols.dns_wire import build_seed_packet
from fuzzer.protocols.dns_parser_strict import DNSStrictParser, DNSParserError
from fuzzer.protocols.dns_parser_lenient import DNSLenientParser, DNSLenientError
from fuzzer.mutator import ProtocolMutator
from fuzzer.divergence_detector import (
    DifferentialDivergenceDetector,
    DivergenceRecord,
    DivergenceType,
    DivergenceSeverity,
)


class DifferentialFuzzerEngine:
    """
    High-performance differential protocol fuzzing coordinator.
    """

    def __init__(self, seed_domains: Optional[List[str]] = None, random_seed: int = 42):
        self.mutator = ProtocolMutator(seed=random_seed)
        self.parser_a = DNSStrictParser()
        self.parser_b = DNSLenientParser()
        self.detector = DifferentialDivergenceDetector()

        domains = seed_domains or [
            "example.com",
            "corp.internal",
            "api.service.io",
            "resolver.cluster.local",
            "secure.auth.net",
        ]
        self.corpus: List[bytes] = [build_seed_packet(d) for d in domains]
        self.divergences: Dict[str, DivergenceRecord] = {}
        self.iterations = 0
        self.start_time = 0.0

    def _execute_parser_a(self, payload: bytes):
        try:
            res = self.parser_a.parse(payload)
            return True, res
        except DNSParserError as e:
            return False, str(e)
        except Exception as e:
            return False, f"UNHANDLED_EXCEPTION: {type(e).__name__}: {str(e)}"

    def _execute_parser_b(self, payload: bytes):
        try:
            res = self.parser_b.parse(payload)
            return True, res
        except DNSLenientError as e:
            return False, str(e)
        except Exception as e:
            return False, f"UNHANDLED_EXCEPTION: {type(e).__name__}: {str(e)}"

    def fuzz_one(self) -> Optional[DivergenceRecord]:
        """Performs a single mutation and dual-parser differential check."""
        self.iterations += 1
        seed = self.mutator.rng.choice(self.corpus)
        mutated_payload = self.mutator.mutate(seed, num_mutations=self.mutator.rng.randint(1, 3))

        res_a = self._execute_parser_a(mutated_payload)
        res_b = self._execute_parser_b(mutated_payload)

        record = self.detector.evaluate(mutated_payload, res_a, res_b)
        if record:
            if record.divergence_id not in self.divergences:
                self.divergences[record.divergence_id] = record
                # Add interesting divergent payload back to corpus to guide deeper exploration
                if len(self.corpus) < 100:
                    self.corpus.append(mutated_payload)
            return record
        return None

    def run_campaign(self, max_iterations: int = 50000) -> Dict[str, Any]:
        """Executes a full differential fuzzing campaign."""
        self.iterations = 0
        self.divergences.clear()
        self.start_time = time.perf_counter()

        for _ in range(max_iterations):
            self.fuzz_one()

        elapsed = time.perf_counter() - self.start_time
        throughput = self.iterations / elapsed if elapsed > 0 else 0.0

        # Tally divergence categories
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for rec in self.divergences.values():
            t = rec.divergence_type.value
            s = rec.severity.value
            by_type[t] = by_type.get(t, 0) + 1
            by_severity[s] = by_severity.get(s, 0) + 1

        return {
            "iterations_executed": self.iterations,
            "elapsed_seconds": round(elapsed, 3),
            "throughput_execs_per_sec": round(throughput, 1),
            "unique_divergences_discovered": len(self.divergences),
            "divergence_breakdown_by_type": by_type,
            "divergence_breakdown_by_severity": by_severity,
            "sample_divergences": [
                {
                    "id": d.divergence_id,
                    "type": d.divergence_type.value,
                    "severity": d.severity.value,
                    "description": d.description,
                    "hex_preview": d.raw_payload_hex[:64] + ("..." if len(d.raw_payload_hex) > 64 else ""),
                }
                for d in list(self.divergences.values())[:5]
            ],
        }

    def save_divergences_to_disk(self, output_dir: str, max_samples: int = 25):
        os.makedirs(output_dir, exist_ok=True)
        for i, (d_id, rec) in enumerate(list(self.divergences.items())[:max_samples]):
            path = os.path.join(output_dir, f"divergence_{d_id}.bin")
            with open(path, "wb") as f:
                f.write(bytes.fromhex(rec.raw_payload_hex))
