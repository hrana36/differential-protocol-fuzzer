"""
Interactive Demonstration of Differential Protocol Fuzzing
Demonstrates live byte mutations on DNS packets and isolates behavioral desynchronization.
"""
import os
import sys

repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_dir not in sys.path:
    sys.path.insert(0, repo_dir)

from fuzzer.engine import DifferentialFuzzerEngine


def main():
    print("=" * 80)
    print("      DIFFERENTIAL PROTOCOL FUZZER: LIVE PARSER DESYNC EXPLORATION      ")
    print("=" * 80)

    engine = DifferentialFuzzerEngine(random_seed=1337)
    print(f"[*] Initialized corpus with {len(engine.corpus)} valid seed DNS queries.")
    print("[*] Fuzzing dual parsers (RFC 1035 Strict vs Lenient Embedded)...")

    found = 0
    target_desyncs = 3

    while found < target_desyncs:
        record = engine.fuzz_one()
        if record:
            found += 1
            print(f"\n[!] Discovered Discrepancy #{found} [ID: {record.divergence_id}]")
            print(f"    Type        : {record.divergence_type.value}")
            print(f"    Severity    : {record.severity.value}")
            print(f"    Payload Len : {record.payload_len} bytes")
            print(f"    Payload Hex : {record.raw_payload_hex[:60]}...")
            print(f"    Explanation : {record.description}")
            print(f"    Parser-Alpha (Strict)  : {record.parser_a_result}")
            print(f"    Parser-Beta  (Lenient) : {record.parser_b_result}")

    print("\n" + "=" * 80)
    print(f"[+] Successfully isolated {target_desyncs} live protocol parsing vulnerabilities in {engine.iterations} mutations.")
    print("=" * 80)


if __name__ == "__main__":
    main()
