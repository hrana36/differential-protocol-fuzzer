"""
Empirical Benchmark Evaluation of Differential Protocol Fuzzing Campaign
Executes high-throughput dual-parser differential fuzzing, isolates desyncs,
and generates publication-quality empirical telemetry.
"""
import os
import sys
import json
import time

script_dir = os.path.dirname(os.path.abspath(__file__))
repo_dir = os.path.dirname(script_dir)
if repo_dir not in sys.path:
    sys.path.insert(0, repo_dir)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from fuzzer.engine import DifferentialFuzzerEngine


def run_campaign_benchmark(iterations: int = 50000):
    print("=" * 80)
    print("      DIFFERENTIAL PROTOCOL FUZZING EMPIRICAL CAMPAIGN BENCHMARK        ")
    print("=" * 80)
    print(f"[*] Target Architecture : Dual RFC 1035 Parsers (Strict vs Lenient)")
    print(f"[*] Fuzzing Budget       : {iterations:,} testcase iterations")

    engine = DifferentialFuzzerEngine(random_seed=42)

    t0 = time.perf_counter()
    report = engine.run_campaign(max_iterations=iterations)
    elapsed = time.perf_counter() - t0

    corpus_dir = os.path.join(repo_dir, "corpus")
    engine.save_divergences_to_disk(corpus_dir)
    print(f"[+] Exported {len(engine.divergences)} divergent testcases to: {corpus_dir}")

    # Generate Visualization Plot
    plot_path = os.path.join(script_dir, "divergence_distribution.png")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), dpi=300)

    # Subplot 1: Divergence Breakdown by Type
    by_type = report["divergence_breakdown_by_type"]
    types = list(by_type.keys())
    counts = list(by_type.values())
    colors = ["#d62728", "#ff7f0e", "#1f77b4", "#2ca02c"][:len(types)]

    ax1.bar(types, counts, color=colors, edgecolor="black", alpha=0.85)
    ax1.set_title("Divergence Taxonomy Breakdown", fontsize=12, fontweight="bold")
    ax1.set_ylabel("Unique Discrepancy Signatures", fontsize=10, fontweight="bold")
    ax1.tick_params(axis="x", rotation=15, labelsize=9)
    ax1.grid(axis="y", linestyle="--", alpha=0.5)

    # Subplot 2: Severity Distribution Pie Chart
    by_sev = report["divergence_breakdown_by_severity"]
    sev_labels = list(by_sev.keys())
    sev_counts = list(by_sev.values())
    sev_colors = ["#d62728" if "CRITICAL" in s else "#ff7f0e" if "HIGH" in s else "#1f77b4" for s in sev_labels]

    ax2.pie(sev_counts, labels=sev_labels, autopct="%1.1f%%", colors=sev_colors, startangle=140,
            textprops={"fontsize": 10, "fontweight": "bold"})
    ax2.set_title("Vulnerability Severity Distribution", fontsize=12, fontweight="bold")

    plt.tight_layout()
    plt.savefig(plot_path)
    plt.close()
    print(f"[+] Generated empirical distribution visualization: {plot_path}")

    # Export report JSON
    report_path = os.path.join(script_dir, "fuzzing_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Saved structured machine-readable metrics: {report_path}")

    print("\n" + "=" * 80)
    print("                    CAMPAIGN RESULTS SUMMARY                             ")
    print("=" * 80)
    print(f" Total Executions       : {report['iterations_executed']:,}")
    print(f" Total Elapsed Time     : {report['elapsed_seconds']:.2f} seconds")
    print(f" Effective Throughput   : {report['throughput_execs_per_sec']:,.1f} execs / sec")
    print(f" Unique Desyncs Found   : {report['unique_divergences_discovered']:,}")
    print(" Breakdown by Type      :")
    for k, v in by_type.items():
        print(f"   - {k:<25}: {v:,}")
    print(" Breakdown by Severity  :")
    for k, v in by_sev.items():
        print(f"   - {k:<25}: {v:,}")
    print(" Sample Isolated Desynchronization:")
    for sample in report["sample_divergences"][:2]:
        print(f"   [{sample['severity']}] {sample['id']} - {sample['description']}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_campaign_benchmark()
