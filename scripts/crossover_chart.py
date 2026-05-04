#!/usr/bin/env python3
"""
Generate a log-log crossover chart comparing Graph-Native STARK vs RISC-V zkVM
constraint counts across event-set sizes.

This produces Figure 7 for the paper: the "Kill Shot" chart showing where
the spatial architecture's O(N log N) constraint count decisively beats
the temporal zkVM's O(K * N * log(K * N)) overhead.

Usage:
    python3 scripts/crossover_chart.py
    # Output: paper/figures/crossover.pdf  (and .png)
"""

import os

import matplotlib.pyplot as plt
import numpy as np

# ── Constants ────────────────────────────────────────────────────────
# Graph-Native STARK (this paper):
#   Constraints = N * (2*ceil(log2(N)) - 1)   [Waksman routing]
#   Each routing layer has N/2 switches, each producing 2 constraints
#   (routing + switch validity). Total: N * depth constraints.

# RISC-V zkVM (Jolt/SP1 baseline):
#   The auth logic involves:
#   - Deserializing each event from JSON (~500 RISC-V instructions/event)
#   - Running state resolution (~200 instructions/comparison)
#   - Hashing (~100 cycles per hash)
#   - Each RISC-V instruction expands to K = ~200 constraints in the AIR
#   We model: constraints = K * N * log2(K * N), where K is the
#   instruction-to-constraint blowup factor.
K_ZK_VM = 200  # conservative ISA emulation overhead factor
INSTRUCTIONS_PER_EVENT = 700  # deserialize + auth + hash per event

# ── Data ─────────────────────────────────────────────────────────────

N = np.logspace(1, 6, 500)  # 10 to 1,000,000 events


# Graph-Native STARK constraints
def graph_native_constraints(n):
    depth = np.maximum(1, 2 * np.ceil(np.log2(np.maximum(n, 2))) - 1)
    return n * depth


# RISC-V zkVM constraints
def zkvm_constraints(n):
    total_instructions = INSTRUCTIONS_PER_EVENT * n
    return (
        K_ZK_VM
        * total_instructions
        * np.log2(np.maximum(K_ZK_VM * total_instructions, 2))
    )


gn = graph_native_constraints(N)
zk = zkvm_constraints(N)

# Empirical data point from benchmark
BENCH_N = 43_543
BENCH_CONSTRAINTS = 1_015_808  # from Table 1

# Crossover point
ratio = zk / gn

# ── Plot ─────────────────────────────────────────────────────────────

fig, ax = plt.subplots(1, 1, figsize=(8, 5.5))

# Style
plt.rcParams.update(
    {
        "font.family": "serif",
        "font.size": 11,
        "axes.linewidth": 0.8,
    }
)

ax.loglog(
    N, gn, "-", color="#2563EB", linewidth=2.2, label="Graph-Native STARK (this paper)"
)
ax.loglog(
    N, zk, "-", color="#DC2626", linewidth=2.2, label=f"RISC-V zkVM ($K={K_ZK_VM}$)"
)

# Empirical benchmark point
ax.plot(
    BENCH_N,
    BENCH_CONSTRAINTS,
    "D",
    color="#2563EB",
    markersize=9,
    markeredgecolor="black",
    markeredgewidth=0.8,
    zorder=5,
)
ax.annotate(
    f"  Benchmark: {BENCH_N:,} events\n  {BENCH_CONSTRAINTS:,} constraints\n  315 ms (i7-8700K)",
    xy=(BENCH_N, BENCH_CONSTRAINTS),
    xytext=(BENCH_N * 3, BENCH_CONSTRAINTS * 0.15),
    fontsize=9,
    arrowprops=dict(arrowstyle="->", color="black", lw=0.8),
    bbox=dict(
        boxstyle="round,pad=0.3", facecolor="#EFF6FF", edgecolor="#2563EB", alpha=0.9
    ),
)

# Shade the gap
ax.fill_between(N, gn, zk, alpha=0.08, color="#DC2626")

# Crossover annotation
crossover_idx = np.argmin(np.abs(gn - zk))
if gn[crossover_idx] < zk[crossover_idx]:
    # Graph-native is always better in our range — annotate the ratio at N=10^5
    idx_100k = np.argmin(np.abs(N - 1e5))
    ratio_100k = zk[idx_100k] / gn[idx_100k]
    ax.annotate(
        f"{ratio_100k:.0f}× fewer\nconstraints",
        xy=(N[idx_100k], gn[idx_100k]),
        xytext=(N[idx_100k] * 0.15, gn[idx_100k] * 8),
        fontsize=10,
        fontweight="bold",
        color="#2563EB",
        arrowprops=dict(arrowstyle="->", color="#2563EB", lw=1.2),
    )

ax.set_xlabel("Number of State Events $N$", fontsize=12)
ax.set_ylabel("Constraint Count", fontsize=12)
ax.set_title(
    "Graph-Native STARK vs. RISC-V zkVM: Constraint Scaling",
    fontsize=13,
    fontweight="bold",
    pad=12,
)
ax.legend(fontsize=10, loc="upper left", framealpha=0.9)
ax.grid(True, which="both", alpha=0.15, linewidth=0.5)
ax.set_xlim(10, 1e6)
ax.set_ylim(1e2, 1e15)

fig.tight_layout()

# Save
os.makedirs("paper/figures", exist_ok=True)
fig.savefig("paper/figures/crossover.pdf", dpi=300, bbox_inches="tight")
fig.savefig("paper/figures/crossover.png", dpi=200, bbox_inches="tight")
print("Saved: paper/figures/crossover.pdf")
print("Saved: paper/figures/crossover.png")

# Print ratio at benchmark point
bench_gn = graph_native_constraints(BENCH_N)
bench_zk = zkvm_constraints(BENCH_N)
print(f"\nAt N={BENCH_N:,}:")
print(f"  Graph-Native: {bench_gn:,.0f} constraints")
print(f"  RISC-V zkVM:  {bench_zk:,.0f} constraints")
print(f"  Ratio:        {bench_zk/bench_gn:.0f}×")
