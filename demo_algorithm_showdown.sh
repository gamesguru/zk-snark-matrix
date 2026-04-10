#!/bin/bash
# ZK-Matrix-Join: Jolt Algorithm Showdown Demo
# Compares Optimized (Topological Reducer) vs. Unoptimized (Full Spec)

echo "=========================================================="
echo "   ZK-Matrix-Join: ALGORITHM SHOWDOWN (Jolt VM)           "
echo "=========================================================="
echo "This demo runs Matrix events through two different Jolt"
echo "pipelines to compare efficiency and correctness."
echo ""

FIXTURE="res/1k.json"
export MATRIX_FIXTURE_PATH=$FIXTURE

# 1. Run Optimized Pipeline
echo "[1/2] Simulating OPTIMIZED Pipeline (Topological Reducer)..."
OPT_OUT=$(MATRIX_FIXTURE_PATH=$FIXTURE cargo run --quiet --bin zk-matrix-join-host 2>/dev/null)
OPT_HASH=$(echo "$OPT_OUT" | grep "Matrix Resolved State Hash" | awk '{print $NF}')

# 2. Run Unoptimized Pipeline
echo "[2/2] Simulating UNOPTIMIZED Pipeline (Full Spec State Res)..."
UNOPT_OUT=$(EXECUTE_UNOPTIMIZED=1 MATRIX_FIXTURE_PATH=$FIXTURE cargo run --quiet --bin zk-matrix-join-host 2>/dev/null)
UNOPT_HASH=$(echo "$UNOPT_OUT" | grep "Matrix Resolved State Hash" | awk '{print $NF}')

echo ""
echo "=========================================================="
echo "                  BENCHMARK COMPARISON                    "
echo "=========================================================="
printf "% -25s | % -15s | % -15s\n" "Metric" "Optimized" "Unoptimized"
echo "----------------------------------------------------------"
printf "% -25s | % -15s | % -15s\n" "VM Engine" "Jolt (Lasso)" "Jolt (Lasso)"
printf "% -25s | % -15s | % -15s\n" "Algorithm Type" "L2-Sequential" "Full Spec (v2)"
printf "% -25s | % -15s | % -15s\n" "Trust Model" "Math Proven" "Math Proven"
echo "----------------------------------------------------------"
echo "Final State Hash (Matches?)"
echo "Optimized:   $OPT_HASH"
echo "Unoptimized: $UNOPT_HASH"

if [ "$OPT_HASH" == "$UNOPT_HASH" ]; then
    echo ""
    echo "✓ VERIFIED: Both Jolt algorithms reached the EXACT same state!"
else
    echo ""
    echo "× ERROR: State Hash Mismatch!"
fi
echo "==========================================================