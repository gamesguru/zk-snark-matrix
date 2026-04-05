#!/usr/local/bin/WolframKernel -script
(* ZK-Matrix Join Benchmark: Empirical Data Plotting *)

dataNaive = {{1000, 71437296}, {5000, 450271496}, {10000, 893025827}};
dataOptimized = {{1000, 2145908}, {5000, 10657944}, {10000, 21299845}};

(* Best-fit complexity curves - Using Log2 to reflect binary search/tree scaling *)
fitNaive = NonlinearModelFit[dataNaive, a * n * Log[2, n], {a}, n];
fitOptimized = LinearModelFit[dataOptimized, n, n];

plot = Plot[
  {fitNaive[n], fitOptimized[n]},
  {n, 0, 11000},
  PlotRange -> {{0, 11000}, {0, 10^9}},
  Frame -> True,
  FrameLabel -> {"Matrix Events (DAG size)", "RISC-V CPU (Prover Cycles)"},
  PlotLabel -> Style["ZK-Matrix Join: Scaling Performance (Empirical Results)", Bold, 16],
  GridLines -> Automatic,
  ImageSize -> 800,
  PlotLegends -> {
    "Naive Algebraic Intermediate Representation\n(Industry Standard Ruma)", 
    "Optimized Constraint Model\n(Topological Coprocessor)"
  },
  Epilog -> {
    (* Only showing the real empirical data points *)
    {ColorData[97, 1], PointSize[0.015], Point[dataNaive]},
    {ColorData[97, 2], PointSize[0.015], Point[dataOptimized]},
    Inset[
      Framed[
        Column[{
          Style["Speedup at 10k: 41.9x", Bold],
          Style["Naive Model: O(n \!\(\*SubscriptBox[\(log\), \(2\)]\) n)"],
          Style["Optimized Model: O(n)"]
        }],
        Background -> White, RoundingRadius -> 5
      ],
      {3000, 7*10^8}
    ]
  }
];

Export["../res/benchmark_visualization.png", plot];
Print["Yeah, visualization exported to ../res/benchmark_visualization.png"];

