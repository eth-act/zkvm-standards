# Proving Cost Estimation

This standard defines a **proving cost metric**: a single scalar a zkVM computes during ordinary emulation — without generating a proof — that stands in a fixed linear relationship to the wall-clock time the zkVM's prover would take on that same execution. The metric lets a guest program's authors compare variants, find hot spots, and drive down proving time by running only the emulator, whose cost is a small fraction of proving.

The metric is **zkVM-specific**: each zkVM defines its own cost unit, and the numbers produced by two different zkVMs are not comparable. Within one zkVM, the metric is a deterministic function of the program and its input, and the same number tracks proving time on any hardware the zkVM's prover runs on — CPU, many-core CPU, or GPU — through a coefficient that differs per prover and hardware. It specifies:

- **What a zkVM must expose** — one scalar, the proving cost metric, reported for an execution as an output of emulation.
- **What contract it satisfies** — proving time is approximately linear in the metric on any given prover and hardware, so lowering the metric lowers proving time. The coefficient relating the two depends on the prover and hardware; a zkVM is not required to publish it.
- **What makes the number comparable over time** — the metric carries a version; the zkVM bumps it whenever its cost model changes, so numbers are only ever compared within a single version.

It standardizes the existence, shape, and determinism of this metric; how the number is computed, its unit scale, and any per-configuration coefficients remain vendor-defined.

## Motivation

Proving is expensive — orders of magnitude slower than emulating the same program. A developer optimizing a guest for proving time cannot afford to prove after every change. Emulation, by contrast, is cheap, and a zkVM's emulator already visits every executed instruction and memory access, so it can accumulate the quantities that drive proving cost as a by-product of a normal run.

Standardizing an emulator-computed proving cost metric gives:

* **Optimization without proving.** Developers get an actionable, monotone signal — "this change makes proving cheaper" — from an emulator run alone, at a fraction of the cost of proving.
* **A stable, documented contract.** The metric's meaning, determinism, and its relationship to proving time are defined and versioned, rather than being an undocumented side effect of a particular emulator build. A recorded number stays interpretable.
* **Hardware-independent guidance.** One number guides optimization whether the target proves on a single core, many cores, or a GPU: the metric measures the work an execution forces on the prover, and each prover-and-hardware configuration relates that work to time through its own coefficient.

## Goals

- Require a conforming zkVM to expose, as an output of emulation, a single scalar proving cost metric.
- Require the metric to be a deterministic function of the program and its input.
- Require the metric to stand in a linear relationship to proving time, so that reducing it reduces proving time on any fixed prover and hardware.
- Require the metric to be versioned, so numbers are only compared within a single cost-model version.

## Non-Goals

- **Cross-vendor comparability.** The metric is defined per zkVM. This standard does not define a unit or a normalization that would make one zkVM's cost comparable to another's; a lower number on zkVM A does not imply a faster proof than a higher number on zkVM B.
- **Publishing coefficients for hardware the vendor does not run.** A zkVM is not required to characterize the metric-to-time coefficient for arbitrary hardware. Consumer CPUs alone are too numerous to enumerate; a vendor may publish coefficients for configurations it supports (for example its own GPU prover), but the standard mandates only that the metric *be* linear in proving time, not that the coefficient be published for every possible machine.
- **Absolute time prediction as the primary purpose.** The metric's first purpose is *relative* optimization on a fixed prover and hardware. Absolute wall-clock prediction is possible where a vendor characterizes a configuration, but is inherently less precise (see [Determinism, quantization, and the limits of prediction](#determinism-quantization-and-the-limits-of-prediction)).
- **Prescribing how the metric is computed.** This standard does not fix the cost model — which quantities are counted, how they are weighted, or the unit scale. It fixes only that a single metric exists, that it is deterministic, and that it is linear in proving time. A model the metric may follow is given in the [Rationale](#how-the-metric-can-be-computed).
- **Modeling prover memory.** The metric estimates proving *time*. Peak prover memory — which can determine whether an execution is provable at all — is out of scope.

## Terminology

A **conforming emulator** is the component of a zkVM that executes a loaded guest program (see [ELF Loading and Validation](../elf-loading-and-validation/README.md)) against a given input without producing a proof, and reports the proving cost metric for that execution.

The **proving cost metric** (`C`) is a single non-negative scalar, expressed in the zkVM's own **cost unit**, that the emulator reports for an execution as its estimate of the proving work that execution would require. Its numerical value is meaningful only relative to other values produced by the same zkVM under the same cost-model version.

## Specification

### The emulator exposes the proving cost metric

The single obligation this standard places on a zkVM is that its emulator, run on a loaded guest program and an input, reports the scalar **proving cost metric** `C` for that execution as an ordinary output of emulation, without producing a proof. `C` is the zkVM's estimate of the proving work the execution would require. How the emulator arrives at the number is unconstrained (a model it may follow is in the [Rationale](#how-the-metric-can-be-computed)); exposing the single scalar is the whole of what a conforming zkVM must do. Everything else in this section constrains what that number means and how it behaves.

A zkVM may additionally report a breakdown of the metric — for example the contribution of individual operation classes, or the fixed versus execution-dependent parts — and is encouraged to do so, because a breakdown supports absolute-time estimation (see [The linearity contract](#the-linearity-contract)) and cost attribution (see [Relationship to profiling](#relationship-to-profiling)). Reporting a breakdown is not required; reporting `C` is.

### The metric is a deterministic function of program and input

For a fixed zkVM and cost-model version, the reported metric is a pure function of the loaded program and its input. Two runs of the emulator on the same program and input produce identical `C`. The metric must not depend on the host machine, wall-clock timing, thread scheduling, available memory, or any other non-deterministic quantity — it is computed from the execution, not measured from a prover run.

Because the metric depends on the input, a developer optimizing for a workload evaluates the metric on representative inputs, exactly as with any input-dependent performance measurement.

### The linearity contract

A zkVM must define the metric so that it is linearly related to proving time: on any fixed prover and hardware, the wall-clock time to prove an execution is approximated by

```
time ≈ k · C + b
```

for constants `k > 0` and `b` that depend on the prover and hardware but not on the program. This is a design obligation on the metric, not a publication requirement: what a zkVM must guarantee is that such a relationship *exists* on its prover, so that the metric is fit for its purpose. It follows that, for two variants of a program proved on the same configuration, `b` cancels and `k > 0`, so proving time is a monotone increasing function of `C` — reducing the metric reduces proving time. This holds on every configuration, which is why one hardware-independent number suffices to guide optimization.

A zkVM **may** characterize `(k, b)` for configurations it supports — for example its own GPU prover — and publish them so consumers can turn the metric into an absolute wall-clock estimate. It is **not** required to do so, and in particular is not expected to characterize hardware it does not run, such as the wide range of consumer CPUs. Where a vendor does publish a coefficient, it should identify the prover configuration and hardware it applies to, the cost-model version it was fitted against, and the range of executions over which it holds.

### The metric is versioned

The cost model — whatever quantities the emulator counts and how it combines them into `C` — is chosen by the zkVM to reflect its prover, and is internal: it need not be published. What the zkVM must do is assign the cost model a **version** and report it alongside the metric. Any change that can alter the number is a new version. Versioning lets a consumer detect when two recorded metrics came from different models and must therefore not be compared; without it, a silent change to the model would invalidate historical comparisons undetectably.

### Determinism, quantization, and the limits of prediction

A zkVM should document any way in which the metric departs from a smooth linear predictor of proving time, so that consumers interpret it correctly. In particular:

- **Quantization.** Provers that operate on fixed-size segments incur cost in discrete steps: the marginal cost of one additional operation is often zero until a segment boundary is crossed, at which point cost jumps by a whole segment. Where this occurs, the emulator should surface enough detail (for example the headroom to the next boundary) that a developer is not misled into expecting a proportional payoff from a sub-boundary reduction.
- **Non-trace stages.** Proving stages that are not proportional to the execution's size — notably a final proof-compression or aggregation stage — contribute to the intercept `b` (and may scale by a different coefficient than `k`). A vendor that characterizes a configuration should document whether such stages are included.

These disclosures do not weaken the metric's contract; they define the resolution at which it holds.

## Rationale

### How the metric can be computed

The specification fixes what the metric must satisfy, not how to compute it. The following is the model existing implementations use and the one from which the linear relationship to proving time is derived.

zkVMs based on STARKs already have an internal notion of this cost. Proving work is dominated by building and committing to the execution trace — low-degree extension (FFT), Merkle hashing, and constraint evaluation — all of which scale with the total trace **area** (rows × columns) the execution forces across the prover's sub-machines. That area is a deterministic property of the execution: the number of executed steps, the number of operations of each class the prover accounts for separately, and the number of memory operations of each kind. Writing these execution counts as `x = (x₁, …, xₙ)`, and assigning each a fixed weight `wᵢ` equal to the proving work one unit of that resource contributes — for a STARK prover, the trace area it occupies — the metric is

```
C = base + Σ wᵢ · xᵢ
```

where `base` is the fixed cost the prover pays regardless of the execution (for example committing to fixed ROM and lookup tables). The emulator accumulates the counts `x` as it runs and evaluates this sum: it is a weighted trace-area total, computable without proving, and proportional to the dominant term of proving work. Existing implementations already compute such a number — ZisK, for example, exposes it through its `-X`/`-S` emulator flags.

For the weighted sum to track proving cost as closely across the prover's hardware as it does on the machine it was tuned on, each weight should reflect the *full* per-unit proving cost of its resource — trace commitment, constraint evaluation, and any lookup or permutation argument the resource drives — not merely a raw cell count (see [Why a single cost model holds across hardware](#why-a-single-cost-model-holds-across-hardware)).

This model also explains two properties the rest of the rationale relies on. The sum is **additive over execution** — the cost of a region of execution is the sum of the costs of its parts — which is what lets an emulator attribute cost to functions or code regions (see [Relationship to profiling](#relationship-to-profiling)). And its execution-dependent part `Σ wᵢ·xᵢ` is **proportional through the origin**: doubling a workload's counts doubles it, which is what makes the relationship to proving time linear.

### Why the metric is a measure of work, not time

Time is work divided by throughput, and throughput is a property of the prover and hardware, not of the program. By defining the metric as work — a hardware-independent function of the execution — the same number is meaningful on every configuration, and each configuration contributes only a coefficient. This is what lets one emulator run guide optimization for CPU and GPU targets alike. It is also why the metric is deterministic: it is computed, not measured. And it is why the standard requires only that the metric *be* linear in proving time, while leaving the coefficient that converts it to seconds to whichever configurations a vendor chooses to characterize.

### Why the fixed cost is a separate term in the model

In the model above, the fixed `base` is held out of the weighted sum rather than folded into a weight, because it behaves differently from the execution-dependent part under two transformations that matter:

- **Optimization.** The fixed cost is constant across variants of a program, so it cancels in any comparison. For short executions, where it dominates the total, keeping it distinct prevents the misreading that optimization is ineffective when in fact the execution is simply below the size where trace cost matters.
- **Hardware scaling.** The execution-dependent (trace-commitment) cost and the fixed (setup, aggregation) cost need not scale by the same factor across hardware — a GPU can accelerate one far more than the other. A consumer fitting `time ≈ k · C + b` absorbs the fixed part into the intercept `b`, which is why the relationship is affine rather than a pure proportion, and why a vendor characterizing a configuration fits an intercept rather than a single scale.

### Why a single cost model holds across hardware

A single fixed set of weights risks being reweighted by different hardware — making the metric's *shape*, not just its scale, hardware-dependent, so that no single coefficient `k` fits. In practice the shape is largely hardware-invariant, because the weights measure trace-commitment cost and a committed trace cell costs essentially the same regardless of which sub-machine it belongs to: the commitment pipeline is the same field, blowup, and hash for every sub-machine. The relative proportions of the cost are thus a property of the *proof system* — its fixed sub-machine layouts, field, hash, and blowup — which travels with the zkVM, while hardware changes throughput. To first order the true per-resource cost on hardware `H` is `w_H ≈ k·w`, which is precisely the condition under which one metric and one coefficient suffice. Choosing weights that reflect full per-unit proving cost (not raw cell count) makes the approximation tighter.

### Why the metric is deliberately not portable

Making one zkVM's cost comparable to another's would require collapsing away exactly the information that makes the metric useful — each prover's own sub-machine layout and cost structure — into a common unit that no prover actually has. The value here is a faithful, prover-specific optimization signal, and that is inherently per-zkVM. A developer choosing between zkVMs compares measured proving times directly; the metric is for driving down proving time on a chosen zkVM, not for selecting one.

### Relationship to profiling

The additivity of the metric is what makes cost attribution possible: because the cost of an execution is the sum of the costs of its parts, an emulator that also reads the program's symbols (as ZisK does under `-S`) can attribute cost to functions or regions of interest and rank them, pointing a developer at the code responsible for the most proving cost. This standard defines the scalar; the attribution of that scalar to source-level regions is a natural and encouraged extension, but is not mandated here.
