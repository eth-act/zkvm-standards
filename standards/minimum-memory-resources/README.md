# Minimum Memory Resources

This proposal establishes minimum memory resource requirements for zkVM implementations. It specifies floor values for stack and heap size that every conforming zkVM must provide.

## Motivation

The Memory Layout Restrictions standard correctly grants vendors ownership of their linker scripts and memory layouts. However, this creates a gap: without a floor on available memory, guest authors have no stable target to write against.

By mandating minimum stack and heap sizes, the standard ensures that a guest program that fits within those bounds will run on any conforming zkVM.

## Specification

Vendors may provide more than the minimum for either resource. Guest programs that rely on more than the mandated minimums are not guaranteed to be portable across all conforming implementations.

### Stack

Every conforming zkVM must provide a stack of at least **X MB**.

### Heap

Every conforming zkVM must provide a heap of at least **Y MB**.


### Linker Script Requirements

Vendors must reflect these minimum sizes in their linker scripts. The stack and heap regions defined in the linker script must be at least as large as the values mandated by this standard.

## Rationale

### Values must come from measurement

The values X and Y cannot be chosen arbitrarily. They must be grounded in profiling of the most demanding guest programs under realistic mainnet conditions. The benchmark methodology and results are expected to accompany this standard as an appendix once profiling is complete. Until those numbers are established, this document serves as a draft.

## Open Questions

* What is the peak stack usage of the most demanding guest program under a large mainnet block?
* What is the peak heap usage of the most demanding guest program under a large mainnet block?

## Appendix: Benchmark Results

*To be completed*
