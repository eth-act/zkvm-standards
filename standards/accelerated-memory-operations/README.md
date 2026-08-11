# Accelerated Memory Operations

This proposal standardizes how zkVMs provide optimized implementations of the standard C memory functions to guest programs. Unlike the [cryptographic accelerators](../c-interface-accelerators/README.md), these operations already have stable, ubiquitous C signatures and are emitted implicitly by compilers, so this standard does not define a new API. Instead it specifies the symbol contract, the exact semantics an implementation must preserve, and the linking rules required for an accelerated implementation to actually take effect.

## Motivation

Bulk memory operations are among the most frequently executed routines in real guest programs. Compilers emit calls to `memcpy`/`memmove`/`memset` not only for explicit `<string.h>` calls but implicitly for struct moves, slice copies, container growth (`Vec`, `std::vector`), zero-initialization, and serialization. In the Ethereum state-transition workload these routines are hot.

In a zkVM, a naive byte- or word-at-a-time copy costs one load plus one store per element, and each memory access contributes to the memory-consistency argument. A zkVM can often prove a bulk copy far more cheaply — either with a tuned word-at-a-time software routine or, in some designs, a dedicated circuit (a DMA-style precompile). Today this is handled inconsistently:

* Some zkVMs provide a circuit-level accelerator for these operations.
* Some provide only a tuned software implementation that overrides the libc symbol.
* Some provide nothing and rely on default compiler codegen.
* Guest authors, lacking a guarantee from the vendor, sometimes ship their **own** hand-tuned `memcpy` — duplicating effort that the vendor or another guest has already done.

Because these symbols are emitted implicitly, an accelerated implementation that resolves the standard symbol benefits all guest code with no source changes and no `#ifdef`s. This is a portability and performance win unavailable to the explicit cryptographic accelerators, and it is the reason this case deserves its own standard.

## Goals

* Define the set of memory-operation symbols a zkVM may accelerate.
* Mandate exact C semantics so that accelerated and non-accelerated builds are behaviorally identical, preserving source portability across vendors.
* Specify the linking and symbol-resolution rules required for the implementation to take effect deterministically.
* Keep acceleration optional, so the standard does not conflict with the [minimal RISC-V target](../riscv-target/target.md) or force a particular architecture.

## Non-Goals

* Defining new function names or a new C API. The API is `<string.h>`.
* Prescribing the invocation mechanism (syscall, custom CSR, custom instruction, or pure RISC-V). As with cryptographic precompiles, the mechanism is an implementation detail hidden behind the symbol.
* Accelerating copies from special memory regions (e.g. the input region). Accessing the input region is governed by the [IO interface](../io-interface/README.md), not this standard.

## Specification

### Scope of symbols

This standard concerns the following standard C symbols:

* `void *memcpy(void *dest, const void *src, size_t n)`
* `void *memmove(void *dest, const void *src, size_t n)`
* `void *memset(void *dest, int c, size_t n)`
* `int   memcmp(const void *lhs, const void *rhs, size_t n)`

When provided, these are exported from the vendor static library defined by the [Static Library and Linker Script](../static-library-and-linker-script/README.md) standard — the same library the guest already links against — under their standard, unmangled C names. No new library or function names are introduced, so both explicit calls and the calls compilers emit implicitly are covered with no guest source changes.

### Acceleration is optional

Acceleration is an optimization, not a requirement, and exporting these symbols is how a vendor opts in. A zkVM may accelerate with a dedicated circuit (a DMA-style precompile), with a tuned software routine, or not at all — mandating a precompile would conflict with the minimal-ISA goal of the [RISC-V target](../riscv-target/target.md) standard.

* If the vendor library exports these symbols, the implementations must obey [Semantics](#semantics) and must be linked so they take effect (see [Linking and symbol resolution](#linking-and-symbol-resolution)).
* If it does not, the guest falls back to the toolchain's default implementations (for Rust, the weak `compiler-builtins` definitions): correct but unaccelerated. The build must still link successfully.

### Semantics

Whether or not an operation is accelerated, the implementation must be behaviorally identical to the canonical C library function for every input, including all alignments and `n == 0`:

* `memcpy` — copies `n` bytes from `src` to `dest`; behavior is undefined if the regions overlap; returns `dest`.
* `memmove` — copies `n` bytes from `src` to `dest` as if through a temporary buffer; must be correct for overlapping regions in both directions; returns `dest`.
* `memset` — fills `n` bytes of `dest` with the byte `(unsigned char)c`; returns `dest`.
* `memcmp` — compares the first `n` bytes as `unsigned char`; returns a value less than, equal to, or greater than zero, stopping at the first differing byte; the sign must follow the C standard.

### Alignment

An implementation must not assume any particular alignment of `dest`, `src`, or `n`. The standard C functions accept operands of arbitrary alignment, and so must their replacements.

The [RISC-V target](../riscv-target/target.md) `Zicclsm` clause requires every zkVM to handle misaligned loads and stores transparently in hardware. A memory-operation implementation may therefore rely on misaligned loads and stores freely. Whether it should is a vendor-specific trade-off: on some zkVMs a misaligned access is more expensive to prove than an aligned one, so a software implementation may instead split a copy into a misaligned head, an aligned word-at-a-time body, and a misaligned tail; on others, where a misaligned access costs the same as an aligned one, the simpler unaligned code path may be cheaper overall. The standard does not prescribe which strategy to use — only that the result is correct for any alignment.

### Linking and symbol resolution

When a vendor does export these symbols, merely *defining* them in the static library is not sufficient for them to take effect. On a `no_std`/bare-metal target there is typically already a *weak* definition of these symbols in the toolchain runtime (for Rust, `compiler-builtins` provides `memcpy`/`memmove`/`memset`/`memcmp` with weak linkage so they can be overridden). Because of how linkers extract members from static archives, a strong vendor definition placed in a separate archive can be silently ignored:

* A static archive (`.a`) member is extracted only to satisfy a currently *undefined* symbol.
* A *weak* definition satisfies the reference. Once the symbol is defined — even weakly — the linker has no reason to extract a strong definition of the same symbol from a *later* archive.
* The result is a silent fallback to the weak (unaccelerated) routine, with no duplicate-symbol diagnostic, because the strong definition was never extracted.

Consequently, this resolution is order-dependent and must not be left to chance. A conforming zkVM that exports these symbols must guarantee they win symbol resolution in the guest's final link, by using at least one of the following mechanisms, and must document which it relies on:

1. **Always-linked runtime.** Provide the symbols as strong definitions inside the runtime/entrypoint object that every guest links unconditionally (not an optional side library), so they are in the link graph from the start and override the weak runtime definitions.
2. **Whole-archive inclusion.** Have the guest link the vendor library with `--whole-archive` (paired with `--gc-sections` to discard unused members), forcing the strong definitions to be present regardless of archive order.

Both mechanisms work even though the vendor runtime library and the application library may be built by different teams with different toolchains: neither depends on the application's sysroot or on controlling the weak definitions it carries. Mechanism (1) is the cleanest, as it needs no special flags in the guest's link command; mechanism (2) also works but retains all members of the vendor library. Relying on link order alone is not conforming.

A note on whole-program optimization: if the guest and the memory-operation implementation are compiled in a single LTO unit, the optimizer may inline or specialize these calls. This does not relax the requirements above — when a call to the symbol survives optimization, it must resolve to a conforming implementation.

### Observability

Observability is recommended, not required — a vendor is under no obligation to provide these statistics. Mirroring the `Zicclsm` observability guidance in the [RISC-V target](../riscv-target/target.md) standard, a zkVM that accelerates memory operations is encouraged to expose how much proving work is attributable to them — at minimum a count of accelerated operations or the cycles/rows they consumed, and ideally a split between aligned (fast-path) and misaligned operations. This lets guest authors confirm the accelerator is engaged and identify copies.

## Rationale

`memcpy` and its siblings are standard C, are emitted implicitly by compilers, and dominate real workloads. Three points follow:

* **Symbol contract, not a new API.** Adding these to a header would duplicate `<string.h>` and capture only *explicit* calls, missing the bulk of compiler-generated copies. Standardizing the symbol captures both, with zero guest source changes.
* **Semantics are mandatory.** Acceleration may be swapped in transparently, so portability depends on the replacement being bit-identical to the naive routine for every input and alignment.
* **Linking must be specified.** The [Static Library and Linker Script](../static-library-and-linker-script/README.md) standard ensures the symbol *can* be provided, but the weak-symbol archive-extraction behavior means a correctly-defined accelerator can still be silently dropped. Pinning down the link mechanism is what makes acceleration reliable and the standard testable.
