# Standardizing a RISC-V target for Ethereum

This proposal aims to standardize a RISC-V target triple for zkEVMs being used on Ethereum. We want to define the minimal target 

Proposed target:

```
riscv64im-unknown-none-elf
```

## Motivation

Different zkEVMs currently target different RISC-V triples, standardization helps to normalize benchmarks across different zkVMs with respects to the circuit being proven, focus formal verification efforts and reduce the long term complexity of auditing the circuits. 

## Goals

- Define a minimal RISC-V instruction set for zkEVMs that want to prove Ethereum blocks.


## Non-Goals

- Define a RISC-V instruction set for proving arbitrary general purpose programs
- Not support every language directly
- We are not defining a standard for other targets and the standardization of this target has no precedence on other targets. For example, one could envision WASM-WASI being a suitable target for WASM.


| **Category**                  | **Proposed Setting**      | 
| ----------------------------- | ------------------------- | 
| **ISA Base**                  | `RV64I`                   |
| **Extensions**                | `M`, `Zicclsm`            |
| **Compressed (`C`)**          | *Excluded*                |
| **Floating Point (`F`, `D`)** | *Excluded (soft-float)*   |
| **Privileged Mode**           | Machine (`M`) only        |
| **Syscalls / Environment**    | None                      |
| **ABI**                       | `LP64` (soft-float)       |
| **Object Format**             | ELF, statically linked    |
| **Endianness**                | Little-endian             |
| **Memory Model**              | Flat, no MMU, no paging   |

## Rationale

Since the execution layer's state transition function(STF) does not contain any floating point arithmetic, the minimal ISA requirements for proving the STF is RV32I. In practice, it is RV32IM because multiplications and divisions will be expensive otherwise.

We use 64-bit since many of the algorithms used in the STF can take advantage of a 64-bit word size. For example, U256 integer arithmetic and keccak256.

## `Zicclsm` extension

`Zicclsm` extension is required. It mandates that misaligned loads and stores to main memory regions must be supported. While well-functioning compilers targeting RISC-V typically generate aligned memory accesses, compiler bugs can inadvertently produce unaligned memory operations. Such bugs have been observed in practice across various compiler toolchains. Without `Zicclsm` support, programs that compile and execute correctly on hardware RISC-V implementations would trap or behave incorrectly in zkVM environments. In the context of Ethereum, this creates a critical risk: blocks containing transactions that trigger unaligned accesses due to compiler bugs would become unprovable, potentially halting block production and compromising network liveness.

By requiring `Zicclsm`, zkVMs align with the behavior of physical RISC-V hardware and standard emulators, all of which handle unaligned accesses transparently. This reduces the risk of subtle compatibility issues and ensures that zkVMs remain a reliable execution environment for the broader RISC-V software ecosystem.

zkVMs must provide visibility into the number of unaligned memory accesses that occur during proof generation. This enables developers to monitor unaligned access patterns over time and investigate specific code blocks that trigger them. At minimum, zkVMs should expose a count of unaligned accesses per proof through command-line output or log files, though more granular metrics are encouraged. This observability helps identify potential optimization opportunities and verify that unaligned accesses remain rare as expected, while ensuring the safeguard is working correctly when edge cases do occur.

## zkVM precompiles

Since zkVM precompiles are defined via a C interface, the implementation details of how a zkVM precompile is called does not need to be specified.
