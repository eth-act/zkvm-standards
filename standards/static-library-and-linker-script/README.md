# Static Library and Linker Script

This standard defines what a zkVM vendor must provide so that guest programs can be compiled with a generic compiler and linked against a single vendor-supplied static library.

## Motivation

Guest programs targeting zkVMs are currently written in Rust and compiled with a custom, vendor-patched toolchain. A vendor-patched toolchain is expensive to maintain, increases the attack surface of the proving system, and creates a high barrier for application developers.

The goal of this standard is to allow guest programs to be written in any language with a compiler that can target the RV64IM ISA defined in the [RISC-V Target Standard](../riscv-target/target.md) — such as C, C++, Rust, Zig, Go, or C# — and compiled with a generic, unmodified compiler. The resulting object files are then linked against a single vendor-supplied static library which provides all zkVM-specific functionality: machine initialization, IO, and cryptographic accelerators. The application developer does not need to know or care about the internal details of the zkVM; those are fully encapsulated in the library.

This standard specifies what that library must contain and what the accompanying linker script must provide.

## Specification

### Static Library

Each zkVM vendor must provide a static library (`.a` archive) targeting their zkVM. The library must include implementations of:

1. The `_start` function — the machine entry point (see [Entry Point and Initialization](#entry-point-and-initialization)).
2. All functions defined in the [IO Interface Standard](../io-interface/README.md): `read_input` and `write_output`.
3. All functions defined in the [Cryptographic Accelerators C Interface Standard](../c-interface-accelerators/README.md).
4. Any additional interface functions required by future standards in this series.

The library filename is not standardized.

### Entry Point and Initialization

The linker script must set the ELF entry point to `_start`. `_start` is the first code executed by the zkVM.

`_start` must perform all machine initialization required before C code can execute. On RISC-V this typically includes, but is not limited to:

- Initializing the stack pointer.
- Initializing the global pointer (`gp` register) for relaxation-based global data access.
- Zeroing the BSS segment (see [BSS Zeroing](#bss-zeroing)).
- Performing any IO interface initialization required by the vendor implementation so that `read_input` and `write_output` are usable when `main` is entered.

The exact set of initialization steps is vendor-defined. Only the observable post-conditions (zeroed BSS, usable IO interface, valid stack and `gp`) are mandated.

After initialization, `_start` must call `main` and pass its return value to the zkVM termination mechanism. The termination mechanism is vendor-specific; `_start` does not return to a caller.

### `main` Contract

`_start` calls `main` using the standard C calling convention. The `main` symbol must be provided by the application and must have the following C signature:

```c
int main(void);
```

zkVMs do not provide command-line arguments. The `argc`/`argv` form of `main` is not required and must not be assumed by the runtime.

The return value of `main` determines termination behavior in accordance with the [Termination Semantics Standard](../standard-termination-semantics/README.md):

- `0` — successful termination.
- Non-zero — abnormal termination; the value is used as the error code.

`main` is the application entry point. All application code runs within `main` or functions called from it.

### BSS Zeroing

The C standard requires that objects with static storage duration and no explicit initializer be zero-initialized before program startup. The observable requirement is that the BSS segment contains only zero bytes when `main` is entered. A conforming implementation may achieve this in one of two ways:

1. **Hardware zeroing**: The zkVM initializes the BSS region to zero before execution begins, for example by reading the ELF and zeroing that segment directly.
2. **Software zeroing**: `_start` explicitly zeros the BSS segment before calling `main`.

### Linker Script

The vendor must supply a linker script alongside the static library. The linker script must be compatible with both GNU ld and LLD (LLVM), the two linkers in common use for RISC-V ELF targets. The linker script must:

- Set the ELF entry point to `_start`.
- Define the following two symbols, which applications may use to implement a custom heap allocator:

| Symbol | Description |
|---|---|
| `_heap_start` | Address of the first byte of the heap region |
| `_heap_end` | Address one past the last byte of the heap region |

All other symbols exported by the linker script (BSS boundaries, stack boundaries, etc.) are vendor-internal. Their names are not standardized because they are consumed exclusively by `_start`, which is provided by the vendor.

## Rationale

### Only heap symbols are standardized

BSS boundaries, stack top, and global pointer anchor are all consumed solely by `_start`, which the vendor writes. There is no need to standardize their names across vendors. The heap boundary symbols are different: they are consumed by application code (a custom allocator), so they must have agreed-upon names.

### `int main(void)` rather than `int main(int argc, char *argv[])`

Both forms are valid C. The `argc`/`argv` form exists to receive command-line arguments from the host OS, a concept that does not apply to zkVMs. Mandating `int main(void)` avoids the question of how `_start` would construct `argc`/`argv`, keeps the runtime simpler, and makes the constraint explicit.

### C++ support is out of scope

Supporting C++ requires invoking static constructors before `main` (via `.init_array` / `.ctors`) and optionally static destructors after it (via `.fini_array` / `.dtors`). This is separable from the core initialization defined here and is deferred to a future standard. Vendors may support C++ as an extension, but guest programs requiring C++ must not assume cross-vendor portability until that standard exists.
