# Static Library and Linker Script

This standard defines what a zkVM vendor must provide so that guest programs can be compiled with a generic compiler and linked against a single vendor-supplied static library.

## Motivation

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

`_start` must perform all machine initialization required before C/C++ code can execute. On RISC-V this typically includes, but is not limited to:

- Initializing the stack pointer.
- Initializing the global pointer (`gp` register) for relaxation-based global data access.
- Zeroing the BSS segment (see [BSS Zeroing](#bss-zeroing)).
- Performing any IO interface initialization required by the vendor implementation so that `read_input` and `write_output` are usable when `main` is entered.
- Invoking C++ static constructors and destructors.

The exact set of initialization steps is vendor-defined. Only the observable post-conditions are mandated.

After initialization, `_start` must call `main` and pass its return value to the zkVM termination mechanism. The termination mechanism is vendor-specific; `_start` does not return to a caller.

### `main` Contract

This contract defines an **ABI boundary** between the vendor-provided `_start` and the application. The application must provide a symbol named `main` that `_start` can call using the standard C calling convention, with the following ABI:

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

### `int main(void)` as an ABI, not a C signature

Both `int main(void)` and the `argc`/`argv` form are valid C, but command-line arguments do not apply to zkVMs, so the no-argument form is mandated: it avoids the question of how `_start` would construct `argc`/`argv` and keeps the contract explicit.

The `int main(void)` notation denotes a linkable symbol, not a requirement to write C. An integer return under the C ABI is the universal lowering that every language's termination model already collapses to (Rust's `Termination`/`ExitCode` on `std` targets, C/C++'s `int`, a Go exit status), so specifying the boundary as an ABI lets unmodified C/C++ work directly while every other language reaches it through its normal runtime adapter.

### C++ support

C++ static constructors and destructors are supported. `_start` invokes all static constructors before calling `main` and all static destructors after `main` returns. No additional vendor or application work is required to use C++ in guest programs.
