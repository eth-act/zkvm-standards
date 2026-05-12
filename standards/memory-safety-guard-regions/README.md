
# Memory Safety Guard Regions

This proposal standardizes memory safety guard regions for guest programs targeting zero-knowledge virtual machines. It specifies a null pointer trap region and a stack guard region as mandatory zkVM features, providing a baseline of memory safety and a well-defined interaction with the execution termination semantics standard.

## Motivation

Memory safety violations — particularly null pointer dereferences and stack overflows — are among the most common classes of bug in systems software. Without hardware or OS support, zkVMs currently provide no reliable mechanism to detect them. This creates several issues:

* **Silent corruption**
  A null pointer dereference or stack overflow may corrupt memory rather than triggering abnormal termination, producing a proof of a silently incorrect computation.

* **Inconsistent behavior across zkVMs**
  Without a standard, the same guest program may crash on one zkVM, silently misbehave on another, and produce a valid proof on a third.

* **Security exposure**
  Malicious or buggy guest programs may exploit the absence of guard regions to manipulate execution state.

## Specification

### Null Pointer Trap Region

The first 4 kB of the guest address space (addresses `0x0000` through `0x0FFF`) must be reserved as a trap region. Any read or write access to this region must trigger abnormal termination, as defined in the Execution Termination Semantics standard.

The region must not be mapped to readable or writable memory. It must not be used by the zkVM runtime, linker scripts, or any other system component.

This protects against null pointer dereferences for all pointer types whose null representation is the zero address, which is the case for all C, C++, Rust, and Go targets.

### Stack Guard Region

A guard region of at least 4 kB must be placed immediately below the bottom of the stack. Any read or write access to this region must trigger abnormal termination, as defined in the Execution Termination Semantics standard.

The guard region must be contiguous and adjacent to the bottom of the stack with no gap between them. It must not be mapped to readable or writable memory.

This catches the common case of stack overflow, where the stack pointer decrements past the bottom of the stack into adjacent memory.

### Interaction with Termination Semantics

Access to either guard region constitutes an abnormal termination condition. The observable behavior is identical to any other abnormal termination: execution halts, failure is reported to the host, and no valid proof of successful execution may be generated.

## Limitations

### Stack Clash

A stack guard region of 4 kB does not protect against stack clash. Stack clash occurs when a single stack frame allocates a local buffer large enough to skip over the entire guard region in one decrement of the stack pointer — for example, `char buf[8192]` in C. In this case, the stack pointer jumps past the guard without touching it, and the overflow goes undetected.

Linux mitigates this by reserving a gap of at least 1 MB below the stack, making it infeasible for a single frame to skip over it entirely. zkVMs may adopt a larger guard region as a vendor extension, but this standard does not require it.

The compiler-level fix is stack probes: the compiler emits a read to each page of a large frame before use, ensuring the guard region is touched on overflow. GCC 15 introduced `-fstack-clash-protection` for RISC-V. At the time of writing this standard, Clang does not support this flag for RISC-V targets.

This standard does not mandate stack probe compilation, because compiler flags are a property of guest toolchains and cannot be enforced by a standard governing zkVM vendors. However, guest program authors should be aware that the stack guard region does not protect against stack clash, and should consider enabling `-fstack-clash-protection` when using a compiler that supports it.

## Rationale

### Precedent

Null pointer protection and stack guard pages are universally used in mainstream operating systems and embedded RTOSes.

### Implementation Cost

For zkVMs that manage their own address space, implementing these protections requires marking two fixed regions as non-accessible. While the conceptual change is straightforward, the actual implementation cost will vary depending on a vendor's proof system architecture.

### Relationship to the Memory Layout Standard

The null pointer trap region and the stack guard region are compatible with the Memory Layout Restrictions standard, which permits vendors to define their own memory layouts. Vendors retain full flexibility over the rest of the address space. The only constraint imposed by this standard is that the first 4 kB and the region immediately below the stack bottom must not be accessible.