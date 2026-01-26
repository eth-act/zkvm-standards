# Memory Layout Restrictions

zkVMs from different vendors should be permitted to define their own memory layouts through vendor-specific linker scripts, rather than adhering to a single standardized memory map.

A consequence of that is that:
- Linux RISCV ELFs won't be compatible with zkVMs
- an ELF produced for a zkVM from one vendor won't be compatible with a zkVM from another

Each zkVM implementation should supply its own linker script that correctly describes its memory constraints, including the location and size of critical memory regions such as heap and stack areas.

Programs should be compiled and linked specifically for each target zkVM using that vendor's linker script and C runtime library (libc). The linker script defines symbols that the libc implementation depends upon - most notably heap boundaries and other memory region demarcations. Consequently, vendors must provide not only the linker script but also a compatible libc implementation that correctly utilizes these symbols.

This approach sacrifices binary portability but gains architectural flexibility, allowing zkVM designers to optimize their memory layouts for proof generation efficiency and security. Source code portability remains achievable through standard RISCV instruction set compatibility and appropriate abstraction layers for accelerators, etc.

## Rationale
zkVMs share fundamental characteristics with embedded systems.

### Specialized execution environments
Like embedded systems, zkVMs often incorporate architectural features driven by their specialized purpose. These may include memory-mapped I/O regions, reserved BIOS areas, or cryptographically-motivated memory organization - all of which are zkVM specific.

### Analogy to chip-vendors
Just as ARM microcontrollers from different manufacturers require distinct linker scripts despite sharing the same instruction set architecture, zkVMs from different vendors will have unique memory requirements driven by their proof system implementations and architectural decisions.

### Incompatibility with Linux ELFs
zkVMs typically provide 2-4GB of addressable memory, comparable to microcontroller-class devices rather than desktop systems. This is orders of magnitude smaller than the 256GB user-space addressing available in generic Linux RISCV ELF (Sv39).

While Linux determines program entry points dynamically from ELF headers, some zkVMs assume fixed entry point addresses. This is a reasonable design choice for constrained environments but breaks compatibility with standard Linux executables.

Some zkVMs preload program input into fixed memory regions. In contrast, Linux programs retrieve input dynamically through system calls like `read`. If a Linux ELF is executed on a zkVM, the linker may have legitimately placed program sections in the same memory region where the zkVM expects preloaded input, causing conflicts.

Linux has minimal memory layout restrictions (null pointer protection, page-aligned segments with proper permissions). These requirements assume a flexibility that zkVMs cannot provide given their cryptographic and architectural constraints.
