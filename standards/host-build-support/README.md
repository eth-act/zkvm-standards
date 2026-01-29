# Host Build Support for Guest Programs

A guest program targeting a zkVM should compile on the host platform without source code modifications. This is achievable because the program targets the RV64IM instruction set. As a consequence, application code does not emit the "ecall" syscall instruction and makes no assumptions about OS ABI conventions. 

Access to I/O and accelerator functions is achieved by linking against external static libraries that provide implementations of standardized function prototypes. These prototypes abstract over I/O and accelerator operations, enabling portability between guest and host environments.

When running on the host, zkVM program input is identified with standard input (stdin) and zkVM program output is identified with standard output (stdout), allowing seamless integration with standard Unix tooling and workflows.

## Rationale

Host portability is essential for making zkVM applications testable and easing the development process. Running guest programs natively on the host provides several critical advantages:

**Development Velocity**: Developers can iterate rapidly using familiar debugging tools (gdb, lldb, valgrind) and profilers without the overhead of proof generation, which can be orders of magnitude slower than native execution.

**Bug Detection and Security Hardening**: Compilation and execution on the host can expose bugs that are difficult or impossible to detect in the bare metal zkVM environment.The ability to test with OS-level security mechanisms helps identify vulnerabilities before deployment. Host operating systems provide powerful error detection mechanisms including:
- Stack guards and canaries that detect buffer overflows
- Address sanitizers (ASan) that catch memory corruption bugs
- SIGSEGV and other signals that immediately flag invalid memory accesses
- Memory leak detectors and undefined behavior sanitizers

Host-compiled binaries (ELFs) can be analyzed with a wide range of static analysis tools, fuzzers, and verification frameworks. The significantly faster execution speed of host binaries compared to zkVM emulation makes iterative fuzzing and analysis practical, enabling more thorough security evaluation.

**Reproducibility**: Host builds enable deterministic testing and continuous integration workflows, making it easier to establish baseline correctness before generating proofs.

## Porting Process

The porting process should work for programs written in C/C++, Rust, and other languages capable of targeting bare metal systems. The build process depends on the programming language but generally follows these steps:

- Application source code remains unmodified
- Standard host toolchain is used (no cross-compilation required)
- Default linker script is used (no custom linker script specified)
- Program links against static libraries implementing the I/O and accelerator function prototypes

## Reference Implementation

The Ethereum Foundation will provide reference implementations of these external libraries for host platforms targeting Linux. These implementations serve as the canonical reference for library behavior.

## Best Practices

Guest programs should avoid conditional compilation directives to maintain true source-level portability between guest and host environments.