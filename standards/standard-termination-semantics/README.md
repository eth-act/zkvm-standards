# Execution Termination Semantics

This proposal standardizes execution termination semantics for zero-knowledge virtual machines. The specification establishes common behavior for successful termination and abnormal termination routines such as `abort()` in C/C++, panics in Rust, and runtime faults in Go, enabling consistent proof generation behavior, improved developer experience, and stronger correctness and security guarantees.

All languages targeting zkVMs must use this termination mechanism for:

* Uncaught exceptions
* Assertion failures
* Runtime errors
* Explicit termination requests

## Motivation

Current zkVM implementations lack a standardized method for terminating execution and reporting success or failure status. This creates several issues:

* **No distinction between success and failure**
  Programs that panic or abort cannot reliably signal failure state to the zkVM.

* **Language interoperability**
  Different languages (Rust panics, C `abort()`, Go runtime panics) require a common termination semantics.

* **Proof system integrity**
  Failed executions should not produce valid proofs, but without standard semantics this behavior is undefined or inconsistent. Malicious or buggy programs must not be able to disguise abnormal termination as successful execution.

* **Developer experience**
  Inconsistent termination behavior across zkVMs hinders portability and debugging. Developers require explicit and machine-readable failure signals.

All high-level language mechanisms for abnormal termination should map to the standardized termination interface defined in this proposal.

## Specification

### Successful Termination

When a program terminates successfully:

* The zkVM execution must halt.
* The execution trace must be considered complete and valid.
* A valid proof may be generated for the execution.
* The zkVM must report successful completion to the host environment.

Successful termination indicates that all program invariants were preserved and execution reached an intended completion state.

### Failed Termination

When a program terminates due to abnormal conditions:

* The zkVM execution must halt.
* The zkVM must report execution failure with the provided error code to the host environment.
* The execution trace must either be unprovable (proof generation fails or is skipped) or the verification of the proof must fail.

Failed termination indicates that the program did not reach a valid completion state and must not be treated as a successful computation by the verifier.

### Mapping Language-Level Failures

Language runtimes and standard libraries must map abnormal termination mechanisms to this standardized interface, including but not limited to:

* Rust:
  * `panic!()` without recovery
  * Panic handlers when unwinding is disabled
* C/C++:
  * `abort()`
  * Failed `assert()`
* Go:
  * Nil pointer dereferences
  * Runtime fatal errors

This mapping must preserve failure semantics and ensure zkVM-level termination is triggered.

## Reference Implementation Mechanism for RISCV

This specification proposes implementing termination using a reserved ECALL interface. zkVMs may implement termination signaling differently.

Termination is performed by invoking an ECALL with a standardized call number and passing an exit code indicating success or failure.

zkVM vendor-specific emulators and execution engines must capture and report the exit code at the end of program execution.

Exit code semantics:

* `0` indicates successful termination.
* Any non-zero value indicates execution failure.

Non-zero exit codes may be used to differentiate between error conditions. Their interpretation may be zkVM-specific.

### ECALL ABI

**ECALL ID**: `0x00000000` (reserved for termination)

| Register | Name | Description              |
| -------- | ---- | ------------------------ |
| x17      | a7   | ECALL number (must be 0) |
| x10      | a0   | Exit code                |

Exit Code Semantics:
* `0` — Successful termination
* Non-zero — Failed termination with error code

### Example Assembly Usage

#### Successful Termination

```assembly
li a7, 0              # ECALL number for termination
li a0, 0              # Exit code: 0 = success
ecall                 # Terminate execution successfully
```

#### Failed Termination (Generic Error)

```assembly
li a7, 0              # ECALL number for termination
li a0, 1              # Exit code: 1 = generic error
ecall                 # Terminate execution with failure
```

## Security and Privacy Considerations

Exit codes are part of the public execution trace and are observable by the host environment.

A correct cryptographic proof can be generated only when the termination ECALL exit value is `0`. As a consequence, no additional failure-related information is leaked to the verifier beyond the binary success or failure outcome enforced by proof validity.
