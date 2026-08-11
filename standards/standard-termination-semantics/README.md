# Execution Termination Semantics

This proposal standardizes execution termination semantics for guest programs targeting zero-knowledge virtual machines. The specification establishes common behavior for successful termination and abnormal termination routines such as `abort()` in C/C++, panics in Rust, and runtime faults in Go, enabling consistent proof verification behavior, improved developer experience, and stronger correctness and security guarantees.

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
* The verifier must implement one of the following APIs:
  * Type 1: If an execution failed, then any proof claiming to attest to that execution must fail verification, regardless of whether it was produced by an honest or a malicious prover.
  * Type 2: Verification accepts an expected exit code and can succeed only if the proof represents an execution that terminated with that exact exit code, enabling proof-of-failure use cases.

This requirement constrains the verification stage only. It is a soundness property: the system must be constructed — in practice, enforced by the circuit — such that no proof of a failed execution can verify as a successful (Type 1) or differently-coded (Type 2) outcome. It is not satisfied by relying on the prover to refuse to produce a proof for a failed execution. An adversarial prover controls its own software and may attempt to forge such a proof, and the guarantee must hold against any proof anyone presents.

An honest prover may surface a failed execution either by declining to produce a proof or, under a Type 2 verifier, by producing a proof-of-failure; that choice does not affect conformance, which depends only on whether a forged proof of a failed execution can pass verification.

Failed termination indicates that the program did not reach a valid completion state and must not be treated as a successful computation by the verifier.

### Application Entry Point Return Value

As defined in the [Static Library and Linker Script Standard](../static-library-and-linker-script/README.md), `_start` calls an application-provided entry point — the `main` symbol — and captures its return value. This is an ABI contract: the `main` entry point is called under the C calling convention and returns a C `int` exit code. When the entry point returns:

* A return value of `0` must be treated as successful termination.
* A non-zero return value must be treated as abnormal termination, with the return value used as the error code.

`_start` is responsible for mapping this return value to the appropriate zkVM termination mechanism. Only the distinction between zero and non-zero is mandated; the range of error codes a zkVM preserves is vendor-defined.

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
