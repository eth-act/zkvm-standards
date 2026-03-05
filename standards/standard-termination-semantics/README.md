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
* The verification of the proof must fail - if the proof was created in the first place.

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
