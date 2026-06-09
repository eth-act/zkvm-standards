# ELF Loading and Validation

This standard defines how a zkVM loads and validates a guest program supplied as a statically linked ELF file, establishing the ELF as the authoritative description of the program's initial machine state. It specifies:

- **What defines the state** — the initial memory image and segment permissions come from the program headers (`PT_LOAD` segments), and the initial program counter from the entry point (`e_entry`).
- **What a loader validates and rejects** — the header fields (class, machine, endianness, type), the segment rules (no overlap, W^X, readability, code/data separation), and entry-point validity.
- **That loading is deterministic** — the initial state is a function of the program headers and `e_entry` alone, independent of optional or strippable content such as section headers.

It standardizes these loading semantics and validation obligations; each zkVM's memory layout — addresses and region sizes — remains vendor-defined.

## Motivation

A guest program produced for the [RISC-V target](../riscv-target/target.md) and linked with a vendor's [static library and linker script](../static-library-and-linker-script/README.md) is distributed as an ELF file. The ELF is the contract between the toolchain and the zkVM: it describes the program's code, its initial data, and its entry point.

Because the ELF format is flexible, this contract admits several reasonable interpretations, and existing implementations have naturally made different choices — for example in whether the loadable image is taken from the program headers or the section headers, how thoroughly the header fields are validated, what makes an entry point valid, and how segment permissions are treated. Converging on a single interpretation strengthens source-level portability and simplifies auditing, since the relationship between the distributed artifact and the proven computation becomes precisely defined.

## Goals

- Define the ELF as the authoritative description of the initial machine state.
- Pin the loadable image to **program headers (segments)**, matching real RISC-V hardware and standard emulators.
- Enumerate the validation checks a loader has to perform and the inputs it has to reject.
- Make the loading process deterministic and independent of optional ELF content.

## Non-Goals

- Standardizing memory addresses, sizes, or the location of heap/stack/IO regions. These are vendor-defined (see [Memory Layout Restrictions](../memory-layout-restrictions/README.md)).
- Standardizing the maximum program size, segment count, or address-space bound. A loader may impose vendor-specific limits; only the semantics of accepted programs are standardized.
- Supporting dynamic linking, position-independent executables, or relocation at load time.

## Terminology

A **conforming loader** is the component of a zkVM (host-side preprocessor, transpiler, or in-circuit boot logic) that consumes an ELF file and produces the initial machine state — the initial memory image, the effective segment protection state, and the initial program counter.

## Specification

### The ELF defines the initial machine state

The guest program is supplied as a single statically linked ELF file as described in the [RISC-V Target](../riscv-target/target.md) standard. The loader derives the initial machine state from that ELF together with the zkVM's own fixed parameters, and from no other per-program input:

- the **initial program counter** (see [Entry point](#entry-point));
- the **initial memory image**, from the file's loadable segments (see [Loadable image from program headers](#loadable-image-from-program-headers));
- the **segment protection state**, from the loadable segments' permission flags (see [Segment permissions](#segment-permissions)).

### Header validation

Before constructing any state, the loader validates the ELF header and rejects the file if any check fails (see the [RISC-V ELF psABI, ELF Object Files](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_elf_object_files) for the header field definitions):

| Field | Requirement |
|---|---|
| Magic | `e_ident[0..4]` equals `\x7fELF`. |
| Class | Matches the bit-width of the [RISC-V Target](../riscv-target/target.md) standard (`ELFCLASS64`). |
| Data encoding | `ELFDATA2LSB` (little-endian). |
| Machine | `e_machine == EM_RISCV`. |
| Type | `e_type == ET_EXEC` (statically linked executable).|

The loader must not infer endianness from, or adapt endianness to, the file; the encoding is fixed by the target standard and any deviation is an invalid input.

### Loadable image from program headers

The initial memory image is constructed exclusively from the ELF's **program headers** of type `PT_LOAD`. The loader must not use section headers (`SHT_*` / `SHF_*`) to determine what is loaded into memory. Section headers are optional ELF content and may be absent or stripped; loading is unaffected by their presence, absence, or contents. (Section headers may still be read for non-normative purposes such as profiling symbols.)

For each `PT_LOAD` segment, with file offset `p_offset`, virtual address `p_vaddr`, file size `p_filesz`, memory size `p_memsz`, and flags `p_flags`:

1. The loader places the `p_filesz` bytes at `[p_offset, p_offset + p_filesz)` in the file at virtual addresses `[p_vaddr, p_vaddr + p_filesz)`.
2. If `p_memsz > p_filesz`, the loader zero-fills the range `[p_vaddr + p_filesz, p_vaddr + p_memsz)`. This is how `.bss` and other zero-initialized regions are materialized.
3. The loader verifies that `p_vaddr` and `p_vaddr + p_memsz` lie within the zkVM's addressable space and rejects the segment otherwise.

The following constraints apply across segments:

- **Alignment.** `p_vaddr` is aligned as required by the target (at minimum 4-byte aligned for the instruction word). Misaligned segments are rejected.
- **No overlap.** Loadable segments must not overlap in virtual address space. A loader rejects overlapping `PT_LOAD` segments rather than resolving the overlap by precedence or accumulation. A normally linked ELF never contains overlapping loadable segments, so this check exists to catch malformed input and — the realistic case — collisions when a zkVM composes the guest with additional payloads (below).
- **Order independence.** Because loadable segments are disjoint, the resulting image does not depend on the order in which program headers appear in the file: a loader that processes segments in header order produces the same image as one that sorts by `p_vaddr`.

### Segment permissions

The loader derives protection state from `p_flags` and enforces the following.

**W^X.** A loadable segment must not be simultaneously writable and executable. A segment with both `PF_W` and `PF_X` set is rejected.

**An executable segment carries one of two permission combinations.** An executable segment is flagged either `PF_X` alone or `PF_X | PF_R`. The two are not interchangeable — the combination fixes whether the segment's bytes are readable as data — and which one a zkVM accepts is an inherent property of that zkVM (see [A zkVM supports exactly one combination](#a-zkvm-supports-exactly-one-combination)).

- **`PF_X` alone — execute-only.** The segment contains only instructions and no read-only data; its entire content must be decodable as a sequence of RISC-V instructions. The segment's bytes are not accessible through load instructions. A load that targets an execute-only segment causes abnormal termination (see [Termination Semantics](../standard-termination-semantics/README.md)), even when the target address holds a valid instruction.
- **`PF_X | PF_R` — execute-and-read.** The segment's bytes may be both executed and read as data through load instructions. A load that targets such a segment must return the real byte stored at that address — the same byte that executes there — even when that address holds an instruction. Read-only data may therefore share the segment with code.

A loader may support finer-grained protection (per-page protection, read-only enforcement, execute protection) consistent with these rules.

#### A zkVM supports exactly one combination

Which of the two combinations an executable segment may use is an inherent property of the zkVM: a given zkVM accepts either `PF_X` or `PF_X | PF_R`, not both, according to how it realizes executable memory. The loader validates that every executable segment's flags match the combination its zkVM accepts, and rejects the ELF otherwise; this check is part of the [validation performed before proving](#validation-before-proving).

A guest program's author must know which combination the target zkVM provides, because it determines whether read-only data is permitted to share the executable segment (see [Code and data separation](#code-and-data-separation)).

### Code and data separation

A zkVM executes only instructions that are present in an executable (`PF_X`) segment of the loaded ELF. Two consequences follow, and a portable guest has to respect both.

**Data is not executed as code.** There is no run-time code generation: a guest cannot write bytes to memory and then execute them, and cannot rely on self-modifying code or a just-in-time compiler. Together with W^X — a writable segment is never executable — this fixes the set of executable bytes at load time.

**Whether code is readable as data depends on the executable segment's flags.** As defined in [Segment permissions](#segment-permissions), a zkVM supports exactly one of two executable-segment models, and a portable guest has to be written for the one its target provides:

- On an **execute-only** (`PF_X`) zkVM, instructions are not readable as data. Every byte the program reads — read-only constants, string literals, switch/jump tables, and constant pools — must be placed in a non-executable, readable segment, and the executable segment must contain only instructions. A load that reaches into the executable segment terminates the program abnormally.
- On an **execute-and-read** (`PF_X | PF_R`) zkVM, read-only data may be interleaved with code in the executable segment; a load against it returns the real byte.

Because these differ in what a valid guest may do, the guest's authors must know which combination the target zkVM provides.

**Keeping read-only data out of the executable segment is the ELF producer's obligation.** A zkVM that requires an execute-only (`PF_X`) segment should provide a linker script that separates the two — using `PHDRS` to assign the code sections (`.text*`, `.init`, `.fini`) to the executable segment and every read-only data section (`.rodata*`, and similar) to a separate readable, non-executable segment. A linker script routes whole sections, so it only helps once the compiler has already emitted every piece of read-only data into a data section; it cannot pull out data that the backend placed inside `.text` (most importantly switch jump tables, which `-fno-jump-tables` forces back into `.rodata`). Because the placement of read-only data cannot be fully controlled through compiler options (see [Read-only data placement cannot be fully controlled](#read-only-data-placement-cannot-be-fully-controlled)), an execute-only artifact ultimately has to be confirmed by post-link inspection of the linked ELF. A zkVM may reject, and otherwise has undefined behavior on, an ELF whose execute-only segment contains data that the program reads as data.

**zkVM authors are encouraged to accept `PF_X | PF_R`.** An execute-only zkVM shifts a fragile obligation onto every guest toolchain, and — as [below](#read-only-data-placement-cannot-be-fully-controlled) — the toolchain cannot be fully relied on to keep read-only data out of the executable section. A zkVM is therefore encouraged to support the execute-and-read (`PF_X | PF_R`) combination, under which a stray jump table or constant pool left in the executable segment remains correct because loads return the real bytes. Supporting only execute-only (`PF_X`) is permitted, but then the guest's authors take on the responsibility of ensuring — and verifying, per the note above — that the linked artifact's executable segment is free of any data the program reads.

#### Read-only data placement cannot be fully controlled

No toolchain offers a switch that guarantees the executable section contains only instructions. Compilers usually place read-only data — constants, string literals, jump tables — in dedicated data sections, but this is an implementation choice rather than a contract, and in some configurations a compiler may place such data in the executable section instead. Options that suppress a particular source of in-section data narrow the problem but do not cover every case and are not documented guarantees.

The robust way to obtain an instruction-only executable segment is a post-link verifier that rejects any executable whose executable segment contains non-instruction bytes or is targeted by data relocations, optionally paired with a restricted language and flag subset — a property of a specific toolchain and coding rules, not of the compiler's documented contract.

### Entry point

The initial program counter is determined by the zkVM. A zkVM may begin execution at a fixed, documented boot address rather than reading `e_entry`; in that case the linker script places the program's entry (the vendor `_start`) at that address. Whichever model a zkVM uses, the loader validates `e_entry` and rejects the ELF if any check fails:

- `e_entry` is aligned to the instruction word (4 bytes).
- `e_entry` lies within the zkVM's addressable space and falls within a loaded executable (`PF_X`) segment.
- If the zkVM begins execution at a fixed boot address, `e_entry` equals that address.

The purpose of validating `e_entry` is not to discover where execution starts — the zkVM may already know that — but to catch a guest whose declared entry disagrees with what the zkVM will actually execute, before any proof is generated.

### Initial memory state

The loader materializes the complete initial memory image during image construction (see [Loadable image from program headers](#loadable-image-from-program-headers)). When control reaches the entry point, memory is already in its initial state:

- every byte initialized from segment file data (`p_filesz`) holds that data at its virtual address;
- every zero-initialized byte (the `p_memsz > p_filesz` tail, conventionally `.bss`) holds zero; and
- read-only data is present and readable at its virtual address.

A guest program is not required to zero `.bss`, initialize `.data`, copy initialized data from a separate load address, or load `.rodata` before using it. Because the loader establishes this state before the first instruction executes, software re-initialization of memory in `_start` is unnecessary; a vendor runtime may still perform unrelated setup (configuring `gp`/`sp`, preparing the IO interface) as described in the [Static Library and Linker Script](../static-library-and-linker-script/README.md) standard.

The loadable image places each segment directly at its virtual address: the load address equals the virtual address (`VMA == LMA`). A loader does not require, and a portable guest does not rely on, a run-time relocation that copies initialized data from a distinct load address into its virtual address (the bare-metal "copy `.data` from flash to RAM" step). No relocation is performed at load time (see [Non-Goals](#non-goals)).

A loader that materializes zeros during image construction must not, in doing so, overwrite any byte that was initialized from `p_filesz` file data.

### Validation before proving

The loader performs the validation in [Header validation](#header-validation), [Loadable image from program headers](#loadable-image-from-program-headers), [Segment permissions](#segment-permissions), and [Entry point](#entry-point) such that an invalid ELF is rejected with a diagnostic and no partial or speculative machine state is presented to the prover. ([Code and data separation](#code-and-data-separation) is primarily an obligation on the ELF producer; a zkVM that detects a violation rejects the ELF on the same terms, but a loader is not required to prove its absence.)

## Rationale

### `e_flags` is not validated

The RISC-V-specific `e_flags` field (RVC, float ABI, RVE, and similar bits; see the [RISC-V ELF psABI, ELF Object Files](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_elf_object_files)) is intentionally left unchecked. Unlike class, endianness, machine, and type — which are fixed for every conforming zkVM — `e_flags` records an ISA/ABI variant, and the [RISC-V target](../riscv-target/target.md) is a minimum a zkVM may exceed: a zkVM that implements the C extension can legitimately run a binary with `EF_RISCV_RVC` set. The field is also only advisory; the actual ISA/ABI limits are enforced by the instruction decoder during execution and by the linker when building the artifact, so a fixed `e_flags` requirement would over-constrain capable zkVMs without adding a real guarantee.


