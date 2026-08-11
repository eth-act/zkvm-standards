This proposal aims to standardize zkVM IO interface. The input is the private input, the existential part of the relation being proven. The output is the public part of that relation. The interface also includes a diagnostic logging channel for developer-facing text that is not part of the proven relation.

# Motivation
Application developers need a zkVM independent way to access input and output. Then the code is portable and can be compiled without changes for various zkVMs.

# Goals
The goal is to define a portable, efficient and convenient way to do IO in zkVMs.

# The interface

The interface consists of the following C function prototypes:
- `void read_input(const uint8_t** buf_ptr, size_t* buf_size)`
- `void write_output(const uint8_t* output, size_t size)`
- `void write_log(const uint8_t* utf8_bytes, size_t utf8_len)`

The `read_input` function is used as follows:

```
    const uint8_t* buf_ptr;
    size_t buf_size;
    read_input(&buf_ptr, &buf_size);
```

After calling `read_input`, the `buf_ptr` variable contains a pointer to the input, and `buf_size` indicates its size. The data provided by `read_input` is the private input described in the introduction. If `buf_size` is 0, then `buf_ptr` may contain an arbitrary value and should be considered invalid. The `read_input` function cannot fail, so no error code is returned. The type `const uint8_t*` for `buf_ptr` indicates that the memory area containing the input may be read-only and that the application code must not write to the memory pointed to by `buf_ptr`. This function has no side effects beyond setting the pointer parameters, may be called multiple times, and is idempotent.

zkVMs that don't preload input will need to read the entire input into an internal buffer during machine initialization to ensure `read_input` can be safely called from `main`. As a consequence, the size of the machine input must be smaller than the zkVM's addressable space.

`write_output` may be called multiple times. The observable result of calling `write_output` multiple times is as if the buffers from successive calls were concatenated, forming the entirety of the public part described in the introduction. Theoretically, this allows writing an unbounded amount of data across multiple calls, more than the maximum value representable by `size_t`, although this is not a practical concern. This function cannot fail, so no error code is returned. The pointer passed to `write_output` must point to readable memory; which memory segments are readable is zkVM-dependent. The 0 (NULL) pointer is not treated specially by this specification.

`write_log` is intended for diagnostic messages such as `println`-style output. The bytes passed to `write_log` must form a UTF-8 string, making the interface language-invariant while remaining efficient for runtimes that already use UTF-8 internally. `write_log` does not contribute to the public output, is not part of the statement being proven, and must not affect guest execution aside from making the diagnostic text available to the host. Calls to `write_log` are independent of `write_output` and may be ignored by production proving environments that do not expose diagnostics. The function cannot fail, so no error code is returned. As with `write_output`, the pointer passed to `write_log` must point to readable memory, and the 0 (NULL) pointer is not treated specially by this specification.

`write_log` is intentionally specified as a raw UTF-8 write rather than a `println` primitive. Guest languages that expose `println` can implement it by passing UTF-8 bytes to `write_log`, optionally appending a newline before the call. This keeps the standard primitive flexible enough for both line-oriented and non-line-oriented logging APIs.

# Rationale

`read_input` enables zero-copy implementations for zkVMs that preload input into memory, which justifies the departure from the standard libc IO interface. This approach naturally precludes interactive input reading, though this limitation is not a concern for EF's use case.

The `read_input`, `write_output`, and `write_log` functions are independent of the libc IO interface. This proposal neither requires the presence of libc IO functions nor prescribes their behavior.