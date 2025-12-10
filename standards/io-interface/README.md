This proposal aims to standardize zkVM IO interface. The input is the private input, the existential part of the relation being proven. The output is the public part of that relation.

# Motivation
Application developers need a zkVM independent way to access input and output. Then the code is portable and can be compiled without changes for various zkVMs.

# Goals
The goal is to define a portable, efficient and convenient way to do IO in zkVMs.

Two possible interfaces are presented below.

# Option 1

## The interface

The proposed interface consists of the following C function prototypes that are part of libc:
- `ssize_t read(int fd, void buf[.count], size_t count);`
- `ssize_t write(int fd, const void buf[.count], size_t count);`

See libc documentation for semantics of these functions:
- https://man7.org/linux/man-pages/man2/read.2.html
- https://man7.org/linux/man-pages/man2/write.2.html

It's assumed that file descriptor "0" corresponds to the input and file descriptor "1" corresponds to the output.

Error conditions should be handled following the standard. E.g. when an invalid file descriptor is passed then a function should return -1 and set `errno` to `EBADF`.

"0" is the only valid file descriptor to `read` and "1" is the only valid file descriptor to `write`.

## Rationale

libc provides good and efficient abstractions for IO. The aforementioned functions are part of POSIX.1-2008 standard and are present in all libc implementations of interest. `glibc` and `musl` obviously support them. `newlib`, which is designed for bare-metal systems, also crucially depends of these functions.

Utilizing libc provides a cross-language interface for IO because C functions can be easilly called with FFIs.

Since standard libraries and runtimes of popular languages (C/C++/Rust/C#/Nim) depend on libc anyway it makes sense to use IO facilities from libc.

# Option 2
## The interface

The proposed interface consists of the following C function prototypes:
- `void read_input(const uint8_t** buf_ptr, size_t* buf_size)`
- `void write_output(const uint8_t* output, size_t size)`

The `read_input` function is used as follows:

```
    const uint8_t* buf_ptr;
    size_t buf_size;
    read_input(&buf_ptr, &buf_size);
```

After calling `read_input`, the `buf_ptr` variable contains a pointer to the input, and `buf_size` indicates its size. If `buf_size` is 0, then `buf_ptr` may contain an arbitrary value and should be considered invalid. The `read_input` function cannot fail, so no error code is returned. The type `const uint8_t*` for `buf_ptr` indicates that the memory area containing the input is read-only. This function has no side effects beyond setting the pointer parameters, may be called multiple times, and is idempotent.

`write_output` may be called multiple times. The program's output is the concatenation of buffers passed to successive calls to `write_output`. This function cannot fail, so no error code is returned.

The `read_input` and `write_output` functions are independent of the libc IO interface. This proposal neither requires the presence of libc IO functions nor prescribes their behavior.

## Rationale

`read_input` enables zero-copy implementations for zkVMs that preload input into memory, which justifies the departure from the standard libc IO interface. As a consequence, zkVMs that don't preload input will need to read the entire input into an internal buffer during machine initialization to ensure `read_input` can be safely called from `main`. This approach naturally precludes interactive input reading, though this limitation is not a concern for EF's use case.
