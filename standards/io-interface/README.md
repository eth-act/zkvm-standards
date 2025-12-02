This proposal aims to standardize zkVM IO interface. The input is the private input, the existential part of the relation being proven. The output is the public part of that relation.

# Motivation
Application developers need a zkVM independent way to access input and output. Then the code is portable and can be compiled without changes for various zkVMs.

# Goals
The goal is to define a portable, efficient and convenient way to do IO in zkVMs.

# The interface

The proposed interface consists of the following C function prototypes that are already part of libc:
- `ssize_t read(int fd, void buf[.count], size_t count);`
- `ssize_t write(int fd, const void buf[.count], size_t count);`
- `off_t lseek(int fd, off_t offset, int whence);`

See libc documentation for semantics of these functions:
- https://man7.org/linux/man-pages/man2/read.2.html
- https://man7.org/linux/man-pages/man2/write.2.html
- https://man7.org/linux/man-pages/man2/lseek.2.html

It's assumed that file descriptor "0" corresponds to the input and file descriptor "1" corresponds to the output.

The support for `lseek` makes sense only for fd "0" and only on zkVMs that provide random access to the input. In other cases that function shall error out.

# Rationale

libc provides good and efficient abstractions for IO. The aforementioned functions are part of POSIX.1-2008 standard and are present in all libc implementations of interest. `glibc` and `musl` obviously support them. `newlib`, which is designed for bare-metal systems, also crucially depends of these functions.

Utilizing libc provides a cross-language interface for IO because C functions can be easilly called with FFIs.

Since standard libraries and runtimes of popular languages (C/C++/Rust/C#/Nim) depend on libc anyway it makes sense to use IO facilities from libc.


