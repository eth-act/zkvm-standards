# zkVM Cryptographic Accelerators C Interface

This standard defines the C interface for accessing accelerators in zkVMs, primarily based on the precompiles needed in the Ethereum Virtual Machine(EVM).

## Overview

zkVMs can provide optimized implementations of common cryptographic operations used in Ethereum. This standard defines a portable C API for guest programs to access these accelerators.

Note: The interface is based on Ethereum precompiles but simplified to expose raw cryptographic operations without Ethereum-specific constraints where feasible.

## Header File

See [`zkvm_accelerators.h`](./zkvm_accelerators.h) for the complete interface that a guest program can use. The functions in the header file will be implemented by the appropriate zkVM.