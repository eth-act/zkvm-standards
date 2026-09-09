# Host Randomness

This standard requires a zkVM to provide guests access to a cryptographically strong pseudorandom number generator (CSPRNG) via a function `zkvm_random_u64`.

## Motivation

@LukaszRozmej made the case for provers to provide a per-proof construction source of randomness as the solution to a particular security problem [here](https://github.com/ethereum/EIPs/pull/12289). The problem arises when a guest program uses hash maps whose keys are computed deterministically from the program inputs. In such a setting, an attacker can find a set of inputs leading to collisions in the hash map, opening the possibility of a simultaneous DoS attack on every prover running that guest.

A guest cannot draw its own randomness, because everything it reads is committed input. So every guest of a given version maps a given key to the same bucket indefinitely, and one colliding set found offline works against every prover.

## Goals

* Standardization: a fixed guest run in different hosts can sample the randomness with a single, portable call.
* Safe default: successive calls return independent values, even if the guest and its inputs remain fixed.
* Debugging support: seeds may be set by the host operator for reproducible runs.
* Compliance with accepted standards: the source satisfies a recognized random bit generation specification. See [Referenced standards](#referenced-standards).

## Non-Goals
* Standardization of the generator: vendors choose any construction that meets the requirements below.
* Constraints on the generated values: the host supplies them as free, private witness values.

## Specification

### Interface

The vendor static library defined by [Static Library and Linker Script](../static-library-and-linker-script/README.md) exports one mandatory symbol:

```c
uint64_t zkvm_random_u64(void);
```

Each call returns 64 uniformly distributed bits, independent of every other call. The function cannot fail, so no error code is returned. A guest that needs more bits calls again rather than expanding one value itself.

### Requirements on the host

The host draws the values for each guest execution from a [cryptographically secure pseudorandom number generator](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator), independently of every other execution. The author of the guest input must not be able to predict them.

### Invariance

The values are free witness values; the prover need not provide any cryptographic attestation of how the values were generated. For a fixed guest input, the public output and exit code must be identical for every sequence the source can return.

### Reproducible runs

The host may force the values for a run, so that a guest execution can be replayed. The guest cannot reach that mechanism: the interface has no seeding function, and a guest cannot observe whether the values were forced.

## Background Reference

* [Motivating pull request into EIP-8025](https://github.com/ethereum/EIPs/pull/12289)
* [NIST SP 800-90A Rev. 1](https://doi.org/10.6028/NIST.SP.800-90Ar1) — DRBG mechanisms that satisfy this requirement. [SP 800-90B](https://doi.org/10.6028/NIST.SP.800-90B) covers the entropy source that seeds one.
