# zkVM Handbook

This document defines the criteria used by EF Research Engineering (zkEVM project) to assess a
zkVM's readiness for inclusion in our testing tools and benchmarks, and for consideration under
EIP-8025. These guidelines represent our recommendations to All Core Devs (ACD) within our team's
capacity and should not be interpreted as authoritative protocol rules for Ethereum.

## zkVM Rubric

The EF will regard a zkVM as ready for use in EIP-8025 Optional Proofs if it meets the following
requirements, which are further described in subsequent sections.

1. It must implement the [zkvm-standards](https://github.com/eth-act/zkvm-standards), which will
   evolve over time
2. It must pass all tests run by the
   [zkevm-test-monitor](https://eth-act.github.io/zkevm-test-monitor/)
3. It must use formal methods to provide correctness guarantees for its circuits
4. It must achieve RTP\* on the EF reference cluster
5. All code used for proving L1 executions must be dual-licensed under MIT + Apache 2.0 and
   continuously developed in public repositories
6. Final proofs to be verified by stateless validators must be no larger than 300 KiB
7. The full, composite protocol, including all continuation layers, must meet the requirements of
   the EF Cryptography team
8. The team maintaining the zkVM must be considered _sustainable_. While this is hard to define
   precisely, preference is given to zkVMs maintained by established execution-layer teams or
   credible working groups

## Formal Methods Requirements

The use of formal verification for the prevention of circuit-correctness bugs has been proven
effective in recent efforts targeting SP1, OpenVM, Pico, and ZisK. Specific coverage expectations
will be published later.

## The Reference Cluster

To manage prover centralization risk, it is important to keep prover requirements at a reasonable
level. The Ethereum Foundation reference cluster is a proposed maximum hardware requirement. It
consists of **four machines**, each identical, with:

- Motherboard: ASRock WRX90 WS EVO
- CPU: AMD Threadripper PRO 9975WX
- GPUs: 4 x NVIDIA RTX 5090
- RAM: 8 x 16GB DDR5 5600 MT/s
- SSD: 2 x Samsung 9100 Pro 2TB

These requirements are subject to change, but they should be interpreted as upper bounds in terms of
capex and power.

## Real-Time Proving* (RTP*)

The natural definition of "real-time proving" is the ability of a prover to prove the execution of
any Ethereum block within a short enough duration that it is possible for proofs to flow around the
network and be made available to attesters in time for them to use the proofs in their validity
decisions. This is an unreasonable requirement to impose now, in Q3 2026, for a few reasons:

- [ePBS](https://eips.ethereum.org/EIPS/eip-7732) changes the slot structure, and the parameters of
  ePBS are currently not set.
- Incoming gas limit increases and repricings will inherently change what "real time proving" means.
- Even with repricing, it is very likely that code
  [chunking](https://ethresear.ch/t/merkelizing-bytecode-options-tradeoffs/22255) or some other
  strategy will be required to set a reasonable bound on the amount of hashing required of provers.

Unfortunately, the need for a moving target is unavoidable. The RTP\* requirement will consist of an
evolving set of test fixtures on which provers will be required to produce proofs in an acceptable
period of time; this set can become fixed once ePBS is finalized.

## Cryptographic Security Proofs

Formal security arguments must be provided and accepted by the broader community, with final
certification coming from the EF Cryptography team. A zkVM must meet the following requirements:

- It must have 128 bits of security (without using conjectures)
- It must be plausibly post-quantum safe

The security proofs must be conditional only on standard, stress-tested assumptions, limited to the
following:

- Security of well-studied hash functions
- Hardness of lattice problems

Security proofs can use recursion for the purposes of continuations and code chunking.

The Cryptography Team has
[established](https://zkevm.ethereum.foundation/blog/cryptography-research-update) a rolling
timeline of requirements, including [soundcalc](https://github.com/ethereum/soundcalc) integration
and the submission of formal specifications, to culminate in a rigorous final assessment of the
cryptographic security of all candidate zkVMs.
