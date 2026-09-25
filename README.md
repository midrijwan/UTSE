# UTSE --- Updatable Threshold Symmetric Encryption

This repository contains C++17 proof-of-concept implementations of
**UTSE1** and **UTSE2**, based on the constructions described in the
paper *Updatable Threshold Symmetric Encryption*.

The implementations use **BICYCL** for class-group operations and
GMP/OpenSSL for supporting arithmetic and randomness.

## Contents

``` text
UTSE/
├── utse1/
│   ├── core/       # Cryptographic building blocks and UTSE1 scheme
│   ├── common/     # Shared checks, scenarios and reporting
│   ├── inproc/     # In-process UTSE1 implementation
│   ├── net/        # TCP/loopback UTSE1 implementation
│   ├── CMakeLists.txt
│   └── README.md
│
└── utse2/
    ├── core/       # UTSE2 scheme and class-group context
    └── inproc/     # In-process UTSE2 implementation
```

## UTSE1

UTSE1 implements the construction corresponding to **Figure 9** of the
paper.

Two front ends are provided:

-   **In-process:** the parties are represented as C++ objects and
    communicate through function calls.
-   **Networked:** the parties run as independent TCP servers over
    loopback, using real sockets and `send()`/`recv()`.

Both implementations share the same cryptographic core and test
scenarios.

UTSE1 covers:

-   Setup
-   Encryption and decryption
-   Epoch updates
-   Threshold reconstruction
-   Ciphertext serialization/parsing
-   Commitment and structural validity checks
-   Rejection of malformed or invalid ciphertexts
-   Misuse/error handling
-   Performance measurements
-   TCP transport and wire-format testing

See [`utse1/README.md`](utse1/README.md) for the detailed UTSE1
documentation, build instructions, implementation notes, and security
scope.

## UTSE2

UTSE2 implements the construction corresponding to **Figure 10** of the
paper.

Compared with UTSE1, the UTSE2 design removes the client identity and
commitment from the ciphertext:

``` text
UTSE1 ciphertext:  (j, r, c)
UTSE2 ciphertext:  (r, c)
```

The UTSE2 implementation therefore demonstrates the unlinkable
ciphertext structure described in the paper.

The current UTSE2 code provides an **in-process** implementation with:

-   Setup
-   Encryption/decryption
-   Threshold reconstruction
-   Epoch updates
-   Fresh random DPRF inputs
-   The additional `r' / R'` round used by `Next`
-   Basic correctness and misuse checks
-   Timing measurements

### UTSE2 build note

The current `utse2` archive is a smaller standalone implementation and
does not include its own CMake configuration or a copy of
`common/Report.hpp`. The UTSE2 `main2.cpp` includes:

``` cpp
#include "common/Report.hpp"
```

If you want to build UTSE2 independently, you should either:

1.  add the required common/reporting files and a CMake target, or
2.  place UTSE2 into the same source tree as the shared `common/` code
    and configure the include paths accordingly.

## Requirements

The implementations are written for C++17.

Typical requirements are:

-   C++17 compiler
-   CMake 3.16+
-   GMP with C++ bindings
-   OpenSSL 1.1.1+ or compatible version
-   [BICYCL](https://gite.lirmm.fr/crypto/bicycl)

BICYCL is **not vendored** in this repository. You need a local BICYCL
checkout and must provide its location when configuring UTSE1.

## Building UTSE1

From the repository root:

``` bash
cd utse1

cmake -S . -B build \
  -DBICYCL_DIR=/path/to/your/bicycl \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build -j
```

Then run:

``` bash
./build/utse1_inproc
./build/utse1_net
```

For command-line options:

``` bash
./build/utse1_inproc -h
./build/utse1_net -h
```

The network implementation uses loopback TCP and supports configuration
of the host and base port.

## Implementation notes

A few details of the paper's pseudocode require concrete choices when
implemented over a class group of unknown order.

In particular, the code uses integer secret sharing and reconstructs an
exponent scaled by:

``` text
Delta² · k
```

where:

``` text
Delta = n!
```

The update operation is adjusted consistently with this scaling.

The implementation also provides its own construction of the
hash-to-class-group operation required by the DPRF.

See the UTSE1 README and source comments for the full discussion.

## Randomness

The implementation distinguishes between public parameter generation and
secret randomness.

For normal operation, secret values are generated using
cryptographically secure randomness through OpenSSL's `RAND_bytes`.

A deterministic `-seed` option is available for debugging and
reproducibility. **Do not use deterministic seeded randomness for real
cryptographic keys.**

## Security / research scope

This repository is a **research and proof-of-concept implementation**,
not production cryptographic software.

In particular, it should not be assumed to provide:

-   constant-time or side-channel-resistant implementations;
-   secure memory erasure;
-   production-grade key management;
-   authenticated/encrypted network transport;
-   protection against every form of malicious server behavior;
-   a formal security proof of the implementation itself.

The code is intended to make the constructions executable and testable,
and to provide a basis for experimentation and comparison with the
paper.

## Repository purpose

The repository is intended for:

-   studying the UTSE constructions;
-   reproducing protocol experiments;
-   testing the cryptographic building blocks;
-   comparing in-process and networked execution for UTSE1;
-   experimenting with the UTSE2 unlinkable construction;
-   benchmarking the main protocol operations.

## Reference

The implementations are based on:

> *Updatable Threshold Symmetric Encryption*

Please consult the accompanying paper for the formal definitions,
security model, algorithms, and proofs.

## License

No license has been specified for this repository yet.

If this code is intended for public reuse, add an appropriate `LICENSE`
file before treating the repository as open-source software.
