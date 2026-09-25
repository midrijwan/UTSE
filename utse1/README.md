# UTSE1 — two implementations of Figure 9

A C++17 implementation of **UTSE1** (Figure 9) from *Updatable Threshold
Symmetric Encryption*, on top of [BICYCL](https://gite.lirmm.fr/crypto/bicycl).
The cryptography (`core/`) is written once; two front ends run it two ways:

- **`utse1_inproc`** — the `n` parties are C++ objects, a "message" between
  them is a function call.
- **`utse1_net`** — the `n` parties are real, independent TCP servers on
  loopback (their own thread, their own listening socket, real
  `send()`/`recv()`); a client connects to all `n` and drives the same
  protocol over the wire.

Both link the exact same `core/` and run the exact same checks
(`common/Scenario.hpp`), so a difference in behaviour between them can only
come from the transport, never from the cryptography or the tests.

## 1. Build

Requirements: a C++17 compiler (GCC >= 9 or Clang >= 10), CMake >= 3.16, GMP
(with the C++ bindings), OpenSSL >= 1.1.1, and a BICYCL checkout (the one you
already have locally — this project does **not** vendor or download it).

```bash
sudo apt-get install build-essential cmake libgmp-dev libssl-dev   # Debian/Ubuntu

cd utse1
cmake -S . -B build -DBICYCL_DIR=/path/to/your/bicycl -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Then:

```bash
./build/utse1_inproc
./build/utse1_net
```

Both accept `-h` for options (parties, threshold, security level, message
size, benchmark trials/batch size). `utse1_net` additionally takes
`-base-port` and `-host`.

### VSCode

Open the `utse1` folder, install the **C/C++** and **CMake Tools**
extensions, edit `.vscode/settings.json` to point `BICYCL_DIR` at your real
path, then *CMake: Configure* → *CMake: Build*. `.vscode/launch.json` has a
debug config for each executable.

### If it does not build

**Please send me the exact error message** (the whole `cmake --build`
output, or at least the first error and the ten or so lines above it) rather
than a description — BICYCL's API differs a little between snapshots, and
the precise error tells me immediately which line to fix. I have *not* run
this build myself in this environment (I only have some of your BICYCL
headers, not the whole tree with a working GMP/OpenSSL install), so treat
the first attempt as the real test.

## 2. What the demos do

Both programs run, in order:

1. **building blocks** — Appendix A.3's integer reconstruction
   (`sum Lambda_j y_j = Delta^2 * secret`, checked for three different
   quorums), Figure 11's `Decode(Encode(u,v)) = (u,v)` round trip and its
   `>= 2^mu` rejection, `H`'s determinism and where it lands, and that
   fresh `ClContext`/`Utse1Scheme` objects rebuilt from `(q, p, n, t, mu,
   com_pp)` alone reproduce the same parameters;
2. **Setup**, then **Enc**/**Dec** at epoch 0 with several different
   (client, quorum) pairs, edge-case messages (`00..00`, `FF..FF`), a batch
   of 4, and a ciphertext serialise/parse round trip;
3. **three rounds of Next + Upd** (Upd applied to every stored record by a
   `StorageHost`, in parallel), then Dec at epoch 3 from yet another quorum,
   a fresh encryption at epoch 3, and rejection of the stale epoch-0
   ciphertext;
4. **all three of Dec's rejection gates**, exercised individually: a
   payload nudged inside `F_CL` (commitment gate), a payload nudged outside
   `F_CL` (structural gate), a tampered `alpha`, a re-attributed header, a
   truncated `alpha`;
5. **misuse is refused**: `|Q| < t`, the client absent from its own quorum,
   a duplicated party in `Q`, a party id outside `1..n`, a wrong-length
   message;
6. **timings**: each building block in isolation, then `Enc`/`Dec` one at a
   time, a batch, `Next`, and `Upd` over every stored record —
   `utse1_net`'s benchmark also reports bytes on the wire per operation.

Expected output ends with `N/N checks passed` and exit code 0.

## 3. File map

| paper | file |
|---|---|
| Figure 9 — `Setup`, `Next`, `Enc`, `Dec`, `Upd` | `core/Utse1Scheme.hpp` |
| Figure 1 — class-group DPRF (`Eval`, `Combine`) | `core/Dprf.hpp` |
| Figure 11 — encoding scheme `E = (Encode, Decode)` | `core/Encode.hpp` |
| Definition 11 — commitment scheme `Com` | `core/Commitment.hpp` |
| Appendix A.3 — Shamir's secret sharing over **Z** | `core/IntegerSSS.hpp` |
| §A.4 — class-group setup, `f`, `Solve`, `G^q_CL` | `core/ClContext.hpp` |
| `H : {0,1}* -> G^q_CL` (assumed by the DPRF) | `core/HashToGq.hpp` |
| the untrusted storage host running `Upd` | `core/StorageHost.hpp` |
| wire format for ciphertexts/tokens/forms | `core/Wire.hpp` |
| bytes, `n!`, SHAKE256 | `core/Util.hpp` |
| all real randomness (never BICYCL's default `RandGen`) | `core/Rng.hpp` |
| the check suite and benchmark, shared by both front ends | `common/Scenario.hpp` |
| in-process parties | `inproc/InProcUtse1.hpp`, `inproc/main.cpp` |
| TCP transport (sockets, framing) | `net/Socket.hpp` |
| the wire messages | `net/Protocol.hpp` |
| a party as a TCP server | `net/PartyServer.hpp` |
| the client side, over TCP | `net/NetUtse1.hpp`, `net/main.cpp` |

## 4. Implementation notes

These are the places where the paper's pseudocode cannot be taken 100%
literally. All three are marked in the source at the point they matter.

### 4.1 Share and shift arithmetic is over Z, not mod q

Figure 9 writes `k^(i)_{e+1} <- k^(i)_e + delta^(i)_{e+1} mod q`. The masks
live in `G^q_CL`, whose order is unknown and is **not** `q` (that is `F_CL`'s
order); reducing key material mod `q` would be reducing modulo the wrong
number. All share and shift arithmetic here is over `Z`
(`core/IntegerSSS.hpp`, `Utse1Scheme::apply_shift`). Shares grow by roughly
`log2(#epochs)` bits over a run.

### 4.2 The reconstructed exponent is `Delta^2 * k`, and `Upd` is adjusted to match

Sharing over `Z` (Appendix A.3, Protocol 1) scales the secret by
`Delta = n!` and reconstructs with integer Lagrange coefficients
`Lambda_{j,Q} = Delta * l_{j,Q}(0)`, so

```
sum_{j in Q} Lambda_{j,Q} y_j = Delta * f(0) = Delta^2 * k_e
```

for *every* quorum — this is exact, not statistical. `Combine` therefore
returns `w_e = H(j||alpha)^(Delta^2 * k_e)`. For `Upd` to produce a
ciphertext that decrypts under this same convention, it raises to
`Delta^2 * delta_{e+1}`, not to `delta_{e+1}` as Figure 9 prints it:

```
c_{e+1} = c_e * H(j||alpha)^(Delta^2 * delta_{e+1})
```

`Delta = n!` is public, so the host computes this itself and the token
stays the single scalar `delta_{e+1}` (`core/Utse1Scheme.hpp::upd`,
`core/IntegerSSS.hpp`). Figure 1 also writes the Lagrange coefficients as
`lambda_{i,Q} ... (mod p)`; there is no `p`, and nothing can be reduced in a
group of unknown order, so `IntegerSSS::lagrange_at_zero` computes them as
exact integers.

*(There is a second, equally valid way to resolve this — keep `Upd`'s
formula exactly as printed and instead redefine what "sample from `D_q`"
produces in `Setup`/`Next`. Both are internally consistent; this codebase
takes Protocol 1 at face value, since it is the paper's own separately
specified subroutine, and lets `Upd` — the scheme's own novel algorithm —
absorb the consequence.)*

### 4.3 `H : {0,1}* -> G^q_CL` is ours to build

BICYCL has no hash into a class group (its `HashAlgo` only hashes a form
*to* bytes, the opposite direction). `HashToGq` builds one the way BICYCL
builds its own generator `h` in `CL_HSMqk`'s constructor:

```
derive a 256-bit prime l from SHAKE256(domain, q, p, input, counter)
  with l != p, l != q, and (Delta / l) = 1   (kronecker symbol test)
  -> ClassGroup::primeform(l)
  -> square (removes the 2-torsion part)
  -> raise to M = q^k                        (projects into G^q_CL)
```

`primeform` does **not** itself check `(Delta / l) = 1` — it calls
`sqrt_mod_prime` unconditionally — so the `kronecker` filter has to run
first; this is confirmed directly from `qfi.inl`, where
`ClassGroup::random()` applies exactly the same filter before calling
`primeform`. This is the single-prime construction analysed in
[SBK24, eprint 2024/034] and [CLR24, eprint 2024/295], the same two papers
the UTSE1 paper itself cites for the existence of `H`; it is a heuristic
random oracle into `G^q_CL`, not a proof.

## 5. Randomness

BICYCL's `RandGen`, default-constructed, always starts from the **same
fixed seed** (`gmp_randinit_default`). It is used here in exactly one place
— generating the *public* class-group parameters, where that does not
matter. Every secret (key shares, shifts, polynomial coefficients,
commitment openings) is drawn from `core/Rng.hpp`, which wraps OpenSSL's
`RAND_bytes` by default. `-seed <text>` switches to a deterministic
SHAKE256 stream instead, for reproducing a specific run while debugging —
the programs print a warning when this is active, and it must never be used
for real keys.

## 6. Scope

This is a proof-of-concept implementation of the construction, not a
hardened one:

- `Setup` is a trusted dealer and `Next` is dealt by a single invoking
  party, exactly as Definition 6 and Figure 9 specify.
- The DPRF is required to be pseudorandom (Definition 3) but not correct
  against a cheating server (Definition 4): a server that returns a
  malformed partial evaluation makes `Dec` output bottom, not a crash and
  not a wrong plaintext — but nothing here proves a server behaved
  honestly. `net/PartyServer.hpp` does validate message shapes and epoch
  agreement, so a malformed or out-of-sync message from a *client* is
  rejected cleanly, but a *malicious* server evaluating on the wrong share
  is out of scope.
- No side-channel hardening, no constant-time arithmetic, no secure
  erasure of key material.
- `utse1_net` binds to loopback only; it is a real socket protocol, not a
  hardened one to run across an untrusted network as-is (no
  authentication of *which* process is on the other end beyond the
  fingerprint-matching handshake, no transport encryption — everything
  Figure 9 sends over the wire is itself already public information or a
  DPRF share meant for that one party, so this matches the paper's own
  trust model, but it is worth being explicit about).
