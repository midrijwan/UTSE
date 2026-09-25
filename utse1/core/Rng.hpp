// core/Rng.hpp -- the randomness every secret of the scheme is drawn from.
//
// BICYCL's RandGen is GMP's Mersenne Twister, and a default-constructed RandGen
// always starts from the same fixed seed (gmp_randinit_default). That is not
// acceptable for key shares, shifts, polynomial coefficients or commitment
// openings, so all of those come from here:
//
//   Rng rng;         OpenSSL RAND_bytes                        (the default)
//   Rng rng(seed);   a SHAKE256 stream keyed by `seed`          (reproducible
//                    runs, for debugging only -- never for real keys)
//
// RandGen is still needed exactly once: CL_HSMqk's constructor takes one to
// generate the PUBLIC class-group parameters. It is seeded from this Rng.
#pragma once

#include <limits>
#include <mutex>

#include <openssl/rand.h>

#include "core/Util.hpp"

namespace utse {

class Rng
{
public:
  /** Empty seed: OS entropy. Non-empty seed: deterministic stream. */
  explicit Rng(Bytes seed = {}) : seed_(std::move(seed)) {}

  Rng(const Rng &) = delete;
  Rng &operator=(const Rng &) = delete;

  bool deterministic() const { return !seed_.empty(); }

  /** n uniformly random bytes. Thread-safe. */
  Bytes bytes(std::size_t n)
  {
    Bytes out(n);
    if (n == 0)
      return out;

    std::lock_guard<std::mutex> lock(mu_);
    if (seed_.empty())
    {
      if (n > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        throw std::invalid_argument("Rng::bytes: request too large");
      if (RAND_bytes(out.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("Rng: RAND_bytes failed");
    }
    else
    {
      Shake256 h;
      h.update_framed(std::string("UTSE1-DRBG-v1"));
      h.update_framed(seed_);
      h.update(u64be(counter_++));
      out = h.finalize(n);
    }
    return out;
  }

  /** Uniform in [0, 2^nbits). */
  Mpz bits(std::size_t nbits)
  {
    if (nbits == 0)
      return Mpz(0UL);
    Bytes b = bytes((nbits + 7) / 8);
    const std::size_t excess = 8 * b.size() - nbits;
    b[0] = static_cast<unsigned char>(b[0] & (0xFFu >> excess));
    return Mpz(b);
  }

  /** Uniform in [0, bound), by rejection (fewer than 2 draws on average). */
  Mpz below(const Mpz &bound)
  {
    if (bound.sgn() <= 0)
      throw std::invalid_argument("Rng::below: bound must be positive");
    const std::size_t nb = bound.nbits();
    for (;;)
    {
      Mpz x = bits(nb);
      if (x < bound)
        return x;
    }
  }

  /** A BICYCL RandGen seeded from this Rng (public-parameter generation only). */
  RandGen randgen() { return RandGen(Mpz(bytes(32))); }

  /**
   * Seed for an independent child generator (one per party). In OS-entropy
   * mode the child uses OS entropy too, so this returns an empty seed.
   */
  Bytes derive_seed(const std::string &label) const
  {
    if (seed_.empty())
      return {};
    Shake256 h;
    h.update_framed(std::string("UTSE1-DRBG-derive-v1"));
    h.update_framed(seed_);
    h.update_framed(label);
    return h.finalize(32);
  }

private:
  std::mutex mu_;
  const Bytes seed_;
  std::uint64_t counter_ = 0;
};

} /* namespace utse */
