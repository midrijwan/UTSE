// core/HashToGq.hpp -- H : {0,1}* -> G^q_CL, modelled as a random oracle.
//
// Used by the DPRF of Figure 1 (every server evaluates H(j||alpha)) and by Upd,
// which recomputes H(j||alpha) from the ciphertext header.
//
// BICYCL has no hash INTO a class group (its HashAlgo only hashes a form to
// bytes). This builds one exactly the way BICYCL builds its own generator h in
// the CL_HSMqk constructor, with the prime taken from the input instead of
// being the smallest one:
//
//   l  := a 256-bit prime derived from SHAKE256(input, counter), with
//         (Delta / l) = 1 so that primeform(l) exists
//   H  := (primeform(l)^2)^M
//
// Squaring removes the 2-torsion (genus) part, on which DDH is easy; raising to
// M = q kills the F_CL component, so the result is in G^q_CL. This is the
// prime-form construction analysed in [SBK24] and [CLR24] (single prime);
// primeform(l) does not itself check (Delta / l) = 1 -- BICYCL's
// ClassGroup::random() filters with kronecker() first, and so do we.
#pragma once

#include "core/ClContext.hpp"

namespace utse {

class HashToGq
{
public:
  HashToGq(const ClContext &ctx, std::string dst, std::size_t prime_bits = 256)
      : ctx_(ctx), dst_(std::move(dst)), prime_bits_(prime_bits),
        q_bytes_(static_cast<Bytes>(ctx.q())), p_bytes_(static_cast<Bytes>(ctx.p()))
  {
    if (prime_bits_ < 128 || prime_bits_ % 8 != 0)
      throw std::invalid_argument("HashToGq: prime_bits must be a multiple of 8, at least 128");
  }

  const std::string &dst() const { return dst_; }
  std::size_t prime_bits() const { return prime_bits_; }

  /** Deterministic: every party computes the same element for the same input. */
  QFI operator()(const Bytes &msg) const
  {
    const std::size_t nbytes = prime_bits_ / 8;

    for (std::uint32_t ctr = 0; ctr < kMaxTries; ++ctr)
    {
      Shake256 h;
      h.update_framed(std::string("UTSE1-HashToGq-v1"));
      h.update_framed(dst_);
      h.update_framed(q_bytes_); /* bind to the parameters */
      h.update_framed(p_bytes_);
      h.update_framed(msg);
      h.update(u32be(ctr));

      Mpz l(h.finalize(nbytes));
      l.setbit(prime_bits_ - 1); /* exactly prime_bits bits */
      l.setbit(0);               /* odd                     */

      if (l == ctx_.q() || l == ctx_.p()) /* must not divide Delta = -p q^3 */
        continue;
      if (ctx_.disc().kronecker(l) != 1) /* cheap test first */
        continue;
      if (!l.is_prime())
        continue;

      const QFI form = ctx_.G().primeform(l);
      QFI sq;
      ctx_.G().nudupl(sq, form);
      const QFI r = ctx_.pow(sq, ctx_.M());

      if (r.is_one()) /* degenerate; astronomically unlikely */
        continue;
      return r;
    }
    throw std::runtime_error("HashToGq: no suitable prime found");
  }

private:
  static constexpr std::uint32_t kMaxTries = 1u << 20;

  const ClContext &ctx_;
  std::string dst_;
  std::size_t prime_bits_;
  Bytes q_bytes_;
  Bytes p_bytes_;
};

} /* namespace utse */
