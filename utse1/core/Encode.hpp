// core/Encode.hpp -- Figure 11 / Appendix A.1: E = (Encode, Decode).
//
//   Encode(u, v) = (2^l <u> + <v>) mod q,     l = mu/2,  2^mu <= q
//   Decode(z)    = split the canonical representative of z at bit l,
//                  and bottom whenever that representative is >= 2^mu.
//
// The bottom branch is the "second weak integrity check" of Section 1.2: it is
// a rejection gate of Dec, not merely a convenience.
//
// mu must be a multiple of 16 so that both slots are whole bytes.
#pragma once

#include "core/ClContext.hpp"

namespace utse {

class Encode
{
public:
  Encode(const ClContext &ctx, std::size_t mu) : ctx_(ctx), mu_(mu)
  {
    if (mu_ == 0 || mu_ % 16 != 0)
      throw std::invalid_argument("Encode: mu must be a positive multiple of 16");

    Mpz::mulby2k(two_pow_mu_, 1UL, static_cast<mp_bitcnt_t>(mu_));
    if (two_pow_mu_ > ctx_.q())
      throw std::invalid_argument("Encode: Figure 11 needs 2^mu <= q (lower mu or raise q)");
  }

  std::size_t mu() const { return mu_; }
  std::size_t slot_bits() const { return mu_ / 2; }
  std::size_t slot_bytes() const { return mu_ / 16; }

  /** u and v must each be exactly slot_bytes() long. */
  Mpz encode(const Bytes &u, const Bytes &v) const
  {
    if (u.size() != slot_bytes() || v.size() != slot_bytes())
      throw std::invalid_argument("Encode::encode: wrong slot size");

    const Mpz U(u);
    const Mpz V(v);

    Mpz z;
    Mpz::mulby2k(z, U, static_cast<mp_bitcnt_t>(slot_bits()));
    Mpz::add(z, z, V);
    Mpz::mod(z, z, ctx_.q());
    return z;
  }

  /** Returns false for bottom. */
  bool decode(const Mpz &z, Bytes &u, Bytes &v) const
  {
    Mpz zbar;
    Mpz::mod(zbar, z, ctx_.q()); /* canonical representative in [0, q) */

    if (zbar >= two_pow_mu_)
      return false;

    Mpz U;
    Mpz V;
    Mpz::divby2k(U, zbar, static_cast<mp_bitcnt_t>(slot_bits()));
    Mpz::mod2k(V, zbar, static_cast<mp_bitcnt_t>(slot_bits()));

    u = mpz_to_fixed(U, slot_bytes());
    v = mpz_to_fixed(V, slot_bytes());
    return true;
  }

private:
  const ClContext &ctx_;
  std::size_t mu_;
  Mpz two_pow_mu_;
};

} /* namespace utse */
