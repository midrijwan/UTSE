// core/ClContext.hpp -- the class-group public parameters (Appendix A.4).
//
//   ppCG = (U, q, Ghat_CL, F_CL, G^q_CL, g_q, f, D, D_q)
//
// BICYCL's CL_HSMqk derives all of this from (q, k, p). We fix k = 1, so the
// message slot is Z_q and the parameters travel as the pair (q, p).
//
// Only CL_HSMqk's setup, f^m (power_of_f) and Solve (dlog_in_F) are used: its
// own encrypt/decrypt implement the public-key CL scheme, not Figure 9.
#pragma once

#include <optional>

#include "core/Rng.hpp"

namespace utse {

class ClContext
{
public:
  /** Fresh parameters: a random q_nbits-bit prime q, at the given security level. */
  ClContext(std::size_t q_nbits, unsigned sec_level_bits, Rng &rng)
      : ClContext(q_nbits, sec_level_bits, rng.randgen())
  {
  }

  /** Rebuild exactly the same parameters from (q, p). Deterministic. */
  ClContext(const Mpz &q, const Mpz &p) : cl_(q, 1, p) {}

  ClContext(const ClContext &) = delete;
  ClContext &operator=(const ClContext &) = delete;

  const CL_HSMqk &cl() const { return cl_; }
  /** Cl(Delta): the group every mask and ciphertext lives in. */
  const ClassGroup &G() const { return cl_.Cl_Delta(); }

  const Mpz &q() const { return cl_.q(); }
  const Mpz &p() const { return cl_.p(); }
  const Mpz &M() const { return cl_.M(); }        /* M = q^k = q */
  const Mpz &disc() const { return cl_.Delta(); } /* Delta = -p q^3 */
  bool large_message_variant() const { return cl_.large_message_variant(); }

  /* ---- group operations ------------------------------------------------ */
  QFI one() const { return G().one(); }

  QFI mul(const QFI &a, const QFI &b) const
  {
    QFI r;
    G().nucomp(r, a, b);
    return r;
  }

  /** a * b^-1 */
  QFI div(const QFI &a, const QFI &b) const
  {
    QFI r;
    G().nucompinv(r, a, b);
    return r;
  }

  /** base^e. BICYCL's nupow exponentiates by |e| and inverts for e < 0. */
  QFI pow(const QFI &base, const Mpz &e) const
  {
    QFI r;
    G().nupow(r, base, e);
    return r;
  }

  /** Does x have our discriminant? (BICYCL's validating QFI constructor does not check this.) */
  bool in_group(const QFI &x) const { return x.discriminant() == disc(); }

  /* ---- F_CL = <f>, where the discrete log is easy ------------------------ */
  /** Gamma(m) = f^m. */
  QFI f_pow(const Mpz &m) const { return cl_.power_of_f(m); }

  /**
   * x in F_CL  <=>  x^M = 1 (sound because gcd(q, s_hat) = 1). This is the
   * "free structural validity check" of Section 1.2.
   */
  bool in_F(const QFI &x) const { return pow(x, M()).is_one(); }

  /**
   * Solve: f^m -> m, or nothing if x is not in F_CL. dlog_in_F also throws on
   * inputs outside F_CL; the explicit x^M test above is checked first anyway,
   * so the gate does not depend on that internal check.
   */
  std::optional<Mpz> solve(const QFI &x) const
  {
    if (!in_F(x))
      return std::nullopt;
    try
    {
      return cl_.dlog_in_F(x);
    }
    catch (const std::invalid_argument &)
    {
      return std::nullopt;
    }
  }

  /* ---- sampling -------------------------------------------------------- */
  /** x <- D_q: uniform below BICYCL's exponent bound for the order-s subgroup. */
  Mpz sample_Dq(Rng &rng) const { return rng.below(cl_.secretkey_bound()); }
  const Mpz &Dq_bound() const { return cl_.secretkey_bound(); }

  /** h: CL_HSMqk's own generator of G^q_CL (used directly by UTSE2, Figure 10). */
  const QFI &h() const { return cl_.h(); }

  /** r <- G^q_CL, uniform: h^x for a fresh x <- D_q (same recipe CL_HSMqk's own encrypt() uses). */
  QFI sample_Gq(Rng &rng) const { return pow(h(), sample_Dq(rng)); }

  /** Largest mu, a multiple of 16, with 2^mu <= q (Figure 11). */
  std::size_t max_mu() const
  {
    const std::size_t nb = q().nbits(); /* 2^(nb-1) <= q < 2^nb */
    return nb < 17 ? 0 : ((nb - 1) / 16) * 16;
  }

private:
  ClContext(std::size_t q_nbits, unsigned sec_level_bits, RandGen &&rg)
      : cl_(q_nbits, 1, BICYCL::SecLevel(sec_level_bits), rg)
  {
  }

  CL_HSMqk cl_;
};

} /* namespace utse */
