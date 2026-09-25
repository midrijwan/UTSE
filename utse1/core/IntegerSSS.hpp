// core/IntegerSSS.hpp -- Shamir's secret sharing over Z (Appendix A.3, Protocol 1).
//
// The group order is unknown, so shares cannot be reduced modulo anything and
// Lagrange interpolation cannot divide. Protocol 1 solves both with Delta = n!:
//
//   share   : alpha~ = alpha * Delta                                  (step 1)
//             f(X)   = alpha~ + r_1 X + ... + r_{t-1} X^{t-1},
//                      r_k <- [0, 2^B)                                (step 2)
//             y_i    = f(i) over Z, i = 1..n                          (steps 3-4)
//
//   combine : Lambda_{j,Q} = Delta * l_{j,Q}(0) is an exact integer, and
//             sum_{j in Q} Lambda_{j,Q} y_j = Delta * f(0) = Delta^2 * alpha.
//
// Protocol 1 is followed literally, so reconstruction always yields
// Delta^2 * alpha. That public factor is carried consistently through the whole
// scheme -- in particular into Upd (README 6.2).
//
// The coefficient size B and the exact-division trick follow BICYCL's own
// integer sharing in CL_threshold.inl (poly_coeff_bitsize_bound,
// lagrange_at_zero), without its VSS commitments and proofs.
#pragma once

#include <algorithm>

#include "core/Rng.hpp"

namespace utse {

class IntegerSSS
{
public:
  /**
   * @param n             number of parties
   * @param t             threshold: any t shares reconstruct (degree t-1)
   * @param secret_nbits  bound on the bit length of a secret
   * @param lambda_st     statistical security parameter
   */
  IntegerSSS(unsigned n, unsigned t, std::size_t secret_nbits, std::size_t lambda_st = 40)
      : n_(n), t_(t), delta_(factorial(n))
  {
    if (n_ == 0 || t_ == 0 || t_ > n_)
      throw std::invalid_argument("IntegerSSS: need 1 <= t <= n");
    Mpz::mul(delta2_, delta_, delta_);
    coeff_bits_ = secret_nbits + delta_.nbits() + lambda_st + 2 * bit_length(t_ + 1) + 3;
  }

  unsigned n() const { return n_; }
  unsigned t() const { return t_; }
  const Mpz &delta() const { return delta_; }   /* Delta   = n!     */
  const Mpz &delta2() const { return delta2_; } /* Delta^2 = (n!)^2 */
  std::size_t coeff_bits() const { return coeff_bits_; }

  /** Protocol 1. Returns y_1 .. y_n; element 0 is party 1's share. */
  std::vector<Mpz> share(const Mpz &alpha, Rng &rng) const
  {
    if (alpha.sgn() < 0)
      throw std::invalid_argument("IntegerSSS::share: negative secret");

    std::vector<Mpz> coeff;
    coeff.reserve(t_);
    Mpz a0;
    Mpz::mul(a0, alpha, delta_); /* step 1 */
    coeff.push_back(a0);
    for (unsigned k = 1; k < t_; ++k) /* step 2 */
      coeff.push_back(rng.bits(coeff_bits_));

    std::vector<Mpz> y(n_);
    for (unsigned i = 1; i <= n_; ++i) /* steps 3-4, Horner's rule over Z */
    {
      Mpz acc(coeff[t_ - 1]);
      for (unsigned k = t_ - 1; k-- > 0;)
      {
        Mpz::mul(acc, acc, static_cast<unsigned long>(i));
        Mpz::add(acc, acc, coeff[k]);
      }
      y[i - 1] = acc;
    }
    return y;
  }

  /**
   * Lambda_{j,Q} = Delta * l_{j,Q}(0), an exact (possibly negative) integer.
   * Q holds 1-based party ids and must contain j, without duplicates.
   */
  Mpz lagrange_at_zero(const std::vector<unsigned> &Q, unsigned j) const
  {
    if (std::find(Q.begin(), Q.end(), j) == Q.end())
      throw std::invalid_argument("lagrange_at_zero: j is not in Q");
    {
      std::vector<unsigned> sorted(Q);
      std::sort(sorted.begin(), sorted.end());
      if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end())
        throw std::invalid_argument("lagrange_at_zero: Q has duplicates");
    }

    /*
     *   l_{j,Q}(0) = prod_{k in Q, k != j} k / (k - j),   negative once per k < j.
     *
     * Starting from Delta = n! makes every division exact: prod |k - j| divides
     * (j-1)!(n-j)!, which divides n!.
     */
    Mpz L(delta_);
    bool negative = false;
    for (unsigned k : Q)
    {
      if (k == j)
        continue;
      if (k == 0 || k > n_)
        throw std::invalid_argument("lagrange_at_zero: party id out of range");

      unsigned long d;
      if (k > j)
      {
        d = static_cast<unsigned long>(k - j);
      }
      else
      {
        d = static_cast<unsigned long>(j - k);
        negative = !negative;
      }
      Mpz::divexact(L, L, d);
      Mpz::mul(L, L, static_cast<unsigned long>(k));
    }
    if (negative)
      L.neg();
    return L;
  }

  /** sum_{k} Lambda_{Q[k],Q} y[k] = Delta^2 * secret. Self-tests only. */
  Mpz combine_in_Z(const std::vector<unsigned> &Q, const std::vector<Mpz> &y) const
  {
    if (Q.size() != y.size())
      throw std::invalid_argument("combine_in_Z: one share per quorum member");
    if (Q.size() < t_)
      throw std::invalid_argument("combine_in_Z: |Q| < t");

    Mpz sum(0UL);
    for (std::size_t k = 0; k < Q.size(); ++k)
    {
      Mpz term;
      Mpz::mul(term, lagrange_at_zero(Q, Q[k]), y[k]);
      Mpz::add(sum, sum, term);
    }
    return sum;
  }

private:
  static std::size_t bit_length(unsigned x)
  {
    std::size_t b = 0;
    for (; x != 0; x >>= 1)
      ++b;
    return b;
  }

  unsigned n_;
  unsigned t_;
  Mpz delta_;
  Mpz delta2_;
  std::size_t coeff_bits_ = 0;
};

} /* namespace utse */
