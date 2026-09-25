// core/Dprf.hpp -- Figure 1: the distributed PRF in the class group.
//
//   Setup   : k <- D_q, (k_1, ..., k_n) <- SSS(n, t, k)   (Utse1Scheme::setup_shares)
//   Eval    : h_i := H(x)^{k_i}
//   Combine : w := prod_{i in Q} h_i^{Lambda_{i,Q}}       (bottom if |Q| < t)
//
// Figure 1 writes the coefficients as "lambda_{i,Q} (mod p)". There is no p,
// and nothing can be reduced in a group of unknown order: here Lambda_{i,Q} =
// Delta * l_{i,Q}(0) are exact integers, and because Protocol 1 also scales the
// secret by Delta, Combine returns w = H(x)^{Delta^2 k} for every quorum.
// README 6.2 explains why this is consistent with Upd.
#pragma once

#include "core/ClContext.hpp"
#include "core/HashToGq.hpp"
#include "core/IntegerSSS.hpp"

namespace utse {

class Dprf
{
public:
  Dprf(const ClContext &ctx, const IntegerSSS &sss, const HashToGq &H)
      : ctx_(ctx), sss_(sss), H_(H)
  {
  }

  /** Eval(k_i, x): the partial evaluation a server returns. */
  QFI eval(const Mpz &k_i, const Bytes &x) const { return ctx_.pow(H_(x), k_i); }

  /** Lambda_{i,Q} for every i in Q, in the order of Q. Throws if |Q| < t. */
  std::vector<Mpz> lagrange(const std::vector<unsigned> &Q) const
  {
    if (Q.size() < sss_.t())
      throw std::invalid_argument("DPRF Combine: |Q| < t (Figure 1 outputs bottom)");
    std::vector<Mpz> L;
    L.reserve(Q.size());
    for (unsigned i : Q)
      L.push_back(sss_.lagrange_at_zero(Q, i));
    return L;
  }

  /** Combine: z[k] is the partial evaluation of party Q[k]. */
  QFI combine(const std::vector<unsigned> &Q, const std::vector<QFI> &z) const
  {
    return combine_with(lagrange(Q), z);
  }

  /** Combine with precomputed coefficients (one quorum, many inputs). */
  QFI combine_with(const std::vector<Mpz> &L, const std::vector<QFI> &z) const
  {
    if (L.size() != z.size())
      throw std::invalid_argument("DPRF Combine: need one partial evaluation per quorum member");
    QFI w = ctx_.one();
    for (std::size_t k = 0; k < z.size(); ++k)
      w = ctx_.mul(w, ctx_.pow(z[k], L[k]));
    return w;
  }

private:
  const ClContext &ctx_;
  const IntegerSSS &sss_;
  const HashToGq &H_;
};

} /* namespace utse */
