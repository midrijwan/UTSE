// core/Utse2Scheme.hpp -- UTSE2 (Figure 10): unlinkable, but not authentic.
//
// Differences from UTSE1 (Section 4.3 / Remark 6), all consequences of one
// design choice: no client identity and no commitment are carried in the
// ciphertext.
//
//   Ciphertext  C_e = (r, c_e)                  -- two components, not three;
//                                                   no j, no alpha (unlinkable)
//   Enc/Dec     m in Z_q directly                -- no Encode/Decode, no rho
//   Dec         one gate only: c_e * w^-1 in F_CL
//               (no commitment -> a forged m' is undetectable; Remark 6)
//   DPRF input  a fresh random r <- G^q_CL       -- no H at all (Section 4.3:
//                                                   "the DPRF is evaluated
//                                                   instead on a freshly
//                                                   sampled random value")
//   Next        also runs one DPRF round on a fresh r', producing R' -- this
//               extra step is what lets Upd re-randomise the base later
//
// Figure 10's own Upd line prints "Parse Ce = (j, r, ce)", left over from
// UTSE1's three-part header; Enc's own line just above it defines
// Ce := (r, ce). This file follows Enc's definition (two components).
//
// The Delta^2 scaling issue is the same as UTSE1's (core/IntegerSSS.hpp,
// README Sec. 4.2): Combine always returns an exponent scaled by Delta^2.
// Token2::R comes directly out of Combine, so it is already correctly
// scaled -- nothing to do there. Token2::delta is the raw sampled shift, and
// wherever Upd uses it directly as an exponent (not through Combine), it
// needs the same Delta^2 multiplier UTSE1's Upd needed, for the identical
// reason: it has to match the scale Combine produces everywhere else.
#pragma once

#include <optional>

#include "core/ClContext.hpp"
#include "core/IntegerSSS.hpp"
#include "core/Rng.hpp"

namespace utse {

/** C_e = (r, c_e). Unlike UTSE1, there is no header: this is why UTSE2 is unlinkable. */
struct Ciphertext2
{
  QFI r;
  QFI c;
};

inline bool operator==(const Ciphertext2 &a, const Ciphertext2 &b)
{
  return a.r == b.r && a.c == b.c;
}

/** Delta_{e+1} = (delta_{e+1}, R', r'). */
struct Token2
{
  Mpz delta;   /* raw shift, as sampled -- scaled by Delta^2 where Upd uses it directly */
  QFI R;       /* Combine(...) over the OLD k_e shares, evaluated at r_prime; already Delta^2 * k_e */
  QFI r_prime; /* the fresh base used to produce R */
};

class Utse2Scheme
{
public:
  Utse2Scheme(const ClContext &ctx, unsigned n, unsigned t)
      : ctx_(ctx), n_(n), t_(t), sss_(n, t, ctx.Dq_bound().nbits())
  {
  }

  Utse2Scheme(const Utse2Scheme &) = delete;
  Utse2Scheme &operator=(const Utse2Scheme &) = delete;

  const ClContext &ctx() const { return ctx_; }
  const IntegerSSS &sss() const { return sss_; }
  unsigned n() const { return n_; }
  unsigned t() const { return t_; }

  void check_quorum(unsigned j, const std::vector<unsigned> &Q) const
  {
    if (Q.size() < t_)
      throw std::invalid_argument("quorum smaller than the threshold t");
    std::vector<unsigned> s(Q);
    std::sort(s.begin(), s.end());
    if (std::adjacent_find(s.begin(), s.end()) != s.end())
      throw std::invalid_argument("quorum lists a party twice");
    if (s.front() == 0 || s.back() > n_)
      throw std::invalid_argument("quorum names a party outside 1..n");
    if (!std::binary_search(s.begin(), s.end(), j))
      throw std::invalid_argument("the client must belong to its quorum (Definition 6: j in Q)");
  }

  /* ---- UTSE.Setup: identical to UTSE1's -------------------------------- */
  std::vector<Mpz> setup_shares(Rng &rng) const
  {
    const Mpz k0 = ctx_.sample_Dq(rng);
    return sss_.share(k0, rng);
  }

  /** DP.Eval, directly on a group element -- no H (Section 4.3). */
  QFI eval(const Mpz &k_i, const QFI &x) const { return ctx_.pow(x, k_i); }

  /** DP.Combine (same Lagrange machinery as UTSE1's; there is no H to feed it). */
  QFI combine(const std::vector<unsigned> &Q, const std::vector<QFI> &z) const
  {
    if (Q.size() != z.size())
      throw std::invalid_argument("Combine: need one partial evaluation per quorum member");
    if (Q.size() < t_)
      throw std::invalid_argument("Combine: |Q| < t");
    QFI w = ctx_.one();
    for (std::size_t k = 0; k < Q.size(); ++k)
      w = ctx_.mul(w, ctx_.pow(z[k], sss_.lagrange_at_zero(Q, Q[k])));
    return w;
  }

  /* ---- UTSE.Next: k-share update, plus the extra r'/R' DPRF round -------
   *   next_begin  : sample delta and r', deal delta's shares
   *   [send delta^(i) and r' to server i; each returns h_i := r'^{k^(i)_e}]
   *   next_finish : Combine the h_i into R', return the token
   *   apply_shift : the server's local half, same as UTSE1's               */
  struct NextBegin
  {
    Mpz delta_raw;
    std::vector<Mpz> delta_shares; /* delta_shares[i-1] -> party i */
    QFI r_prime;
  };

  NextBegin next_begin(Rng &rng) const
  {
    NextBegin nb;
    nb.delta_raw = ctx_.sample_Dq(rng);
    nb.delta_shares = sss_.share(nb.delta_raw, rng);
    nb.r_prime = ctx_.sample_Gq(rng);
    return nb;
  }

  /** Q, Rparts: the quorum that evaluated r_prime under the OLD (pre-shift) shares. */
  Token2 next_finish(const NextBegin &nb, const std::vector<unsigned> &Q,
                     const std::vector<QFI> &Rparts) const
  {
    Token2 tok;
    tok.delta = nb.delta_raw;
    tok.R = combine(Q, Rparts); /* r_prime^{Delta^2 * k_e} */
    tok.r_prime = nb.r_prime;
    return tok;
  }

  static void apply_shift(Mpz &share, const Mpz &shift_share)
  {
    Mpz::add(share, share, shift_share);
  }

  /* ---- UTSE.Enc: m in Z_q directly, no Encode, no rho, no commitment ---- */
  struct EncState2
  {
    Mpz m;
    QFI r;
  };

  EncState2 enc_begin(const Mpz &m, Rng &rng) const
  {
    if (m.sgn() < 0 || m >= ctx_.q())
      throw std::invalid_argument("Enc: m must be an element of Z_q, i.e. 0 <= m < q");
    EncState2 s;
    s.m = m;
    s.r = ctx_.sample_Gq(rng);
    return s;
  }

  Ciphertext2 enc_finish(const EncState2 &s, const QFI &w) const
  {
    Ciphertext2 C;
    C.r = s.r;
    C.c = ctx_.mul(ctx_.f_pow(s.m), w);
    return C;
  }

  /* ---- UTSE.Dec: one gate only (Remark 6: no commitment => no gate 3) --- */
  const QFI &dec_input(const Ciphertext2 &C) const { return C.r; }

  std::optional<Mpz> dec_finish(const Ciphertext2 &C, const QFI &w) const
  {
    if (!ctx_.in_group(C.c) || !ctx_.in_group(C.r))
      return std::nullopt;
    return ctx_.solve(ctx_.div(C.c, w)); /* structural gate: c*w^-1 in F_CL, then Solve */
  }

  /* ---- UTSE.Upd: run by the host, public parameters only ----------------
   * Ce+1 := (r * r', ce * r^{Delta^2 delta} * R' * r'^{Delta^2 delta})       */
  Ciphertext2 upd(const Token2 &tok, const Ciphertext2 &C) const
  {
    Mpz scaled_delta;
    Mpz::mul(scaled_delta, tok.delta, sss_.delta2());

    Ciphertext2 out;
    out.r = ctx_.mul(C.r, tok.r_prime);

    QFI acc = ctx_.mul(C.c, ctx_.pow(C.r, scaled_delta)); /* c_e * r^{Delta^2 delta} */
    acc = ctx_.mul(acc, tok.R);                           /* * R' (already scaled)  */
    acc = ctx_.mul(acc, ctx_.pow(tok.r_prime, scaled_delta)); /* * r'^{Delta^2 delta} */
    out.c = acc;
    return out;
  }

private:
  const ClContext &ctx_;
  unsigned n_;
  unsigned t_;
  IntegerSSS sss_;
};

} /* namespace utse */
