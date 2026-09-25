// inproc/InProcUtse2.hpp -- UTSE2 (Figure 10) with the n parties as in-process objects.
#pragma once

#include "core/Utse2Scheme.hpp"

namespace utse {

/** Party P_i for UTSE2: identical role to UTSE1's Party, plus the r'/R' round in Next. */
class Party2
{
public:
  Party2(unsigned id, Mpz share) : id_(id), share_(std::move(share)) {}

  unsigned id() const { return id_; }
  std::uint64_t epoch() const { return epoch_; }

  /** DP.Eval directly on a group element x (no H; Section 4.3). */
  QFI eval(const Utse2Scheme &S, const QFI &x) const { return S.eval(share_, x); }

  void apply_shift(const Mpz &shift_share)
  {
    Utse2Scheme::apply_shift(share_, shift_share);
    ++epoch_;
  }

  const Mpz &share() const { return share_; }

private:
  unsigned id_;
  std::uint64_t epoch_ = 0;
  Mpz share_;
};

class InProcUtse2
{
public:
  explicit InProcUtse2(const Utse2Scheme &S) : S_(S) {}

  std::vector<Party2> setup(Rng &rng) const
  {
    const std::vector<Mpz> shares = S_.setup_shares(rng);
    std::vector<Party2> parties;
    parties.reserve(shares.size());
    for (unsigned i = 1; i <= S_.n(); ++i)
      parties.emplace_back(i, shares[i - 1]);
    return parties;
  }

  /**
   * UTSE.Next: samples delta and r', runs the r'/R' DPRF round against the
   * CURRENT (pre-shift) shares of `quorum_for_R`, then applies the shift to
   * every one of the n parties.
   */
  Token2 next(const std::vector<unsigned> &quorum_for_R, std::vector<Party2> &parties,
             Rng &rng) const
  {
    check_parties(parties);
    S_.check_quorum(quorum_for_R.front(), quorum_for_R);
    const std::uint64_t e = parties.front().epoch();
    for (const Party2 &P : parties)
      if (P.epoch() != e)
        throw std::logic_error("Next: parties are at different epochs");

    const Utse2Scheme::NextBegin nb = S_.next_begin(rng);

    std::vector<QFI> Rparts; /* r_prime^{k_e^(i)}, using the OLD shares */
    Rparts.reserve(quorum_for_R.size());
    for (unsigned i : quorum_for_R)
      Rparts.push_back(parties[i - 1].eval(S_, nb.r_prime));
    const Token2 tok = S_.next_finish(nb, quorum_for_R, Rparts);

    for (Party2 &P : parties) /* delta^(i) to server i, applied after R' is computed */
      P.apply_shift(nb.delta_shares[P.id() - 1]);
    return tok;
  }

  Ciphertext2 enc(unsigned j, const std::vector<Party2> &parties, const std::vector<unsigned> &Q,
                  const Mpz &m, Rng &rng) const
  {
    S_.check_quorum(j, Q);
    const Utse2Scheme::EncState2 st = S_.enc_begin(m, rng);
    return S_.enc_finish(st, dprf_round(parties, Q, st.r));
  }

  std::optional<Mpz> dec(unsigned j, const std::vector<Party2> &parties,
                        const std::vector<unsigned> &Q, const Ciphertext2 &C) const
  {
    S_.check_quorum(j, Q);
    return S_.dec_finish(C, dprf_round(parties, Q, S_.dec_input(C)));
  }

  Ciphertext2 upd(const Token2 &tok, const Ciphertext2 &C) const { return S_.upd(tok, C); }

private:
  QFI dprf_round(const std::vector<Party2> &parties, const std::vector<unsigned> &Q,
                 const QFI &x) const
  {
    check_parties(parties);
    const std::uint64_t e = parties[Q.front() - 1].epoch();
    std::vector<QFI> z;
    z.reserve(Q.size());
    for (unsigned i : Q)
    {
      const Party2 &P = parties[i - 1];
      if (P.epoch() != e)
        throw std::logic_error("quorum members are at different epochs");
      z.push_back(P.eval(S_, x));
    }
    return S_.combine(Q, z);
  }

  void check_parties(const std::vector<Party2> &parties) const
  {
    if (parties.size() != S_.n())
      throw std::invalid_argument("expected exactly n parties");
    for (std::size_t k = 0; k < parties.size(); ++k)
      if (parties[k].id() != k + 1)
        throw std::invalid_argument("parties must be ordered by id 1..n");
  }

  const Utse2Scheme &S_;
};

} /* namespace utse */
