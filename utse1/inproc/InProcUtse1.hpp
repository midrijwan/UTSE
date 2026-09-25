// inproc/InProcUtse1.hpp -- UTSE1 (Figure 9) with the n parties as in-process objects.
//
// A "message" from a client to a server is a function call carrying exactly the
// value Figure 9 says is sent (j||alpha for Eval, delta^(i) for Next); the reply
// is exactly the value that comes back (h_i). Parties share nothing else.
#pragma once

#include "core/Utse1Scheme.hpp"

namespace utse {

/** Party P_i: holds only its share of the current epoch key. */
class Party
{
public:
  Party(unsigned id, Mpz share) : id_(id), share_(std::move(share)) {}

  unsigned id() const { return id_; }
  std::uint64_t epoch() const { return epoch_; }

  /** Figure 1 Eval on the received x = j||alpha: h_i = H(x)^{k^(i)_e}. */
  QFI eval(const Dprf &dprf, const Bytes &x) const { return dprf.eval(share_, x); }

  /** Local half of Next: k^(i)_{e+1} <- k^(i)_e + delta^(i)_{e+1} (over Z). */
  void apply_shift(const Mpz &shift_share)
  {
    Utse1Scheme::apply_shift(share_, shift_share);
    ++epoch_;
  }

  const Mpz &share() const { return share_; } /* inspection / benchmarks only */

private:
  unsigned id_;
  std::uint64_t epoch_ = 0;
  Mpz share_;
};

class InProcUtse1
{
public:
  explicit InProcUtse1(const Utse1Scheme &S) : S_(S) {}

  /** UTSE.Setup with a trusted dealer (Definition 6). */
  std::vector<Party> setup(Rng &rng) const
  {
    const std::vector<Mpz> shares = S_.setup_shares(rng);
    std::vector<Party> parties;
    parties.reserve(shares.size());
    for (unsigned i = 1; i <= S_.n(); ++i)
      parties.emplace_back(i, shares[i - 1]);
    return parties;
  }

  /** UTSE.Next invoked by `invoker`; every party updates; returns the token. */
  Token next(unsigned invoker, std::vector<Party> &parties, Rng &rng) const
  {
    check_parties(parties);
    if (invoker == 0 || invoker > S_.n())
      throw std::invalid_argument("Next: invoking party out of range");
    const std::uint64_t e = parties.front().epoch();
    for (const Party &P : parties)
      if (P.epoch() != e)
        throw std::logic_error("Next: parties are at different epochs");

    const Utse1Scheme::ShiftDeal deal = S_.next_deal(rng); /* by the invoker   */
    for (Party &P : parties)                              /* delta^(i) to P_i */
      P.apply_shift(deal.shares[P.id() - 1]);
    return deal.token;
  }

  Ciphertext enc(unsigned j, const std::vector<Party> &parties, const std::vector<unsigned> &Q,
                 const Bytes &m, Rng &rng) const
  {
    S_.check_quorum(j, Q);
    const Utse1Scheme::EncState st = S_.enc_begin(j, m, rng);
    return S_.enc_finish(st, dprf_round(parties, Q, st.x));
  }

  std::optional<Bytes> dec(unsigned j, const std::vector<Party> &parties,
                           const std::vector<unsigned> &Q, const Ciphertext &C) const
  {
    S_.check_quorum(j, Q);
    return S_.dec_finish(C, dprf_round(parties, Q, S_.dec_input(C)));
  }

  Ciphertext upd(const Token &tok, const Ciphertext &C) const { return S_.upd(tok, C); }

private:
  /** Send x to every i in Q, collect h_i, Combine. */
  QFI dprf_round(const std::vector<Party> &parties, const std::vector<unsigned> &Q,
                 const Bytes &x) const
  {
    check_parties(parties);
    const std::uint64_t e = parties[Q.front() - 1].epoch();
    std::vector<QFI> z;
    z.reserve(Q.size());
    for (unsigned i : Q)
    {
      const Party &P = parties[i - 1];
      if (P.epoch() != e)
        throw std::logic_error("quorum members are at different epochs");
      z.push_back(P.eval(S_.dprf(), x));
    }
    return S_.dprf().combine(Q, z);
  }

  void check_parties(const std::vector<Party> &parties) const
  {
    if (parties.size() != S_.n())
      throw std::invalid_argument("expected exactly n parties");
    for (std::size_t k = 0; k < parties.size(); ++k)
      if (parties[k].id() != k + 1)
        throw std::invalid_argument("parties must be ordered by id 1..n");
  }

  const Utse1Scheme &S_;
};

} /* namespace utse */
