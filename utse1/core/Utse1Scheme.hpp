// core/Utse1Scheme.hpp -- UTSE1 (Figure 9): everything that is not communication.
//
// Both front ends (inproc/ and net/) run the protocol through this class, so
// the cryptography exists exactly once and the two variants differ only in how
// a value travels between parties. The interactive steps of Figure 9 are split
// where the client talks to the quorum:
//
//   Setup  setup_shares                                         (trusted dealer, Def. 6)
//   Next   next_deal  -> [delta^(i) to each server i]  -> apply_shift
//   Enc    enc_begin  -> [j||alpha to Q; h_i back; Combine] -> enc_finish
//   Dec    dec_input  -> [j||alpha to Q; h_i back; Combine] -> dec_finish
//   Upd    upd                                                  (host: no key, no interaction)
#pragma once

#include <algorithm>
#include <optional>

#include "core/ClContext.hpp"
#include "core/Commitment.hpp"
#include "core/Dprf.hpp"
#include "core/Encode.hpp"
#include "core/HashToGq.hpp"
#include "core/IntegerSSS.hpp"
#include "core/Rng.hpp"

namespace utse {

/** C_e = (j, alpha, c_e). The header (j, alpha) is invariant under Upd. */
struct Ciphertext
{
  unsigned j = 0;
  Bytes alpha;
  QFI c;
};

inline bool operator==(const Ciphertext &a, const Ciphertext &b)
{
  return a.j == b.j && a.alpha == b.alpha && a.c == b.c;
}

/** The update token of UTSE1: a single scalar, Delta_{e+1} = delta_{e+1}. */
struct Token
{
  Mpz shift;
};

class Utse1Scheme
{
public:
  static constexpr const char *kHashDst = "UTSE1/DPRF/H";

  /**
   * @param ctx     class-group parameters (must outlive this object)
   * @param n, t    t-out-of-n
   * @param mu      Figure 11's mu: messages and openings are mu/2 bits each
   * @param com_pp  output of Com.Setup
   */
  Utse1Scheme(const ClContext &ctx, unsigned n, unsigned t, std::size_t mu, Bytes com_pp)
      : ctx_(ctx), n_(n), t_(t), com_pp_(std::move(com_pp)), H_(ctx, kHashDst),
        encoder_(ctx, mu), sss_(n, t, ctx.Dq_bound().nbits()), dprf_(ctx, sss_, H_)
  {
    if (com_pp_.empty())
      throw std::invalid_argument("Utse1Scheme: empty commitment parameters");
    fingerprint_ = compute_fingerprint();
  }

  Utse1Scheme(const Utse1Scheme &) = delete;
  Utse1Scheme &operator=(const Utse1Scheme &) = delete;

  /* ---- public parameters -------------------------------------------------- */
  const ClContext &ctx() const { return ctx_; }
  const IntegerSSS &sss() const { return sss_; }
  const Dprf &dprf() const { return dprf_; }
  const Encode &encoder() const { return encoder_; }
  unsigned n() const { return n_; }
  unsigned t() const { return t_; }
  std::size_t mu() const { return encoder_.mu(); }
  std::size_t slot_bytes() const { return encoder_.slot_bytes(); }
  const Bytes &com_pp() const { return com_pp_; }
  /** SHAKE256 of every public parameter; parties compare it before talking. */
  const Bytes &fingerprint() const { return fingerprint_; }
  QFI hash(const Bytes &x) const { return H_(x); }

  /** The DPRF input j || alpha (j as 4 bytes, big endian; alpha is fixed-length). */
  static Bytes header(unsigned j, const Bytes &alpha)
  {
    Bytes h = u32be(static_cast<std::uint32_t>(j));
    append(h, alpha);
    return h;
  }

  /**
   * Definition 6: a client j runs Enc/Dec with a quorum Q, |Q| >= t, j in Q.
   * Throws std::invalid_argument (a caller error, not the scheme's bottom).
   */
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

  /* ---- UTSE.Setup ------------------------------------------------------------
   * k_0 <- D_q;  (k_0^(1), ..., k_0^(n)) <- SSS(n, t, k_0).                    */
  std::vector<Mpz> setup_shares(Rng &rng) const
  {
    const Mpz k0 = ctx_.sample_Dq(rng);
    return sss_.share(k0, rng);
  }

  /* ---- UTSE.Next -------------------------------------------------------------
   * The invoking party samples delta_{e+1} <- D_q, deals SSS(n, t, delta_{e+1}),
   * sends delta^(i) to each server i, and sets Delta_{e+1} <- delta_{e+1}.      */
  struct ShiftDeal
  {
    Token token;
    std::vector<Mpz> shares; /* shares[i-1] goes to party i */
  };

  ShiftDeal next_deal(Rng &rng) const
  {
    ShiftDeal d;
    d.token.shift = ctx_.sample_Dq(rng);
    d.shares = sss_.share(d.token.shift, rng);
    return d;
  }

  /** Server side of Next: k^(i)_{e+1} <- k^(i)_e + delta^(i)_{e+1}, over Z (README 6.1). */
  static void apply_shift(Mpz &share, const Mpz &shift_share)
  {
    Mpz::add(share, share, shift_share);
  }

  /* ---- UTSE.Enc ------------------------------------------------------------ */
  struct EncState
  {
    unsigned j = 0;
    Bytes m;
    Bytes rho;
    Bytes alpha;
    Bytes x; /* j || alpha: what the client sends to Q */
  };

  /** Step 1: rho <- {0,1}^{mu/2}, alpha := Commit(m; rho), x := j || alpha. */
  EncState enc_begin(unsigned j, const Bytes &m, Rng &rng) const
  {
    if (m.size() != slot_bytes())
      throw std::invalid_argument("Enc: the message must be exactly mu/2 bits ("
                                  + std::to_string(slot_bytes()) + " bytes)");
    EncState s;
    s.j = j;
    s.m = m;
    s.rho = rng.bytes(slot_bytes());
    s.alpha = Commitment::commit(com_pp_, s.m, s.rho);
    s.x = header(j, s.alpha);
    return s;
  }

  /** Step 3, after Combine returned w: c_e := f^{Encode(m, rho)} * w. */
  Ciphertext enc_finish(const EncState &s, const QFI &w) const
  {
    Ciphertext C;
    C.j = s.j;
    C.alpha = s.alpha;
    C.c = ctx_.mul(ctx_.f_pow(encoder_.encode(s.m, s.rho)), w);
    return C;
  }

  /* ---- UTSE.Dec ------------------------------------------------------------ */
  /** Step 1: the client sends j || alpha to Q. */
  Bytes dec_input(const Ciphertext &C) const { return header(C.j, C.alpha); }

  /**
   * Steps 2-3, after Combine returned w. nullopt is the scheme's bottom; it is
   * returned at three separate gates (README 6.6).
   */
  std::optional<Bytes> dec_finish(const Ciphertext &C, const QFI &w) const
  {
    if (C.alpha.size() != Commitment::kOutBytes || !ctx_.in_group(C.c))
      return std::nullopt;

    /* gate 1 (structural): c * w^-1 must lie in F_CL; then Solve */
    const std::optional<Mpz> z = ctx_.solve(ctx_.div(C.c, w));
    if (!z)
      return std::nullopt;

    /* gate 2 (encoding): Decode rejects anything >= 2^mu */
    Bytes m;
    Bytes rho;
    if (!encoder_.decode(*z, m, rho))
      return std::nullopt;

    /* gate 3 (commitment): alpha = Com(m; rho) */
    if (Commitment::commit(com_pp_, m, rho) != C.alpha)
      return std::nullopt;
    return m;
  }

  /* ---- UTSE.Upd ------------------------------------------------------------
   * Run by the host with public parameters only:
   *   C_{e+1} := (j, alpha, c_e * H(j||alpha)^{Delta^2 * delta_{e+1}}).
   * Figure 9 prints the exponent as delta_{e+1}; the Delta^2 matches what
   * Combine reconstructs (README 6.2). Delta = n! is public, so the token is
   * still the single scalar delta_{e+1}.                                        */
  Ciphertext upd(const Token &tok, const Ciphertext &C) const
  {
    Mpz e;
    Mpz::mul(e, tok.shift, sss_.delta2());
    Ciphertext out = C;
    out.c = ctx_.mul(C.c, ctx_.pow(H_(header(C.j, C.alpha)), e));
    return out;
  }

private:
  Bytes compute_fingerprint() const
  {
    Shake256 h;
    h.update_framed(std::string("UTSE1-pp-v1"));
    h.update_framed(static_cast<Bytes>(ctx_.q()));
    h.update_framed(static_cast<Bytes>(ctx_.p()));
    h.update(u32be(n_));
    h.update(u32be(t_));
    h.update(u32be(static_cast<std::uint32_t>(encoder_.mu())));
    h.update_framed(com_pp_);
    h.update_framed(H_.dst());
    h.update(u32be(static_cast<std::uint32_t>(H_.prime_bits())));
    return h.finalize(32);
  }

  const ClContext &ctx_;
  unsigned n_;
  unsigned t_;
  Bytes com_pp_;
  HashToGq H_;
  Encode encoder_;
  IntegerSSS sss_;
  Dprf dprf_;
  Bytes fingerprint_;
};

} /* namespace utse */
