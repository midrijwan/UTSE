// common/Scenario.hpp -- the test scenario and benchmark shared by both variants.
//
// The in-process and the networked front end each implement Backend; the very
// same checks and the very same benchmark then run on both, so a difference in
// outcome can only come from how values travel, never from the tests.
#pragma once

#include <iomanip>
#include <optional>

#include "common/Report.hpp"
#include "core/StorageHost.hpp"
#include "core/Utse1Scheme.hpp"
#include "core/Wire.hpp"

namespace utse {
namespace scenario {

/** One way of running Figure 9's protocols. Party ids are 1-based. */
class Backend
{
public:
  virtual ~Backend() = default;

  /** UTSE.Enc by client j with quorum Q (j in Q). */
  virtual Ciphertext enc(unsigned j, const std::vector<unsigned> &Q, const Bytes &m) = 0;
  virtual std::vector<Ciphertext> enc_batch(unsigned j, const std::vector<unsigned> &Q,
                                            const std::vector<Bytes> &ms) = 0;
  /** UTSE.Dec by client j with quorum Q; nullopt is bottom. */
  virtual std::optional<Bytes> dec(unsigned j, const std::vector<unsigned> &Q,
                                   const Ciphertext &C) = 0;
  virtual std::vector<std::optional<Bytes>> dec_batch(unsigned j, const std::vector<unsigned> &Q,
                                                      const std::vector<Ciphertext> &Cs) = 0;
  /** UTSE.Next invoked by party `invoker`; returns the token for the host. */
  virtual Token next(unsigned invoker) = 0;
  /** Current epoch of every party, party 1 first. */
  virtual std::vector<std::uint64_t> epochs() const = 0;

  /** Optional per-phase annotation (the networked variant reports bytes on the wire). */
  virtual void begin_phase() {}
  virtual std::string end_phase(std::size_t /*ops*/) { return {}; }
};

inline Bytes pattern(std::size_t len, unsigned char base)
{
  Bytes m(len);
  for (std::size_t i = 0; i < len; ++i)
    m[i] = static_cast<unsigned char>(base + i);
  return m;
}

/* -------------------------------------------------------------------------- */
/* Building blocks, independent of any backend                                 */
/* -------------------------------------------------------------------------- */
inline void run_core_checks(const Utse1Scheme &S, Rng &rng, report::Checker &check)
{
  using report::window;
  const ClContext &ctx = S.ctx();
  const unsigned n = S.n();
  const unsigned t = S.t();

  std::cout << "\n== building blocks ==\n";

  { /* Appendix A.3 */
    const IntegerSSS &sss = S.sss();
    const Mpz s = ctx.sample_Dq(rng);
    const std::vector<Mpz> y = sss.share(s, rng);
    Mpz expect;
    Mpz::mul(expect, s, sss.delta2());
    auto recon = [&](const std::vector<unsigned> &Q) {
      std::vector<Mpz> yq;
      for (unsigned i : Q)
        yq.push_back(y[i - 1]);
      return sss.combine_in_Z(Q, yq);
    };
    check(recon(window(1, t, n)) == expect && recon(window(n - t + 1, t, n)) == expect
              && recon(window(1, n, n)) == expect,
          "Appendix A.3: sum_j Lambda_j y_j = Delta^2 * secret over Z, for three quorums");
  }

  { /* Figure 11 */
    const Encode &E = S.encoder();
    const Bytes u = pattern(S.slot_bytes(), 0x10);
    const Bytes v = pattern(S.slot_bytes(), 0x80);
    Bytes u2;
    Bytes v2;
    const bool round_trip = E.decode(E.encode(u, v), u2, v2) && u2 == u && v2 == v;
    Mpz big;
    Mpz::mulby2k(big, 1UL, static_cast<mp_bitcnt_t>(E.mu()));
    Bytes a;
    Bytes b;
    check(round_trip && !E.decode(big, a, b),
          "Figure 11: Decode(Encode(u, v)) = (u, v), and Decode(2^mu) = bottom");
  }

  { /* H */
    const Bytes x1{1};
    const Bytes x2{2};
    const QFI h1 = S.hash(x1);
    check(h1 == S.hash(x1) && !(h1 == S.hash(x2)) && ctx.in_group(h1) && !ctx.in_F(h1),
          "H: deterministic, input-dependent, lands in Cl(Delta) and outside F_CL");
  }

  { /* the public parameters really are (q, p, n, t, mu, com_pp) */
    ClContext ctx2(ctx.q(), ctx.p());
    Utse1Scheme S2(ctx2, n, t, S.mu(), S.com_pp());
    const Bytes x{7, 7, 7};
    check(ctx2.disc() == ctx.disc() && S2.fingerprint() == S.fingerprint()
              && S2.hash(x) == S.hash(x),
          "pp rebuilt from (q, p, n, t, mu, com_pp) alone: same Delta, fingerprint and H");
  }
}

/* -------------------------------------------------------------------------- */
/* Figure 9 end to end                                                         */
/* -------------------------------------------------------------------------- */
inline void run_protocol_checks(Backend &B, const Utse1Scheme &S, report::Checker &check)
{
  using report::ids;
  using report::throws;
  using report::window;

  const ClContext &ctx = S.ctx();
  const unsigned n = S.n();
  const unsigned t = S.t();

  const std::vector<unsigned> Qa = window(1, t, n);         /* client 1      */
  const std::vector<unsigned> Qb = window(n - t + 1, t, n); /* the last t    */
  const std::vector<unsigned> Qm = window(n / 2 + 1, t, n); /* from the middle */
  const std::vector<unsigned> Qall = window(1, n, n);       /* |Q| = n > t   */
  const unsigned ja = Qa.front();
  const unsigned jb = Qb.front();
  const unsigned jm = Qm.front();
  const unsigned jall = Qall[n / 2];

  auto who = [](unsigned j, const std::vector<unsigned> &Q) {
    return "party " + std::to_string(j) + ", Q=" + ids(Q);
  };
  auto dec_is = [&](unsigned j, const std::vector<unsigned> &Q, const Ciphertext &C,
                    const Bytes &expect) {
    const std::optional<Bytes> out = B.dec(j, Q, C);
    return out.has_value() && *out == expect;
  };
  auto rejected = [&](unsigned j, const std::vector<unsigned> &Q, const Ciphertext &C) {
    return !B.dec(j, Q, C).has_value();
  };

  const Bytes m = pattern(S.slot_bytes(), 0xA0);
  const Bytes zeros(S.slot_bytes(), 0x00);
  const Bytes ones(S.slot_bytes(), 0xFF);

  /* ---- epoch 0 -------------------------------------------------------------- */
  std::cout << "\n== epoch 0: Enc / Dec ==\n";
  const Ciphertext C0 = B.enc(ja, Qa, m);
  check(dec_is(ja, Qa, C0, m), "Enc by " + who(ja, Qa) + "; Dec by the same quorum");
  check(dec_is(jb, Qb, C0, m), "Dec by " + who(jb, Qb) + " (another client, another quorum)");
  check(dec_is(jall, Qall, C0, m), "Dec by " + who(jall, Qall) + " (|Q| > t)");

  const Ciphertext Cz = B.enc(jm, Qm, zeros);
  const Ciphertext C1 = B.enc(jm, Qm, ones);
  check(dec_is(ja, Qa, Cz, zeros) && dec_is(ja, Qa, C1, ones),
        "edge messages 00..00 and FF..FF round-trip");

  std::vector<Bytes> batch;
  for (unsigned k = 0; k < 4; ++k)
    batch.push_back(pattern(S.slot_bytes(), static_cast<unsigned char>(0x20 * k + 1)));
  const std::vector<Ciphertext> Cbatch = B.enc_batch(jb, Qb, batch);
  const std::vector<std::optional<Bytes>> outs = B.dec_batch(ja, Qa, Cbatch);
  bool batch_ok = outs.size() == batch.size();
  for (std::size_t k = 0; batch_ok && k < batch.size(); ++k)
    batch_ok = outs[k].has_value() && *outs[k] == batch[k];
  check(batch_ok, "batch of 4: Enc by " + who(jb, Qb) + ", Dec by " + who(ja, Qa));

  {
    Writer w;
    w.ciphertext(C0);
    const Bytes wire = w.take();
    Reader r(wire);
    const Ciphertext back = r.ciphertext(ctx);
    r.expect_end();
    check(back == C0, "a ciphertext serialises and parses back unchanged ("
                          + std::to_string(wire.size()) + " bytes)");
  }

  /* ---- rotations ------------------------------------------------------------ */
  std::cout << "\n== three rotations: Next, then Upd at the storage host ==\n";
  StorageHost host(S);
  host.put(C0);
  host.put(Cz);
  host.put(C1);
  for (const Ciphertext &C : Cbatch)
    host.put(C);

  const unsigned invokers[3] = {window(2, 1, n)[0], n, window(3, 1, n)[0]};
  for (unsigned e = 1; e <= 3; ++e)
  {
    report::Stopwatch sw;
    const Token tok = B.next(invokers[e - 1]);
    const double t_next = sw.ms();
    sw.reset();
    host.rotate(tok);
    std::cout << "  epoch " << e << ": Next invoked by party " << invokers[e - 1] << " ("
              << t_next << " ms); token " << tok.shift.nbits() << " bits; host updated "
              << host.size() << " records in " << sw.ms() << " ms\n";
  }

  bool at3 = host.epoch() == 3;
  for (std::uint64_t e : B.epochs())
    at3 = at3 && e == 3;
  check(at3, "all n parties and the host are at epoch 3");

  const Ciphertext &C3 = host.get(0);
  check(C3.j == C0.j && C3.alpha == C0.alpha && !(C3.c == C0.c),
        "Upd rewrites c only; the header (j, alpha) is invariant, so UTSE1 is linkable "
        "(Remark 4)");
  check(dec_is(jm, Qm, C3, m), "record updated 3 times decrypts at epoch 3, " + who(jm, Qm));

  bool rest = dec_is(jb, Qb, host.get(1), zeros) && dec_is(jb, Qb, host.get(2), ones);
  for (std::size_t k = 0; k < batch.size(); ++k)
    rest = rest && dec_is(jb, Qb, host.get(3 + k), batch[k]);
  check(rest, "every other stored record decrypts at epoch 3 as well");

  const Ciphertext Cf = B.enc(jb, Qb, m);
  check(dec_is(ja, Qa, Cf, m), "fresh encryption at epoch 3 decrypts");
  check(rejected(ja, Qa, C0), "stale epoch-0 ciphertext is rejected at epoch 3");

  /* ---- Dec's gates ---------------------------------------------------------- */
  std::cout << "\n== Dec's rejection gates (epoch 3) ==\n";
  {
    Ciphertext X = C3;
    X.c = ctx.mul(X.c, ctx.f_pow(Mpz(1UL)));
    check(rejected(ja, Qa, X), "c * f: stays in F_CL, Decode passes, the commitment check rejects");
  }
  {
    Ciphertext X = C3;
    X.c = ctx.mul(X.c, HashToGq(ctx, "UTSE1/test/tamper")(Bytes{1, 2, 3}));
    check(rejected(ja, Qa, X), "c * g, g in G^q_CL: c * w^-1 leaves F_CL, the structural check rejects");
  }
  {
    Ciphertext X = C3;
    X.alpha[0] = static_cast<unsigned char>(X.alpha[0] ^ 0x01u);
    check(rejected(ja, Qa, X), "alpha with one bit flipped is rejected");
  }
  {
    Ciphertext X = C3;
    X.j = (X.j % n) + 1;
    check(rejected(ja, Qa, X), "header re-attributed to another client j is rejected");
  }
  {
    Ciphertext X = C3;
    X.alpha.pop_back();
    check(rejected(ja, Qa, X), "truncated alpha is rejected");
  }

  /* ---- misuse ---------------------------------------------------------------- */
  std::cout << "\n== misuse is refused ==\n";
  check(throws([&] { B.enc(ja, window(1, t - 1, n), m); }), "|Q| < t");
  if (n > t)
    check(throws([&] { B.enc(n, Qa, m); }), "client not in its own quorum (Definition 6: j in Q)");
  if (t >= 2)
  {
    std::vector<unsigned> Qdup = Qa;
    Qdup.back() = Qdup.front();
    check(throws([&] { B.enc(ja, Qdup, m); }), "a party listed twice in Q");
  }
  {
    std::vector<unsigned> Qout = Qa;
    Qout.push_back(n + 1);
    check(throws([&] { B.enc(ja, Qout, m); }), "a party id outside 1..n");
  }
  check(throws([&] { B.enc(ja, Qa, Bytes(S.slot_bytes() + 1, 0x00)); }),
        "a message that is not exactly mu/2 bits");
}

/* -------------------------------------------------------------------------- */
/* Benchmark, organised like DiSE's frontend eval(): latency, then batches     */
/* -------------------------------------------------------------------------- */
inline void run_benchmark(Backend &B, const Utse1Scheme &S, unsigned j,
                          const std::vector<unsigned> &Q, unsigned trials, unsigned batch)
{
  std::cout << "\n== benchmark: party " << j << " initiates, Q=" << report::ids(Q) << ", "
            << trials << " trials, batch " << batch << " ==\n";

  auto line = [](const std::string &label, double total_ms, std::size_t ops,
                 const std::string &extra) {
    const double per = ops ? total_ms / static_cast<double>(ops) : 0.0;
    const double rate = total_ms > 0 ? 1000.0 * static_cast<double>(ops) / total_ms : 0.0;
    std::cout << "  " << std::left << std::setw(24) << label << std::right << std::setw(10)
              << per << " ms/op" << std::setw(10) << rate << " op/s" << extra << "\n";
  };

  const Bytes m = pattern(S.slot_bytes(), 0x5A);
  std::vector<Ciphertext> Cs;
  report::Stopwatch sw;

  /* latency: one operation in flight (DiSE's "lat" mode) */
  B.begin_phase();
  sw.reset();
  for (unsigned k = 0; k < trials; ++k)
    Cs.push_back(B.enc(j, Q, m));
  line("Enc (one at a time)", sw.ms(), trials, B.end_phase(trials));

  bool ok = true;
  B.begin_phase();
  sw.reset();
  for (const Ciphertext &C : Cs)
  {
    const std::optional<Bytes> out = B.dec(j, Q, C);
    ok = ok && out.has_value() && *out == m;
  }
  line("Dec (one at a time)", sw.ms(), Cs.size(), B.end_phase(Cs.size()) + (ok ? "" : "   <-- FAILED"));

  /* throughput: many inputs per round trip (DiSE's "batch") */
  const std::vector<Bytes> ms(batch, m);
  B.begin_phase();
  sw.reset();
  for (unsigned k = 0; k < trials; ++k)
  {
    const std::vector<Ciphertext> v = B.enc_batch(j, Q, ms);
    Cs.insert(Cs.end(), v.begin(), v.end());
  }
  const std::size_t nb = static_cast<std::size_t>(trials) * batch;
  line("Enc (batch " + std::to_string(batch) + ")", sw.ms(), nb, B.end_phase(nb));

  /* key rotation: one Next, then Upd over everything stored */
  StorageHost host(S);
  for (const Ciphertext &C : Cs)
    host.put(C);
  B.begin_phase();
  sw.reset();
  const Token tok = B.next(j);
  line("Next", sw.ms(), 1, B.end_phase(1));
  sw.reset();
  host.rotate(tok);
  line("Upd (host, " + std::to_string(host.workers()) + " thr)", sw.ms(), host.size(),
       "   per record, no interaction");

  const std::optional<Bytes> after = B.dec(j, Q, host.get(host.size() - 1));
  std::cout << "  (an updated record " << (after && *after == m ? "decrypts" : "FAILS to decrypt")
            << " after the rotation)\n";
}

} /* namespace scenario */
} /* namespace utse */
