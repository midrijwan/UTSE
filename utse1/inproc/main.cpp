// inproc/main.cpp -- UTSE1 with in-process parties: checks, then timings.
#include <algorithm>
#include <iomanip>
#include <iostream>

#include "common/Report.hpp"
#include "common/Scenario.hpp"
#include "inproc/InProcUtse1.hpp"

using namespace utse;

namespace {

class InProcBackend : public scenario::Backend
{
public:
  InProcBackend(const InProcUtse1 &u, std::vector<Party> &parties, Rng &rng)
      : u_(u), parties_(parties), rng_(rng)
  {
  }

  Ciphertext enc(unsigned j, const std::vector<unsigned> &Q, const Bytes &m) override
  {
    return u_.enc(j, parties_, Q, m, rng_);
  }

  std::vector<Ciphertext> enc_batch(unsigned j, const std::vector<unsigned> &Q,
                                    const std::vector<Bytes> &ms) override
  {
    std::vector<Ciphertext> out;
    for (const Bytes &m : ms)
      out.push_back(u_.enc(j, parties_, Q, m, rng_));
    return out;
  }

  std::optional<Bytes> dec(unsigned j, const std::vector<unsigned> &Q,
                           const Ciphertext &C) override
  {
    return u_.dec(j, parties_, Q, C);
  }

  std::vector<std::optional<Bytes>> dec_batch(unsigned j, const std::vector<unsigned> &Q,
                                              const std::vector<Ciphertext> &Cs) override
  {
    std::vector<std::optional<Bytes>> out;
    for (const Ciphertext &C : Cs)
      out.push_back(u_.dec(j, parties_, Q, C));
    return out;
  }

  Token next(unsigned invoker) override { return u_.next(invoker, parties_, rng_); }

  std::vector<std::uint64_t> epochs() const override
  {
    std::vector<std::uint64_t> e;
    for (const Party &P : parties_)
      e.push_back(P.epoch());
    return e;
  }

private:
  const InProcUtse1 &u_;
  std::vector<Party> &parties_;
  Rng &rng_;
};

void usage()
{
  std::cout << "utse1_inproc -- UTSE1 (Figure 9) with in-process parties\n"
               "  -n <int>       parties                          (default 5)\n"
               "  -t <int>       threshold                        (default 3)\n"
               "  -q <int>       bits of q                        (default 264)\n"
               "  -sec <int>     security level 112|128|192|256   (default 128)\n"
               "  -mu <int>      Figure 11's mu, multiple of 16   (default: largest allowed)\n"
               "  -trials <int>  benchmark repetitions            (default 5)\n"
               "  -batch <int>   benchmark batch size             (default 8)\n"
               "  -seed <text>   deterministic randomness, debugging only\n";
}

} /* anonymous namespace */

int main(int argc, char **argv)
{
  try
  {
    const report::Args args(argc, argv);
    if (args.has("h") || args.has("help"))
    {
      usage();
      return 0;
    }
    const unsigned n = static_cast<unsigned>(args.num("n", 5));
    const unsigned t = static_cast<unsigned>(args.num("t", 3));
    const std::size_t q_bits = args.num("q", 264);
    const unsigned sec = static_cast<unsigned>(args.num("sec", 128));
    const unsigned trials = static_cast<unsigned>(std::max(1UL, args.num("trials", 5)));
    const unsigned batch = static_cast<unsigned>(std::max(1UL, args.num("batch", 8)));
    if (t == 0 || t > n)
      throw std::invalid_argument("need 1 <= t <= n");

    Rng rng(args.seed());
    report::Checker check;
    std::cout << std::fixed << std::setprecision(2);

    std::cout << "== public parameters ==\n";
    report::Stopwatch sw;
    ClContext ctx(q_bits, sec, rng);
    const double t_pp = sw.ms();
    const std::size_t mu = args.num("mu", ctx.max_mu());
    Utse1Scheme S(ctx, n, t, mu, Commitment::setup(rng));
    InProcUtse1 utse(S);

    std::cout << "  randomness       "
              << (rng.deterministic() ? "deterministic (-seed): NOT for real keys"
                                      : "OpenSSL RAND_bytes")
              << "\n"
              << "  class group      " << t_pp << " ms, security " << sec << " bits\n"
              << "  q                " << ctx.q().nbits() << " bits\n"
              << "  Delta            " << ctx.disc().nbits() << " bits"
              << (ctx.large_message_variant() ? " (large-message variant)" : "") << "\n"
              << "  D_q bound        " << ctx.Dq_bound().nbits() << " bits\n"
              << "  (t, n)           (" << t << ", " << n << "), Delta = n! = " << S.sss().delta()
              << "\n"
              << "  mu               " << S.mu() << "  (messages of " << S.slot_bytes()
              << " bytes)\n"
              << "  fingerprint      " << to_hex(S.fingerprint(), 8) << "\n";

    scenario::run_core_checks(S, rng, check);

    std::cout << "\n== Setup ==\n";
    sw.reset();
    std::vector<Party> parties = utse.setup(rng);
    std::cout << "  " << sw.ms() << " ms; share of party 1: " << parties[0].share().nbits()
              << " bits\n";

    InProcBackend backend(utse, parties, rng);
    scenario::run_protocol_checks(backend, S, check);

    /* cost of the building blocks */
    std::cout << "\n== building-block costs (average of " << trials << ") ==\n";
    auto avg = [&](auto &&f) {
      report::Stopwatch w;
      for (unsigned k = 0; k < trials; ++k)
        f();
      return w.ms() / trials;
    };
    const Bytes x = Utse1Scheme::header(1, Bytes(Commitment::kOutBytes, 0x42));
    const std::vector<unsigned> Q = report::window(1, t, n);
    std::vector<QFI> z;
    for (unsigned i : Q)
      z.push_back(parties[i - 1].eval(S.dprf(), x));
    const Mpz enc_val =
        S.encoder().encode(Bytes(S.slot_bytes(), 0x11), Bytes(S.slot_bytes(), 0x22));
    const QFI fm = ctx.f_pow(enc_val);
    std::cout << "  H(x) into G^q_CL          " << avg([&] { (void)S.hash(x); }) << " ms\n";
    std::cout << "  Eval  H(x)^{k_i}          "
              << avg([&] { (void)parties[0].eval(S.dprf(), x); }) << " ms\n";
    std::cout << "  Combine (|Q| = t)         " << avg([&] { (void)S.dprf().combine(Q, z); })
              << " ms\n";
    std::cout << "  f^m                       " << avg([&] { (void)ctx.f_pow(enc_val); })
              << " ms\n";
    std::cout << "  Solve (incl. F check)     " << avg([&] { (void)ctx.solve(fm); }) << " ms\n";

    scenario::run_benchmark(backend, S, 1, Q, trials, batch);

    std::cout << "\n"
              << (check.total() - check.failures()) << "/" << check.total()
              << " checks passed\n";
    return check.failures() == 0 ? 0 : 1;
  }
  catch (const std::exception &e)
  {
    std::cerr << "error: " << e.what() << "\n";
    return 2;
  }
}
