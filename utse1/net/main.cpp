// net/main.cpp -- UTSE1 over real TCP connections: checks, then timings.
//
// n parties are started as independent TCP servers (one thread each, its own
// listening socket, real send()/recv()) and a single client connects to all n
// over loopback and drives Figure 9 exactly as inproc/main.cpp does over
// function calls -- same core/Utse1Scheme, same common/Scenario checks.
//
// UTSE.Setup is run once, centrally, as Definition 6 permits ("we write Setup
// as a trusted dealer"): the n shares are hand out to the PartyServer objects
// in-process before they start listening, never sent over a socket.
#include <algorithm>
#include <atomic>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <thread>

#include "common/Report.hpp"
#include "common/Scenario.hpp"
#include "net/NetUtse1.hpp"

using namespace utse;
using namespace utse::net;

namespace {

class NetBackend : public scenario::Backend
{
public:
  NetBackend(NetUtse1 &u, Rng &rng, const Counters &counters)
      : u_(u), rng_(rng), counters_(counters)
  {
  }

  Ciphertext enc(unsigned j, const std::vector<unsigned> &Q, const Bytes &m) override
  {
    return u_.enc(j, Q, m, rng_);
  }

  std::vector<Ciphertext> enc_batch(unsigned j, const std::vector<unsigned> &Q,
                                    const std::vector<Bytes> &ms) override
  {
    std::vector<Ciphertext> out;
    for (const Bytes &m : ms)
      out.push_back(u_.enc(j, Q, m, rng_));
    return out;
  }

  std::optional<Bytes> dec(unsigned j, const std::vector<unsigned> &Q,
                           const Ciphertext &C) override
  {
    return u_.dec(j, Q, C);
  }

  std::vector<std::optional<Bytes>> dec_batch(unsigned j, const std::vector<unsigned> &Q,
                                              const std::vector<Ciphertext> &Cs) override
  {
    std::vector<std::optional<Bytes>> out;
    for (const Ciphertext &C : Cs)
      out.push_back(u_.dec(j, Q, C));
    return out;
  }

  Token next(unsigned invoker) override { return u_.next(invoker, rng_); }
  std::vector<std::uint64_t> epochs() const override { return u_.epochs(); }

  void begin_phase() override { phase_start_ = snapshot(); }

  std::string end_phase(std::size_t ops) override
  {
    const std::uint64_t after = snapshot();
    const std::uint64_t delta = after - phase_start_;
    std::ostringstream os;
    os << "   " << delta << " B" << (ops ? " (" + std::to_string(delta / std::max<std::size_t>(1, ops)) + " B/op)" : "");
    return os.str();
  }

private:
  std::uint64_t snapshot() const { return counters_.bytes_out + counters_.bytes_in; }

  NetUtse1 &u_;
  Rng &rng_;
  const Counters &counters_; /* the same Counters every Channel in NetUtse1 writes into */
  std::uint64_t phase_start_ = 0;
};

void usage()
{
  std::cout
      << "utse1_net -- UTSE1 (Figure 9) with n parties as real TCP servers on loopback\n"
         "  -n <int>       parties                          (default 5)\n"
         "  -t <int>       threshold                        (default 3)\n"
         "  -q <int>       bits of q                        (default 264)\n"
         "  -sec <int>     security level 112|128|192|256   (default 128)\n"
         "  -mu <int>      Figure 11's mu, multiple of 16   (default: largest allowed)\n"
         "  -trials <int>  benchmark repetitions            (default 5)\n"
         "  -batch <int>   benchmark batch size             (default 8)\n"
         "  -base-port <int>  first port tried per party, then the OS picks   (default 51200)\n"
         "  -host <text>   loopback address parties bind to (default 127.0.0.1)\n"
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
    const std::uint16_t base_port = static_cast<std::uint16_t>(args.num("base-port", 51200));
    const std::string host = args.str("host", "127.0.0.1");
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

    std::cout << "  randomness       "
              << (rng.deterministic() ? "deterministic (-seed): NOT for real keys"
                                      : "OpenSSL RAND_bytes")
              << "\n"
              << "  class group      " << t_pp << " ms, security " << sec << " bits\n"
              << "  q                " << ctx.q().nbits() << " bits\n"
              << "  Delta            " << ctx.disc().nbits() << " bits"
              << (ctx.large_message_variant() ? " (large-message variant)" : "") << "\n"
              << "  (t, n)           (" << t << ", " << n << "), Delta = n! = " << S.sss().delta()
              << "\n"
              << "  mu               " << S.mu() << "  (messages of " << S.slot_bytes()
              << " bytes)\n"
              << "  fingerprint      " << to_hex(S.fingerprint(), 8) << "\n";

    scenario::run_core_checks(S, rng, check);

    /* ---- Setup: trusted dealer, then hand each server its own share -------- */
    std::cout << "\n== Setup (trusted dealer), then n independent TCP servers ==\n";
    sw.reset();
    const std::vector<Mpz> shares = S.setup_shares(rng);

    std::vector<std::unique_ptr<PartyServer>> servers;
    std::vector<std::pair<std::string, std::uint16_t>> addrs(n);
    for (unsigned i = 1; i <= n; ++i)
    {
      servers.push_back(std::make_unique<PartyServer>(i, shares[i - 1], S));
      std::uint16_t bound = 0;
      servers.back()->bind(host, static_cast<std::uint16_t>(base_port + i - 1), bound);
      addrs[i - 1] = {host, bound};
    }
    std::cout << "  Setup + bind     " << sw.ms() << " ms; share of party 1: "
              << servers[0]->share_snapshot().nbits() << " bits\n  ports           ";
    for (unsigned i = 1; i <= n; ++i)
      std::cout << " " << addrs[i - 1].second;
    std::cout << "\n";

    std::atomic<bool> stop{false};
    std::vector<std::thread> pool;
    pool.reserve(n);
    for (auto &srv : servers)
      pool.emplace_back([&srv, &stop] { srv->serve(stop); });

    std::cout << "\n== client: connecting to all " << n << " parties over TCP ==\n";
    sw.reset();
    Counters counters; /* every Channel below writes into this one, for bandwidth reporting */
    std::vector<Channel> chans = connect_all(S, addrs, &counters);
    NetUtse1 net_utse(S, std::move(chans));
    std::cout << "  handshake with all " << n << " parties: " << sw.ms() << " ms ("
              << (counters.bytes_out + counters.bytes_in) << " B)\n";

    NetBackend backend(net_utse, rng, counters);
    scenario::run_protocol_checks(backend, S, check);

    scenario::run_benchmark(backend, S, 1, report::window(1, t, n), trials, batch);

    std::cout << "\n== shutting down ==\n";
    net_utse.close_all();
    stop.store(true);
    for (std::thread &th : pool)
      th.join();

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
