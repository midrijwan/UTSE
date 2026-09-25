// inproc/main2.cpp -- UTSE2 (Figure 10) with in-process parties: checks, then timings.
//
// Standalone from common/Scenario.hpp: UTSE2's Ciphertext2/Token2 shapes, its
// single-gate Dec, and Next's extra r'/R' round don't fit the UTSE1-shaped
// Backend interface, so this file has its own small check suite, reusing only
// the generic printer/stopwatch/arg-parser from common/Report.hpp.
#include <algorithm>
#include <iomanip>
#include <iostream>

#include "common/Report.hpp"
#include "inproc/InProcUtse2.hpp"

using namespace utse;

namespace {

Mpz message_from_pattern(unsigned char base, const Mpz &below_q)
{
  Bytes b((below_q.nbits() + 7) / 8, base);
  b[0] &= 0x7Fu; /* stay comfortably below q without checking bit-for-bit */
  return Mpz(b);
}

void usage()
{
  std::cout << "utse2_inproc -- UTSE2 (Figure 10) with in-process parties\n"
               "  -n <int>       parties                          (default 5)\n"
               "  -t <int>       threshold                        (default 3)\n"
               "  -q <int>       bits of q                        (default 264)\n"
               "  -sec <int>     security level 112|128|192|256   (default 128)\n"
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
    if (t == 0 || t > n)
      throw std::invalid_argument("need 1 <= t <= n");

    Rng rng(args.seed());
    report::Checker check;
    std::cout << std::fixed << std::setprecision(2);

    std::cout << "== public parameters ==\n";
    ClContext ctx(q_bits, sec, rng);
    Utse2Scheme S(ctx, n, t);
    InProcUtse2 utse(S);
    std::cout << "  q                " << ctx.q().nbits() << " bits\n"
              << "  (t, n)           (" << t << ", " << n << "), Delta = n! = " << S.sss().delta()
              << "\n";

    std::cout << "\n== building blocks ==\n";
    {
      const QFI r1 = ctx.sample_Gq(rng);
      const QFI r2 = ctx.sample_Gq(rng);
      check(ctx.in_group(r1) && ctx.in_group(r2) && !(r1 == r2) && !ctx.in_F(r1),
            "sample_Gq: lands in Cl(Delta), fresh each time, outside F_CL");
    }

    std::cout << "\n== Setup ==\n";
    std::vector<Party2> parties = utse.setup(rng);
    std::cout << "  share of party 1: " << parties[0].share().nbits() << " bits\n";

    using report::window;
    const std::vector<unsigned> Qa = window(1, t, n);
    const std::vector<unsigned> Qb = window(n - t + 1, t, n);
    const Mpz m = message_from_pattern(0xA5, ctx.q());
    const Mpz m2 = message_from_pattern(0x3C, ctx.q());

    std::cout << "\n== epoch 0: Enc / Dec ==\n";
    const Ciphertext2 C0 = utse.enc(Qa.front(), parties, Qa, m, rng);
    {
      const std::optional<Mpz> out = utse.dec(Qa.front(), parties, Qa, C0);
      check(out.has_value() && *out == m, "Enc by " + report::ids(Qa) + "; Dec by the same quorum");
    }
    {
      const std::optional<Mpz> out = utse.dec(Qb.front(), parties, Qb, C0);
      check(out.has_value() && *out == m, "Dec by " + report::ids(Qb) + " (a different quorum)");
    }

    std::cout << "\n== three rotations: Next (with its extra r'/R' round), then Upd ==\n";
    Ciphertext2 C = C0;
    for (unsigned e = 1; e <= 3; ++e)
    {
      const Token2 tok = utse.next(window(e % n + 1, t, n), parties, rng);
      C = utse.upd(tok, C);
      std::cout << "  epoch " << e << ": token delta " << tok.delta.nbits() << " bits, share now "
                << parties[0].share().nbits() << " bits\n";
    }
    {
      const std::optional<Mpz> out = utse.dec(Qb.front(), parties, Qb, C);
      check(out.has_value() && *out == m, "the 3x-rotated ciphertext still decrypts to m");
    }
    {
      const Ciphertext2 Cf = utse.enc(Qa.front(), parties, Qa, m2, rng);
      const std::optional<Mpz> out = utse.dec(Qb.front(), parties, Qb, Cf);
      check(out.has_value() && *out == m2, "a fresh encryption at epoch 3 decrypts");
    }

    std::cout << "\n== Dec's one gate, and its known limit (Remark 6) ==\n";
    {
      Ciphertext2 X = C;
      X.c = ctx.mul(X.c, ctx.pow(ctx.h(), Mpz(9999UL))); /* nudges c outside F_CL */
      const bool rejected = !utse.dec(Qa.front(), parties, Qa, X).has_value();
      check(rejected, "c nudged outside F_CL: the structural gate rejects it");
    }
    {
      /* c * f^1 stays INSIDE F_CL: Solve succeeds, decrypting to m+1. There is
       * no commitment to catch this -- Remark 6 states UTSE2 does not provide
       * authenticity, and this is exactly why. This check demonstrates the
       * paper's own claim, it is not a bug in the implementation. */
      Ciphertext2 X = C;
      X.c = ctx.mul(X.c, ctx.f_pow(Mpz(1UL)));
      const std::optional<Mpz> out = utse.dec(Qa.front(), parties, Qa, X);
      Mpz expect;
      Mpz::add(expect, m, 1UL);
      check(out.has_value() && *out == expect,
            "c * f^1 (inside F_CL) silently decrypts to m+1: UTSE2 has no authenticity gate, "
            "as the paper states");
    }

    std::cout << "\n== misuse is refused ==\n";
    check(report::throws([&] { utse.enc(Qa.front(), parties, window(1, t - 1, n), m, rng); }),
          "|Q| < t");
    if (n > t) /* when t == n, every valid quorum is all n parties, so this case can't arise */
      check(report::throws([&] { utse.enc(n, parties, Qa, m, rng); }),
            "client not in its own quorum");
    check(report::throws([&] { utse.enc(Qa.front(), parties, Qa, ctx.q(), rng); }),
          "m == q is out of range (m must be < q)");

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
