// core/Wire.hpp -- byte encoding of integers, class-group elements, ciphertexts
// and tokens, with validation on the way in.
//
// A form is sent as (a, b) only: c is recomputed as (b^2 - Delta) / 4a, which
// both saves a third of the bytes and FORCES the discriminant to be ours.
// BICYCL's validating QFI constructor then checks that the form is primitive,
// normal and reduced -- but not which discriminant it has, which is why the
// recomputation matters: a form from another group fed into nucomp would be
// undefined behaviour.
#pragma once

#include <cstddef>
#include <limits>

#include "core/Utse1Scheme.hpp"

namespace utse {

class WireError : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

constexpr std::size_t kMaxMpzBytes = std::size_t(1) << 16;

class Writer
{
public:
  void u8(std::uint8_t v) { buf_.push_back(v); }
  void u32(std::uint32_t v) { append(buf_, u32be(v)); }
  void u64(std::uint64_t v) { append(buf_, u64be(v)); }

  void bytes(const Bytes &b)
  {
    if (b.size() > std::numeric_limits<std::uint32_t>::max())
      throw WireError("Writer: byte string too long");
    u32(static_cast<std::uint32_t>(b.size()));
    append(buf_, b);
  }

  void str(const std::string &s) { bytes(Bytes(s.begin(), s.end())); }

  /** sign byte (0 or 1), then the big-endian magnitude. */
  void mpz(const Mpz &x)
  {
    u8(x.sgn() < 0 ? 1 : 0);
    Mpz a;
    Mpz::abs(a, x);
    bytes(static_cast<Bytes>(a));
  }

  /** (a, b); the receiver recomputes c from the discriminant. */
  void qfi(const QFI &f)
  {
    mpz(f.a());
    mpz(f.b());
  }

  void ciphertext(const Ciphertext &C)
  {
    u32(static_cast<std::uint32_t>(C.j));
    bytes(C.alpha);
    qfi(C.c);
  }

  void token(const Token &T) { mpz(T.shift); }

  std::size_t size() const { return buf_.size(); }
  Bytes take() { return std::move(buf_); }

private:
  Bytes buf_;
};

class Reader
{
public:
  explicit Reader(const Bytes &b) : b_(b) {}
  /* The Reader keeps a reference: never hand it a temporary. */
  explicit Reader(Bytes &&) = delete;

  std::uint8_t u8()
  {
    need(1);
    return b_[off_++];
  }

  std::uint32_t u32()
  {
    need(4);
    const std::uint32_t v = load_u32be(&b_[off_]);
    off_ += 4;
    return v;
  }

  std::uint64_t u64()
  {
    need(8);
    const std::uint64_t v = load_u64be(&b_[off_]);
    off_ += 8;
    return v;
  }

  Bytes bytes(std::size_t max_len)
  {
    const std::size_t len = u32();
    if (len > max_len)
      throw WireError("Reader: field longer than allowed");
    need(len);
    const auto first = b_.begin() + static_cast<std::ptrdiff_t>(off_);
    Bytes out(first, first + static_cast<std::ptrdiff_t>(len));
    off_ += len;
    return out;
  }

  std::string str(std::size_t max_len)
  {
    const Bytes b = bytes(max_len);
    return std::string(b.begin(), b.end());
  }

  Mpz mpz(std::size_t max_bytes = kMaxMpzBytes)
  {
    const std::uint8_t sign = u8();
    if (sign > 1)
      throw WireError("Reader: bad sign byte");
    const Bytes mag = bytes(max_bytes);
    Mpz x(mag);
    if (sign == 1)
      x.neg();
    return x;
  }

  /** A form of discriminant ctx.disc(), reduced, or WireError. */
  QFI qfi(const ClContext &ctx)
  {
    const Mpz a = mpz();
    const Mpz b = mpz();
    if (a.sgn() <= 0)
      throw WireError("form: a must be positive");

    Mpz num; /* b^2 - Delta  (> 0, since Delta < 0) */
    Mpz::mul(num, b, b);
    Mpz::sub(num, num, ctx.disc());
    Mpz den; /* 4a */
    Mpz::mulby4(den, a);
    Mpz rem;
    Mpz::mod(rem, num, den);
    if (!rem.is_zero())
      throw WireError("form: (b^2 - Delta) is not divisible by 4a");
    Mpz c;
    Mpz::divexact(c, num, den);

    try
    {
      return QFI(a, b, c); /* checks: primitive, normal, reduced */
    }
    catch (const std::exception &e)
    {
      throw WireError(std::string("form rejected: ") + e.what());
    }
  }

  Ciphertext ciphertext(const ClContext &ctx)
  {
    Ciphertext C;
    C.j = u32();
    C.alpha = bytes(256);
    C.c = qfi(ctx);
    return C;
  }

  Token token()
  {
    Token T;
    T.shift = mpz();
    if (T.shift.sgn() < 0)
      throw WireError("token: negative shift");
    return T;
  }

  bool at_end() const { return off_ == b_.size(); }

  void expect_end() const
  {
    if (!at_end())
      throw WireError("Reader: trailing bytes");
  }

private:
  void need(std::size_t n) const
  {
    if (n > b_.size() - off_)
      throw WireError("Reader: message truncated");
  }

  const Bytes &b_;
  std::size_t off_ = 0;
};

} /* namespace utse */
