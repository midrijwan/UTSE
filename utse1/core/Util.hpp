// core/Util.hpp -- byte strings, big-endian integers, n!, hex and SHAKE256.
//
// WHY THIS WHOLE PROJECT IS HEADER-ONLY
// BICYCL is header-only (.hpp + .inl). In the gmp_extras.inl of the BICYCL tree
// this code was written against, three functions are defined WITHOUT `inline`:
// WNAF::WNAF, WNAF::operator[] and BICYCL::nbits(mp_limb_t). BICYCL's own tests
// are single-file programs so it never shows there, but any program that
// includes BICYCL from two .cpp files fails to link with "multiple definition".
// So every file of ours is a header, and every executable is exactly one .cpp.
#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <openssl/evp.h>

#include "bicycl.hpp"

namespace utse {

using BICYCL::CL_HSMqk;
using BICYCL::ClassGroup;
using BICYCL::Mpz;
using BICYCL::QFI;
using BICYCL::RandGen;

using Bytes = std::vector<unsigned char>;

/* ---- big-endian fixed-width integers ------------------------------------ */

inline Bytes u32be(std::uint32_t v)
{
  return Bytes{static_cast<unsigned char>((v >> 24) & 0xFFu),
               static_cast<unsigned char>((v >> 16) & 0xFFu),
               static_cast<unsigned char>((v >> 8) & 0xFFu),
               static_cast<unsigned char>(v & 0xFFu)};
}

inline Bytes u64be(std::uint64_t v)
{
  Bytes out(8);
  for (std::size_t i = 8; i-- > 0;)
  {
    out[i] = static_cast<unsigned char>(v & 0xFFu);
    v >>= 8;
  }
  return out;
}

inline std::uint32_t load_u32be(const unsigned char *p)
{
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16)
         | (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

inline std::uint64_t load_u64be(const unsigned char *p)
{
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < 8; ++i)
    v = (v << 8) | static_cast<std::uint64_t>(p[i]);
  return v;
}

inline void append(Bytes &dst, const Bytes &src)
{
  dst.insert(dst.end(), src.begin(), src.end());
}

inline void append(Bytes &dst, const std::string &src)
{
  dst.insert(dst.end(), src.begin(), src.end());
}

/* ---- integers ------------------------------------------------------------ */

/**
 * Big endian, exactly nbytes long. BICYCL's own conversion exports the
 * magnitude with leading zeros dropped, so we pad (and refuse negatives).
 */
inline Bytes mpz_to_fixed(const Mpz &x, std::size_t nbytes)
{
  if (x.sgn() < 0)
    throw std::invalid_argument("mpz_to_fixed: negative value");

  const Bytes raw = static_cast<Bytes>(x);

  std::size_t start = 0;
  while (start + 1 < raw.size() && raw[start] == 0)
    ++start;
  const std::size_t len = raw.size() - start;

  if (len > nbytes)
    throw std::invalid_argument("mpz_to_fixed: value does not fit");

  Bytes out(nbytes - len, 0);
  out.insert(out.end(), raw.begin() + static_cast<std::ptrdiff_t>(start), raw.end());
  return out;
}

/** Delta = n!, the clearing factor of Appendix A.3. */
inline Mpz factorial(unsigned n)
{
  Mpz r(1UL);
  for (unsigned i = 2; i <= n; ++i)
    Mpz::mul(r, r, static_cast<unsigned long>(i));
  return r;
}

inline std::string to_hex(const Bytes &b,
                          std::size_t max_bytes = std::numeric_limits<std::size_t>::max())
{
  static const char *digits = "0123456789abcdef";
  std::string s;
  const std::size_t n = b.size() < max_bytes ? b.size() : max_bytes;
  for (std::size_t i = 0; i < n; ++i)
  {
    s += digits[(b[i] >> 4) & 0xF];
    s += digits[b[i] & 0xF];
  }
  if (n < b.size())
    s += "..";
  return s;
}

/* ---- SHAKE256 (OpenSSL >= 1.1.1) ---------------------------------------- */

class Shake256
{
public:
  Shake256() : ctx_(EVP_MD_CTX_new())
  {
    if (ctx_ == nullptr)
      throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx_, EVP_shake256(), nullptr) != 1)
    {
      EVP_MD_CTX_free(ctx_);
      throw std::runtime_error("EVP_DigestInit_ex(SHAKE256) failed");
    }
  }

  ~Shake256() { EVP_MD_CTX_free(ctx_); }

  Shake256(const Shake256 &) = delete;
  Shake256 &operator=(const Shake256 &) = delete;

  void update(const void *p, std::size_t n)
  {
    if (n != 0 && EVP_DigestUpdate(ctx_, p, n) != 1)
      throw std::runtime_error("EVP_DigestUpdate failed");
  }

  void update(const Bytes &v) { update(v.data(), v.size()); }
  void update(const std::string &s) { update(s.data(), s.size()); }

  /** Length-prefixed, so that a || b can never be confused with a' || b'. */
  void update_framed(const Bytes &v)
  {
    update(u32be(static_cast<std::uint32_t>(v.size())));
    update(v);
  }

  void update_framed(const std::string &s)
  {
    update(u32be(static_cast<std::uint32_t>(s.size())));
    update(s);
  }

  Bytes finalize(std::size_t outlen)
  {
    Bytes out(outlen);
    if (EVP_DigestFinalXOF(ctx_, out.data(), outlen) != 1)
      throw std::runtime_error("EVP_DigestFinalXOF failed");
    return out;
  }

private:
  EVP_MD_CTX *ctx_;
};

} /* namespace utse */
