// common/Report.hpp -- small helpers shared by the two demo programs.
#pragma once

#include <chrono>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "core/Util.hpp"

namespace utse {
namespace report {

/** Prints "[ ok ]" / "[FAIL]" per check and counts failures. */
class Checker
{
public:
  void operator()(bool ok, const std::string &what)
  {
    ++total_;
    if (!ok)
      ++failures_;
    std::cout << (ok ? "  [ ok ] " : "  [FAIL] ") << what << std::endl;
  }

  int failures() const { return failures_; }
  int total() const { return total_; }

private:
  int failures_ = 0;
  int total_ = 0;
};

/** True iff f() throws a std::exception. */
template <class F>
bool throws(F &&f)
{
  try
  {
    f();
  }
  catch (const std::exception &)
  {
    return true;
  }
  return false;
}

class Stopwatch
{
public:
  Stopwatch() : t0_(std::chrono::steady_clock::now()) {}
  void reset() { t0_ = std::chrono::steady_clock::now(); }
  double ms() const
  {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0_)
        .count();
  }

private:
  std::chrono::steady_clock::time_point t0_;
};

/** "{1,2,3}" */
inline std::string ids(const std::vector<unsigned> &Q)
{
  std::string s = "{";
  for (std::size_t k = 0; k < Q.size(); ++k)
    s += (k ? "," : "") + std::to_string(Q[k]);
  return s + "}";
}

/** len consecutive party ids starting at `start`, wrapping around 1..n. */
inline std::vector<unsigned> window(unsigned start, unsigned len, unsigned n)
{
  std::vector<unsigned> Q;
  for (unsigned k = 0; k < len; ++k)
    Q.push_back(((start - 1 + k) % n) + 1);
  return Q;
}

/** "-key value" / "--key value" / "-flag" command-line options. */
class Args
{
public:
  Args(int argc, char **argv)
  {
    for (int i = 1; i < argc; ++i)
    {
      const std::string a = argv[i];
      if (a.size() < 2 || a[0] != '-')
        throw std::invalid_argument("unexpected argument '" + a + "' (try -h)");
      const std::string key = a.substr(a[1] == '-' ? 2 : 1);
      std::string value;
      if (i + 1 < argc && argv[i + 1][0] != '-')
        value = argv[++i];
      kv_[key] = value;
    }
  }

  bool has(const std::string &k) const { return kv_.count(k) != 0; }

  unsigned long num(const std::string &k, unsigned long def) const
  {
    const auto it = kv_.find(k);
    if (it == kv_.end())
      return def;
    std::size_t pos = 0;
    unsigned long v = 0;
    try
    {
      v = std::stoul(it->second, &pos);
    }
    catch (const std::exception &)
    {
      pos = 0;
    }
    if (it->second.empty() || pos != it->second.size())
      throw std::invalid_argument("-" + k + " expects a non-negative integer");
    return v;
  }

  std::string str(const std::string &k, const std::string &def) const
  {
    const auto it = kv_.find(k);
    return it == kv_.end() ? def : it->second;
  }

  /** -seed <text>: deterministic randomness (debugging only). */
  Bytes seed() const
  {
    if (!has("seed"))
      return {};
    const std::string s = str("seed", "");
    if (s.empty())
      throw std::invalid_argument("-seed expects a value");
    return Bytes(s.begin(), s.end());
  }

private:
  std::map<std::string, std::string> kv_;
};

} /* namespace report */
} /* namespace utse */
