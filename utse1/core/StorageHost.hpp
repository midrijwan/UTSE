// core/StorageHost.hpp -- the untrusted storage host of Section 1.
//
// It holds ciphertexts and, when handed a token, runs Upd on every record. It
// has public parameters only: no key share, no interaction with the parties, no
// plaintext. Records are independent, so the pass is spread over threads, and
// it is all-or-nothing: the stored records are replaced only once every one of
// them has been updated.
#pragma once

#include <exception>
#include <mutex>
#include <thread>

#include "core/Utse1Scheme.hpp"

namespace utse {

class StorageHost
{
public:
  /** threads = 0: one per hardware thread. */
  explicit StorageHost(const Utse1Scheme &S, unsigned threads = 0) : S_(S), threads_(threads) {}

  /** Store a ciphertext of the host's current epoch; returns its record id. */
  std::size_t put(const Ciphertext &C)
  {
    records_.push_back(C);
    return records_.size() - 1;
  }

  const Ciphertext &get(std::size_t id) const { return records_.at(id); }
  std::size_t size() const { return records_.size(); }
  std::uint64_t epoch() const { return epoch_; }

  unsigned workers() const
  {
    unsigned w = threads_ != 0 ? threads_ : std::thread::hardware_concurrency();
    return w == 0 ? 1 : w;
  }

  /** Upd(token, .) on every record, then epoch <- epoch + 1. */
  void rotate(const Token &tok)
  {
    const std::size_t N = records_.size();
    unsigned W = workers();
    if (N < W)
      W = N == 0 ? 1 : static_cast<unsigned>(N);

    std::vector<Ciphertext> updated(N);
    std::exception_ptr error;
    std::mutex error_mu;

    auto work = [&](unsigned w) {
      try
      {
        for (std::size_t i = w; i < N; i += W)
          updated[i] = S_.upd(tok, records_[i]);
      }
      catch (...)
      {
        std::lock_guard<std::mutex> lock(error_mu);
        if (!error)
          error = std::current_exception();
      }
    };

    if (W == 1)
    {
      work(0);
    }
    else
    {
      std::vector<std::thread> pool;
      pool.reserve(W);
      for (unsigned w = 0; w < W; ++w)
        pool.emplace_back(work, w);
      for (std::thread &th : pool)
        th.join();
    }

    if (error)
      std::rethrow_exception(error);
    records_.swap(updated);
    ++epoch_;
  }

private:
  const Utse1Scheme &S_;
  unsigned threads_;
  std::vector<Ciphertext> records_;
  std::uint64_t epoch_ = 0;
};

} /* namespace utse */
