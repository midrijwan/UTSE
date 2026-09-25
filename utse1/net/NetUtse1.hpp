// net/NetUtse1.hpp -- the client side of Figure 9 over real TCP connections.
//
// One persistent Channel per party (party i is channels_[i-1]), opened once by
// connect_all() and kept for the whole run -- matching DiSE's own
// GroupChannel, which also holds one long-lived connection per peer rather
// than reconnecting per request.
#pragma once

#include <chrono>

#include "core/Utse1Scheme.hpp"
#include "net/PartyServer.hpp"
#include "net/Protocol.hpp"
#include "net/Socket.hpp"

namespace utse {
namespace net {

/** Connect to every party's (host, port), handshake, and verify its identity. */
inline std::vector<Channel> connect_all(const Utse1Scheme &S,
                                        const std::vector<std::pair<std::string, std::uint16_t>> &addrs,
                                        Counters *counters,
                                        std::chrono::milliseconds timeout = std::chrono::seconds(10))
{
  if (addrs.size() != S.n())
    throw std::invalid_argument("connect_all: need exactly n addresses");

  std::vector<Channel> chans;
  chans.reserve(addrs.size());
  for (unsigned i = 1; i <= S.n(); ++i)
  {
    Socket sock = connect_tcp(addrs[i - 1].first, addrs[i - 1].second, timeout);
    Channel ch(std::move(sock), counters);
    ch.send(make_hello(Msg::Hello, 0, S.fingerprint()));
    const Hello ack = parse_hello(ch.recv(kMaxHelloFrame), Msg::HelloAck);
    if (ack.id != i)
      throw ProtocolError("connected to party " + std::to_string(ack.id) + " where party "
                          + std::to_string(i) + " was expected (check the address list order)");
    if (ack.fingerprint != S.fingerprint())
      throw ProtocolError("party " + std::to_string(i) + " runs different public parameters");
    chans.push_back(std::move(ch));
  }
  return chans;
}

class NetUtse1
{
public:
  NetUtse1(const Utse1Scheme &S, std::vector<Channel> chans) : S_(S), chans_(std::move(chans))
  {
    if (chans_.size() != S_.n())
      throw std::invalid_argument("NetUtse1: need exactly n channels");
  }

  std::uint64_t epoch() const { return epoch_; }
  std::vector<std::uint64_t> epochs() const { return std::vector<std::uint64_t>(S_.n(), epoch_); }

  Ciphertext enc(unsigned j, const std::vector<unsigned> &Q, const Bytes &m, Rng &rng)
  {
    S_.check_quorum(j, Q);
    const Utse1Scheme::EncState st = S_.enc_begin(j, m, rng);
    return S_.enc_finish(st, dprf_round(Q, st.x));
  }

  std::optional<Bytes> dec(unsigned j, const std::vector<unsigned> &Q, const Ciphertext &C)
  {
    S_.check_quorum(j, Q);
    return S_.dec_finish(C, dprf_round(Q, S_.dec_input(C)));
  }

  /** UTSE.Next invoked by `invoker`: a fresh deal, delta^(i) to every server i. */
  Token next(unsigned invoker, Rng &rng)
  {
    if (invoker == 0 || invoker > S_.n())
      throw std::invalid_argument("Next: invoking party out of range");

    const Utse1Scheme::ShiftDeal deal = S_.next_deal(rng);
    const std::uint64_t req_id = next_req_id();
    for (unsigned i = 1; i <= S_.n(); ++i)
      chans_[i - 1].send(make_next_req(req_id, epoch_, invoker, deal.shares[i - 1]));

    std::uint64_t new_epoch = 0;
    bool have_epoch = false;
    for (unsigned i = 1; i <= S_.n(); ++i)
    {
      const Bytes frame = chans_[i - 1].recv();
      Reader r(frame);
      const auto type = static_cast<Msg>(r.u8());
      const std::uint64_t got_id = r.u64();
      if (got_id != req_id)
        throw ProtocolError("party " + std::to_string(i) + ": mismatched request id");
      if (type == Msg::Error)
        throw ProtocolError("party " + std::to_string(i) + " refused Next: "
                            + r.str(kMaxErrorBytes));
      if (type != Msg::NextAck)
        throw ProtocolError("party " + std::to_string(i) + ": unexpected reply to Next");
      const std::uint64_t ne = r.u64();
      r.expect_end();
      if (!have_epoch)
      {
        new_epoch = ne;
        have_epoch = true;
      }
      else if (ne != new_epoch)
      {
        throw std::logic_error("parties disagree on the new epoch after Next");
      }
    }
    epoch_ = new_epoch;
    return deal.token;
  }

  void close_all()
  {
    for (Channel &c : chans_)
      c.close();
  }

private:
  std::uint64_t next_req_id() { return req_ctr_++; }

  /** Send x to every party in Q, collect h_i, Combine (Figure 1 over the wire). */
  QFI dprf_round(const std::vector<unsigned> &Q, const Bytes &x)
  {
    const std::uint64_t req_id = next_req_id();
    const std::vector<Bytes> xs{x};
    for (unsigned i : Q)
      chans_[i - 1].send(make_eval_req(req_id, epoch_, xs));

    std::vector<QFI> z;
    z.reserve(Q.size());
    for (unsigned i : Q)
    {
      const Bytes frame = chans_[i - 1].recv();
      Reader r(frame);
      const auto type = static_cast<Msg>(r.u8());
      const std::uint64_t got_id = r.u64();
      if (got_id != req_id)
        throw ProtocolError("party " + std::to_string(i) + ": mismatched request id");
      if (type == Msg::Error)
        throw ProtocolError("party " + std::to_string(i) + " refused the DPRF request: "
                            + r.str(kMaxErrorBytes));
      if (type != Msg::EvalResp)
        throw ProtocolError("party " + std::to_string(i) + ": unexpected reply");
      r.u64(); /* the server's epoch; already implied by req_id/epoch_ matching */
      const std::uint32_t count = r.u32();
      if (count != 1)
        throw ProtocolError("party " + std::to_string(i) + ": unexpected batch size in reply");
      z.push_back(r.qfi(S_.ctx()));
      r.expect_end();
    }
    return S_.dprf().combine(Q, z);
  }

  const Utse1Scheme &S_;
  std::vector<Channel> chans_;
  std::uint64_t epoch_ = 0;
  std::uint64_t req_ctr_ = 1;
};

} /* namespace net */
} /* namespace utse */
