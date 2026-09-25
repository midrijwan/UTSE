// net/PartyServer.hpp -- party P_i as a TCP server.
//
// One PartyServer binds its own listening socket, then serve() accepts exactly
// one client connection and answers on it until that client disconnects. Every
// message it acts on is exactly what Figure 9 has a client send a server: a
// batch of j||alpha (Eval), or a single delta^(i) (the local half of Next).
// The server never sees a plaintext, a quorum, or another party's share.
#pragma once

#include <mutex>

#include "core/Utse1Scheme.hpp"
#include "net/Protocol.hpp"
#include "net/Socket.hpp"

namespace utse {
namespace net {

class PartyServer
{
public:
  PartyServer(unsigned id, Mpz share, const Utse1Scheme &S) : id_(id), share_(std::move(share)), S_(S) {}

  unsigned id() const { return id_; }

  Mpz share_snapshot() const
  {
    std::lock_guard<std::mutex> lock(mu_);
    return share_;
  }

  std::uint64_t epoch_snapshot() const
  {
    std::lock_guard<std::mutex> lock(mu_);
    return epoch_;
  }

  const Counters &counters() const { return counters_; }

  /** Bind now (so the port is known before serve() runs in its own thread). */
  void bind(const std::string &host, std::uint16_t port_hint, std::uint16_t &bound_port)
  {
    listen_sock_ = listen_tcp(host, port_hint, bound_port);
  }

  /** Accept one connection and service it until it closes, or `stop` is set. */
  void serve(const std::atomic<bool> &stop)
  {
    Socket conn = accept_tcp(listen_sock_.fd(), stop);
    if (!conn.valid())
      return; /* asked to stop before any client connected */
    handle_connection(std::move(conn));
  }

private:
  void handle_connection(Socket conn)
  {
    Channel ch(std::move(conn), &counters_);
    try
    {
      const Bytes hello = ch.recv(kMaxHelloFrame);
      const Hello h = parse_hello(hello, Msg::Hello);
      if (h.version != kProtocolVersion)
      {
        ch.send(make_error(0, "protocol version mismatch"));
        return;
      }
      if (h.fingerprint != S_.fingerprint())
      {
        ch.send(make_error(0, "public parameters differ (fingerprint mismatch)"));
        return;
      }
      ch.send(make_hello(Msg::HelloAck, id_, S_.fingerprint()));

      for (;;)
      {
        std::optional<Bytes> frame = ch.try_recv();
        if (!frame)
          return; /* client closed the connection: normal end of run */
        dispatch(ch, *frame);
      }
    }
    catch (const std::exception &)
    {
      /* A malformed or disconnected peer ends this connection; the process
       * keeps running (other parties, other tests) rather than crashing. */
      return;
    }
  }

  void dispatch(Channel &ch, const Bytes &frame)
  {
    Reader r(frame);
    const auto type = static_cast<Msg>(r.u8());
    const std::uint64_t req_id = r.u64();

    try
    {
      switch (type)
      {
      case Msg::EvalReq:
        handle_eval(ch, r, req_id);
        break;
      case Msg::NextReq:
        handle_next(ch, r, req_id);
        break;
      default:
        ch.send(make_error(req_id, "unexpected message type"));
      }
    }
    catch (const std::exception &e)
    {
      ch.send(make_error(req_id, e.what()));
    }
  }

  void handle_eval(Channel &ch, Reader &r, std::uint64_t req_id)
  {
    const std::uint64_t epoch = r.u64();
    const std::uint32_t count = r.u32();
    if (count == 0 || count > kMaxBatch)
      throw ProtocolError("EvalReq: bad batch size");
    std::vector<Bytes> xs;
    xs.reserve(count);
    for (std::uint32_t k = 0; k < count; ++k)
      xs.push_back(r.bytes(kMaxInputBytes));
    r.expect_end();

    Mpz share_copy;
    std::uint64_t my_epoch;
    {
      std::lock_guard<std::mutex> lock(mu_);
      share_copy = share_;
      my_epoch = epoch_;
    }
    if (epoch != my_epoch)
      throw ProtocolError("epoch mismatch: server is at epoch " + std::to_string(my_epoch)
                          + ", request was for " + std::to_string(epoch));

    Writer w;
    w.u8(static_cast<std::uint8_t>(Msg::EvalResp));
    w.u64(req_id);
    w.u64(my_epoch);
    w.u32(count);
    for (const Bytes &x : xs)
      w.qfi(S_.dprf().eval(share_copy, x));
    ch.send(w.take());
  }

  void handle_next(Channel &ch, Reader &r, std::uint64_t req_id)
  {
    const std::uint64_t from_epoch = r.u64();
    const std::uint32_t invoker = r.u32();
    const Mpz shift_share = r.mpz();
    r.expect_end();
    if (invoker == 0 || invoker > S_.n())
      throw ProtocolError("NextReq: invoker out of range");

    std::uint64_t new_epoch;
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (from_epoch != epoch_)
        throw ProtocolError("epoch mismatch: server is at epoch " + std::to_string(epoch_)
                            + ", request assumed " + std::to_string(from_epoch));
      Utse1Scheme::apply_shift(share_, shift_share);
      new_epoch = ++epoch_;
    }

    Writer w;
    w.u8(static_cast<std::uint8_t>(Msg::NextAck));
    w.u64(req_id);
    w.u64(new_epoch);
    ch.send(w.take());
  }

  unsigned id_;
  mutable std::mutex mu_;
  Mpz share_;
  std::uint64_t epoch_ = 0;
  const Utse1Scheme &S_;
  Socket listen_sock_;
  Counters counters_;
};

} /* namespace net */
} /* namespace utse */
