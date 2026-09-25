// net/Protocol.hpp -- the messages parties exchange.
//
//   Hello    / HelloAck : u8 type, u32 version, u32 party id, bytes fingerprint
//   EvalReq             : u8 type, u64 req_id, u64 epoch, u32 count, count x bytes(j||alpha)
//   EvalResp            : u8 type, u64 req_id, u64 epoch, u32 count, count x form(h_i)
//   NextReq             : u8 type, u64 req_id, u64 from_epoch, u32 invoker, mpz(delta^(i))
//   NextAck             : u8 type, u64 req_id, u64 new_epoch
//   Error               : u8 type, u64 req_id, str message
//
// Every reply starts with (type, req_id). Every frame is length-prefixed (Socket.hpp).
#pragma once

#include "core/Utse1Scheme.hpp"
#include "core/Wire.hpp"

namespace utse {
namespace net {

class ProtocolError : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

enum class Msg : std::uint8_t
{
  Hello = 1,
  HelloAck = 2,
  EvalReq = 3,
  EvalResp = 4,
  NextReq = 5,
  NextAck = 6,
  Error = 7
};

constexpr std::uint32_t kProtocolVersion = 1;
constexpr std::size_t kMaxBatch = std::size_t(1) << 16;
constexpr std::size_t kMaxInputBytes = 1024;
constexpr std::size_t kMaxErrorBytes = 1024;
constexpr std::size_t kMaxHelloFrame = 4096;

struct Hello
{
  std::uint32_t version = 0;
  std::uint32_t id = 0;
  Bytes fingerprint;
};

inline Bytes make_hello(Msg type, unsigned id, const Bytes &fingerprint)
{
  Writer w;
  w.u8(static_cast<std::uint8_t>(type));
  w.u32(kProtocolVersion);
  w.u32(static_cast<std::uint32_t>(id));
  w.bytes(fingerprint);
  return w.take();
}

inline Bytes make_error(std::uint64_t req_id, const std::string &what)
{
  Writer w;
  w.u8(static_cast<std::uint8_t>(Msg::Error));
  w.u64(req_id);
  w.str(what.substr(0, kMaxErrorBytes));
  return w.take();
}

/** Parses a Hello/HelloAck; an Error frame becomes a ProtocolError. */
inline Hello parse_hello(const Bytes &frame, Msg expected)
{
  Reader r(frame);
  const auto type = static_cast<Msg>(r.u8());
  if (type == Msg::Error)
  {
    r.u64();
    throw ProtocolError("connection refused by the peer: " + r.str(kMaxErrorBytes));
  }
  if (type != expected)
    throw ProtocolError("unexpected handshake message");
  Hello h;
  h.version = r.u32();
  h.id = r.u32();
  h.fingerprint = r.bytes(256);
  r.expect_end();
  return h;
}

inline Bytes make_eval_req(std::uint64_t req_id, std::uint64_t epoch, const std::vector<Bytes> &xs)
{
  Writer w;
  w.u8(static_cast<std::uint8_t>(Msg::EvalReq));
  w.u64(req_id);
  w.u64(epoch);
  w.u32(static_cast<std::uint32_t>(xs.size()));
  for (const Bytes &x : xs)
    w.bytes(x);
  return w.take();
}

inline Bytes make_next_req(std::uint64_t req_id, std::uint64_t from_epoch, unsigned invoker,
                           const Mpz &shift_share)
{
  Writer w;
  w.u8(static_cast<std::uint8_t>(Msg::NextReq));
  w.u64(req_id);
  w.u64(from_epoch);
  w.u32(static_cast<std::uint32_t>(invoker));
  w.mpz(shift_share);
  return w.take();
}

struct ReplyHeader
{
  Msg type = Msg::Error;
  std::uint64_t req_id = 0;
};

inline ReplyHeader peek_reply(const Bytes &frame)
{
  Reader r(frame);
  ReplyHeader h;
  h.type = static_cast<Msg>(r.u8());
  h.req_id = r.u64();
  return h;
}

} /* namespace net */
} /* namespace utse */
