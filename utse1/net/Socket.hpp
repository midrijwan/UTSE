// net/Socket.hpp -- minimal POSIX TCP transport: RAII sockets and length-framed messages.
//
// DiSE uses cryptoTools' Session/Channel, which pulls in Boost (plus relic,
// coproto, ...) through its CMake. The protocol only needs "send a message to
// party i, receive its reply", so this implements exactly that on BSD sockets:
// Linux, macOS and WSL, no third-party dependency.
#pragma once

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <optional>
#include <string>
#include <thread>

#include "core/Util.hpp"

namespace utse {
namespace net {

class NetError : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

inline std::string sys_error(const std::string &what)
{
  return what + ": " + std::strerror(errno);
}

/** Owns a file descriptor. Move-only. */
class Socket
{
public:
  Socket() = default;
  explicit Socket(int fd) : fd_(fd) {}
  ~Socket() { close(); }

  Socket(Socket &&o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  Socket &operator=(Socket &&o) noexcept
  {
    if (this != &o)
    {
      close();
      fd_ = o.fd_;
      o.fd_ = -1;
    }
    return *this;
  }
  Socket(const Socket &) = delete;
  Socket &operator=(const Socket &) = delete;

  int fd() const { return fd_; }
  bool valid() const { return fd_ >= 0; }

  void shutdown_both()
  {
    if (fd_ >= 0)
      ::shutdown(fd_, SHUT_RDWR);
  }

  void close()
  {
    if (fd_ >= 0)
    {
      ::close(fd_);
      fd_ = -1;
    }
  }

private:
  int fd_ = -1;
};

struct Counters
{
  std::atomic<std::uint64_t> bytes_out{0};
  std::atomic<std::uint64_t> bytes_in{0};
  std::atomic<std::uint64_t> frames_out{0};
  std::atomic<std::uint64_t> frames_in{0};
};

constexpr std::size_t kMaxFrame = std::size_t(64) << 20;

inline void configure(int fd)
{
  int one = 1;
  ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
  ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
}

inline void set_recv_timeout(int fd, std::chrono::milliseconds timeout)
{
  timeval tv{};
  tv.tv_sec = static_cast<decltype(tv.tv_sec)>(timeout.count() / 1000);
  tv.tv_usec = static_cast<decltype(tv.tv_usec)>((timeout.count() % 1000) * 1000);
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

inline void write_all(int fd, const unsigned char *p, std::size_t n)
{
  while (n > 0)
  {
#ifdef MSG_NOSIGNAL
    const ssize_t k = ::send(fd, p, n, MSG_NOSIGNAL);
#else
    const ssize_t k = ::send(fd, p, n, 0);
#endif
    if (k < 0)
    {
      if (errno == EINTR)
        continue;
      throw NetError(sys_error("send"));
    }
    p += k;
    n -= static_cast<std::size_t>(k);
  }
}

/** Returns false on a clean EOF before the first byte (only if eof_ok). */
inline bool read_all(int fd, unsigned char *p, std::size_t n, bool eof_ok)
{
  std::size_t got = 0;
  while (got < n)
  {
    const ssize_t k = ::recv(fd, p + got, n - got, 0);
    if (k == 0)
    {
      if (eof_ok && got == 0)
        return false;
      throw NetError("connection closed in the middle of a message");
    }
    if (k < 0)
    {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        throw NetError("timed out waiting for the peer");
      throw NetError(sys_error("recv"));
    }
    got += static_cast<std::size_t>(k);
  }
  return true;
}

/** Frame = 4-byte big-endian length || payload. */
inline void send_frame(int fd, const Bytes &payload, Counters *c = nullptr)
{
  if (payload.size() > kMaxFrame)
    throw NetError("outgoing frame too large");
  Bytes frame = u32be(static_cast<std::uint32_t>(payload.size()));
  append(frame, payload);
  write_all(fd, frame.data(), frame.size());
  if (c != nullptr)
  {
    c->bytes_out += frame.size();
    ++c->frames_out;
  }
}

/** nullopt: the peer closed the connection cleanly between frames. */
inline std::optional<Bytes> recv_frame(int fd, std::size_t max_len, Counters *c = nullptr)
{
  unsigned char hdr[4];
  if (!read_all(fd, hdr, 4, true))
    return std::nullopt;
  const std::uint32_t len = load_u32be(hdr);
  if (len > max_len)
    throw NetError("incoming frame exceeds the size limit");
  Bytes payload(len);
  if (len != 0)
    read_all(fd, payload.data(), len, false);
  if (c != nullptr)
  {
    c->bytes_in += 4 + static_cast<std::uint64_t>(len);
    ++c->frames_in;
  }
  return payload;
}

/** A framed, owned connection. Used by one thread at a time. */
class Channel
{
public:
  Channel() = default;
  Channel(Socket s, Counters *c) : sock_(std::move(s)), counters_(c) {}

  void send(const Bytes &payload) { send_frame(sock_.fd(), payload, counters_); }

  Bytes recv(std::size_t max_len = kMaxFrame)
  {
    std::optional<Bytes> f = recv_frame(sock_.fd(), max_len, counters_);
    if (!f)
      throw NetError("the peer closed the connection");
    return std::move(*f);
  }

  /** nullopt on a clean close between frames; throws on any other error. */
  std::optional<Bytes> try_recv(std::size_t max_len = kMaxFrame)
  {
    return recv_frame(sock_.fd(), max_len, counters_);
  }

  bool valid() const { return sock_.valid(); }

  void close()
  {
    sock_.shutdown_both();
    sock_.close();
  }

private:
  Socket sock_;
  Counters *counters_ = nullptr;
};

/** Bind and listen; port 0 picks a free port, returned in bound_port. */
inline Socket listen_tcp(const std::string &host, std::uint16_t port, std::uint16_t &bound_port)
{
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  addrinfo *res = nullptr;
  const std::string service = std::to_string(port);
  const int rc =
      ::getaddrinfo(host.empty() ? nullptr : host.c_str(), service.c_str(), &hints, &res);
  if (rc != 0)
    throw NetError("getaddrinfo(" + host + "): " + ::gai_strerror(rc));

  std::string last_err = "no usable address";
  for (addrinfo *ai = res; ai != nullptr; ai = ai->ai_next)
  {
    Socket s(::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
    if (!s.valid())
    {
      last_err = sys_error("socket");
      continue;
    }
    int one = 1;
    ::setsockopt(s.fd(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (::bind(s.fd(), ai->ai_addr, ai->ai_addrlen) != 0)
    {
      last_err = sys_error("bind");
      continue;
    }
    if (::listen(s.fd(), 64) != 0)
    {
      last_err = sys_error("listen");
      continue;
    }
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (::getsockname(s.fd(), reinterpret_cast<sockaddr *>(&ss), &len) != 0)
    {
      last_err = sys_error("getsockname");
      continue;
    }
    if (ss.ss_family == AF_INET6)
      bound_port = ntohs(reinterpret_cast<sockaddr_in6 *>(&ss)->sin6_port);
    else
      bound_port = ntohs(reinterpret_cast<sockaddr_in *>(&ss)->sin_port);
    ::freeaddrinfo(res);
    return s;
  }
  ::freeaddrinfo(res);
  throw NetError("cannot listen on " + host + ":" + service + " (" + last_err + ")");
}

/** Connect, retrying until `timeout` (the peer may not be listening yet). */
inline Socket connect_tcp(const std::string &host, std::uint16_t port,
                          std::chrono::milliseconds timeout)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  const std::string service = std::to_string(port);
  std::string last_err = "no attempt";
  for (;;)
  {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &res);
    if (rc != 0)
    {
      last_err = std::string("getaddrinfo: ") + ::gai_strerror(rc);
    }
    else
    {
      for (addrinfo *ai = res; ai != nullptr; ai = ai->ai_next)
      {
        Socket s(::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (!s.valid())
        {
          last_err = sys_error("socket");
          continue;
        }
        if (::connect(s.fd(), ai->ai_addr, ai->ai_addrlen) == 0)
        {
          ::freeaddrinfo(res);
          configure(s.fd());
          return s;
        }
        last_err = sys_error("connect");
      }
      ::freeaddrinfo(res);
    }
    if (std::chrono::steady_clock::now() >= deadline)
      throw NetError("cannot reach " + host + ":" + service + " (" + last_err + ")");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

/** Wait for a connection, checking `stop` every 100 ms. Invalid Socket if stopped. */
inline Socket accept_tcp(int listen_fd, const std::atomic<bool> &stop)
{
  while (!stop.load())
  {
    pollfd pfd{};
    pfd.fd = listen_fd;
    pfd.events = POLLIN;
    const int r = ::poll(&pfd, 1, 100);
    if (r < 0)
    {
      if (errno == EINTR)
        continue;
      throw NetError(sys_error("poll"));
    }
    if (r == 0)
      continue;
    const int fd = ::accept(listen_fd, nullptr, nullptr);
    if (fd < 0)
    {
      if (errno == EINTR || errno == ECONNABORTED || errno == EAGAIN)
        continue;
      throw NetError(sys_error("accept"));
    }
    configure(fd);
    return Socket(fd);
  }
  return Socket();
}

} /* namespace net */
} /* namespace utse */
