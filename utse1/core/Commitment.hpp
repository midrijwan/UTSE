// core/Commitment.hpp -- Definition 11: Com = (Setup, Commit).
//
//   Setup(1^lambda)     -> pp          (random public string)
//   Commit(m, pp; rho)  -> alpha = SHAKE256("UTSE1-Com-v1" || pp || m || rho)
//
// Random-oracle instantiation, as DiSE's implementation uses (AmmrClient hashes
// m || rho). Hiding: rho is uniform and never leaves the ciphertext's F_CL slot.
// Binding: two openings of one alpha are a SHAKE256 collision (256-bit output).
#pragma once

#include "core/Rng.hpp"

namespace utse {

class Commitment
{
public:
  static constexpr std::size_t kOutBytes = 32;

  /** Setup(1^lambda) -> pp */
  static Bytes setup(Rng &rng, std::size_t pp_bytes = 32) { return rng.bytes(pp_bytes); }

  /** Commit(m, pp; rho) -> alpha */
  static Bytes commit(const Bytes &pp, const Bytes &m, const Bytes &rho)
  {
    Shake256 h;
    h.update_framed(std::string("UTSE1-Com-v1"));
    h.update_framed(pp);
    h.update_framed(m);
    h.update_framed(rho);
    return h.finalize(kOutBytes);
  }
};

} /* namespace utse */
