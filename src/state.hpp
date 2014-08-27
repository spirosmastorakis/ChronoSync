/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2014 University of California, Los Angeles
 *
 * This file is part of ChronoSync, synchronization library for distributed realtime
 * applications for NDN.
 *
 * ChronoSync is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ChronoSync is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ChronoSync, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Zhenkai Zhu <http://irl.cs.ucla.edu/~zhenkai/>
 * @author Chaoyi Bian <bcy@pku.edu.cn>
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 * @author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef CHRONOSYNC_STATE_HPP
#define CHRONOSYNC_STATE_HPP

#include "tlv.hpp"
#include "leaf-container.hpp"
#include <ndn-cxx/util/digest.hpp>

namespace chronosync {

class State;
typedef shared_ptr<State> StatePtr;
typedef shared_ptr<const State> ConstStatePtr;

/**
 * @brief Abstraction of state tree.
 *
 * State is used to represent sync tree, it is also the base class of DiffState,
 * which represent the diff between two states. Due to the second usage, State
 * should be copyable.
 */
class State
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

  virtual
  ~State();

  /**
   * @brief Add or update leaf to the sync tree
   *
   * @param info session name of the leaf
   * @param seq  sequence number of the leaf
   * @return 3-tuple (isInserted, isUpdated, oldSeqNo)
   */
  boost::tuple<bool, bool, SeqNo>
  update(const Name& info, const SeqNo& seq);

  /**
   * @brief Get state leaves
   */
  const LeafContainer&
  getLeaves() const
  {
    return m_leaves;
  }

  ndn::ConstBufferPtr
  getRootDigest() const;

  /**
   * @brief Reset the sync tree, remove all state leaves
   */
  void
  reset();

  /**
   * @brief Combine `this' state and the supplied state
   *
   * The combination result contains all leaves in two states.
   * When leaves conflict, keep the one with largest seq.
   *
   * @param state another state to combine with
   * @return Combined state
   */
  State&
  operator+=(const State& state);

  /**
   * @brief Encode to a wire format
   */
  const Block&
  wireEncode() const;

  /**
   * @brief Decode from the wire format
   */
  void
  wireDecode(const Block& wire);

protected:
  template<bool T>
  size_t
  wireEncode(ndn::EncodingImpl<T>& block) const;

protected:
  LeafContainer m_leaves;

  mutable ndn::util::Sha256 m_digest;
  mutable Block m_wire;
};

} // namespace chronosync

#endif // CHRONOSYNC_STATE_HPP
