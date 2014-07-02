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
 */

#ifndef SYNC_LEAF_H
#define SYNC_LEAF_H

#include "sync-seq-no.h"
#include "sync-name-info.h"

namespace Sync {

/**
 * \ingroup sync
 * @brief Sync tree leaf
 */
class Leaf
{
public:
  /**
   * @brief Constructor
   * @param info Smart pointer to leaf's name
   * @param seq  Initial sequence number of the pointer
   */
  Leaf (NameInfoConstPtr info, const SeqNo &seq);
  virtual ~Leaf ();

  /**
   * @brief Get name of the leaf
   */
  NameInfoConstPtr
  getInfo () const { return m_info; }

  /**
   * @brief Get sequence number of the leaf
   */
  const SeqNo&
  getSeq () const { return m_seq; }

  /**
   * @brief Update sequence number of the leaf
   * @param seq Sequence number
   *
   * Sequence number is updated to the largest value among this->m_seq and seq
   */
  virtual void
  setSeq (const SeqNo &seq);

private:
  NameInfoConstPtr m_info;
  SeqNo m_seq;
};

typedef boost::shared_ptr<Leaf> LeafPtr;
typedef boost::shared_ptr<const Leaf> LeafConstPtr;

inline std::ostream &
operator << (std::ostream &os, const Leaf &leaf)
{
  os << *leaf.getInfo () << "(" << leaf.getSeq () << ")";
  return os;
}

} // Sync

#endif // SYNC_LEAF_H
