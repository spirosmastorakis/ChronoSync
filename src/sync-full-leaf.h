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

#ifndef SYNC_FULL_LEAF_H
#define SYNC_FULL_LEAF_H

#include "sync-leaf.h"

namespace Sync {

/**
 * @ingroup sync
 * @brief SYNC leaf for the full state (with support of Digest calculation)
 */
class FullLeaf : public Leaf
{
public:
  /**
   * @brief Constructor to create an UPDATE diff leaf
   * @param info Smart pointer to leaf's name
   * @param seq  Initial sequence number of the pointer
   */
  FullLeaf (NameInfoConstPtr info, const SeqNo &seq);
  virtual ~FullLeaf () { }

  /**
   * @brief Get hash digest of the leaf
   *
   * The underlying Digest object is recalculated on every update or removal
   * (including updates of child classes)
   */
  const Digest &
  getDigest () const { return m_digest; }

  // from Leaf
  virtual void
  setSeq (const SeqNo &seq);

private:
  void
  updateDigest ();

private:
  Digest m_digest;
};

typedef boost::shared_ptr<FullLeaf> FullLeafPtr;
typedef boost::shared_ptr<const FullLeaf> FullLeafConstPtr;

} // Sync

#endif // SYNC_FULL_LEAF_H
