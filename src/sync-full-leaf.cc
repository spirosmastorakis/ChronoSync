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

#include "sync-full-leaf.h"
#include <boost/ref.hpp>

using namespace boost;

namespace Sync {

FullLeaf::FullLeaf (NameInfoConstPtr info, const SeqNo &seq)
  : Leaf (info, seq)
{
  updateDigest ();
}

void
FullLeaf::updateDigest ()
{
  m_digest.reset ();
  m_digest << getInfo ()->getDigest () << *getSeq ().getDigest ();
  m_digest.finalize ();
}

// from Leaf
void
FullLeaf::setSeq (const SeqNo &seq)
{
  Leaf::setSeq (seq);
  updateDigest ();
}

} // Sync
