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
 */

#include "leaf.hpp"
#include <ndn-cxx/encoding/buffer-stream.hpp>

#include "boost-test.hpp"


namespace chronosync {
namespace test {

BOOST_AUTO_TEST_SUITE(LeafTests)

BOOST_AUTO_TEST_CASE(LeafBasic)
{
  Name userPrefix("/test/name");
  BOOST_CHECK_NO_THROW(Leaf leaf(userPrefix, 1, 10));

  Leaf leaf(userPrefix, 1, 10);
  Name sessionName = userPrefix;
  sessionName.appendNumber(1);
  BOOST_CHECK_EQUAL(leaf.getSessionName(), sessionName);
  BOOST_CHECK_EQUAL(leaf.getSeq(), 10);

  leaf.setSeq(9);
  BOOST_CHECK_EQUAL(leaf.getSeq(), 10);
  leaf.setSeq(11);
  BOOST_CHECK_EQUAL(leaf.getSeq(), 11);
}

BOOST_AUTO_TEST_CASE(LeafDigest)
{
  using namespace CryptoPP;

  std::string hexResult = "05fe7f728d3341e9eff82526277b02171044124d0a52e8c4610982261c20de2b";
  ndn::OBufferStream os;
  StringSource(hexResult, true, new HexDecoder(new FileSink(os)));
  ndn::ConstBufferPtr result = os.buf();

  Name userPrefix("/test/name");
  Leaf leaf(userPrefix, 1, 10);

  BOOST_CHECK_NO_THROW(leaf.getDigest());

  ndn::ConstBufferPtr digest = leaf.getDigest();
  BOOST_CHECK(*result == *digest);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace chronosync
