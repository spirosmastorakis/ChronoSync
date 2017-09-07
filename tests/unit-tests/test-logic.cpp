/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2017 University of California, Los Angeles
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

#include "logic.hpp"

#include "boost-test.hpp"
#include "../identity-management-fixture.hpp"

#include "dummy-forwarder.hpp"

namespace chronosync {
namespace test {

using std::vector;
using ndn::chronosync::DummyForwarder;

class Handler
{
public:
  Handler(ndn::Face& face,
          const Name& syncPrefix,
          const Name& userPrefix)
    : logic(face,
            syncPrefix,
            userPrefix,
            bind(&Handler::onUpdate, this, _1))
  {
  }

  void
  onUpdate(const vector<MissingDataInfo>& v)
  {
    for (size_t i = 0; i < v.size(); i++) {
      update(v[i].session, v[i].high, v[i].low);
    }
  }

  void
  update(const Name& p, const SeqNo& high, const SeqNo& low)
  {
    map[p] = high;
  }

  void
  updateSeqNo(const SeqNo& seqNo)
  {
    logic.updateSeqNo(seqNo);
  }

public:
  Logic logic;
  std::map<Name, SeqNo> map;
};

class LogicFixture : public ndn::tests::IdentityManagementTimeFixture
{
public:
  LogicFixture()
    : syncPrefix("/ndn/broadcast/sync")
    , fw(io, m_keyChain)
  {
    syncPrefix.appendVersion();
    userPrefix[0] = Name("/user0");
    userPrefix[1] = Name("/user1");
    userPrefix[2] = Name("/user2");
    userPrefix[3] = Name("/user3");
  }

public:
  Name syncPrefix;
  Name userPrefix[4];

  DummyForwarder fw;
  // std::unique_ptr<DummyClientFace> faces[4];
  shared_ptr<Handler> handler[4];

  // size_t readInterestOffset[4];
  // size_t readDataOffset[4];
};

BOOST_FIXTURE_TEST_SUITE(LogicTests, LogicFixture)

void
onUpdate(const vector<MissingDataInfo>& v)
{
}

BOOST_AUTO_TEST_CASE(Constructor)
{
  Name syncPrefix("/ndn/broadcast/sync");
  Name userPrefix("/user");
  ndn::util::DummyClientFace face(io, {true, true});
  BOOST_REQUIRE_NO_THROW(Logic(face, syncPrefix, userPrefix, bind(onUpdate, _1)));
}

BOOST_AUTO_TEST_CASE(TwoBasic)
{
  handler[0] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[0]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[1] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[1]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[0]->updateSeqNo(1);

  advanceClocks(ndn::time::milliseconds(10), 100);

  BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[0]->updateSeqNo(2);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 2);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[1]->updateSeqNo(2);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 2);
}

BOOST_AUTO_TEST_CASE(ThreeBasic)
{
  handler[0] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[0]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[1] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[1]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[2] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[2]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[0]->updateSeqNo(1);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1);
  BOOST_CHECK_EQUAL(handler[2]->map[handler[0]->logic.getSessionName()], 1);

  handler[1]->updateSeqNo(2);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 2);
  BOOST_CHECK_EQUAL(handler[2]->map[handler[1]->logic.getSessionName()], 2);

  handler[2]->updateSeqNo(4);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[2]->logic.getSessionName()], 4);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[2]->logic.getSessionName()], 4);
}

BOOST_AUTO_TEST_CASE(ResetRecover)
{
  handler[0] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[0]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[1] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[1]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[0]->updateSeqNo(1);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1);

  handler[1]->updateSeqNo(2);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 2);

  advanceClocks(ndn::time::milliseconds(10), 100);
  handler[2] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[2]);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[2]->map[handler[0]->logic.getSessionName()], 1);
  BOOST_CHECK_EQUAL(handler[2]->map[handler[1]->logic.getSessionName()], 2);

  handler[2]->updateSeqNo(4);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[2]->logic.getSessionName()], 4);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[2]->logic.getSessionName()], 4);
}

BOOST_AUTO_TEST_CASE(RecoverConflict)
{
  handler[0] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[0]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[1] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[1]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[2] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[2]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[0]->updateSeqNo(1);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1);
  BOOST_CHECK_EQUAL(handler[2]->map[handler[0]->logic.getSessionName()], 1);

  handler[1]->updateSeqNo(2);
  handler[2]->updateSeqNo(4);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 2);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[2]->logic.getSessionName()], 4);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[2]->logic.getSessionName()], 4);
  BOOST_CHECK_EQUAL(handler[2]->map[handler[1]->logic.getSessionName()], 2);
}

BOOST_AUTO_TEST_CASE(PartitionRecover)
{
  handler[0] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[0]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[1] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[1]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[2] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[2]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[3] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[3]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[0]->updateSeqNo(1);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1);
  BOOST_CHECK_EQUAL(handler[2]->map[handler[0]->logic.getSessionName()], 1);
  BOOST_CHECK_EQUAL(handler[3]->map[handler[0]->logic.getSessionName()], 1);

  handler[2]->updateSeqNo(2);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[2]->logic.getSessionName()], 2);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[2]->logic.getSessionName()], 2);
  BOOST_CHECK_EQUAL(handler[3]->map[handler[2]->logic.getSessionName()], 2);

  // Network Partition start

  handler[1]->updateSeqNo(3);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 3);
  handler[2]->map[handler[1]->logic.getSessionName()] = 0;
  handler[3]->map[handler[1]->logic.getSessionName()] = 0;

  handler[3]->updateSeqNo(4);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[2]->map[handler[3]->logic.getSessionName()], 4);
  handler[0]->map[handler[3]->logic.getSessionName()] = 0;
  handler[1]->map[handler[3]->logic.getSessionName()] = 0;

  // Network partition over

  handler[0]->updateSeqNo(5);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 5);
  BOOST_CHECK_EQUAL(handler[2]->map[handler[0]->logic.getSessionName()], 5);
  BOOST_CHECK_EQUAL(handler[3]->map[handler[0]->logic.getSessionName()], 5);

  handler[2]->updateSeqNo(6);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[2]->logic.getSessionName()], 6);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[2]->logic.getSessionName()], 6);
  BOOST_CHECK_EQUAL(handler[3]->map[handler[2]->logic.getSessionName()], 6);
}

BOOST_AUTO_TEST_CASE(MultipleUserUnderOneLogic)
{
  handler[0] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[0]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[1] = make_shared<Handler>(ref(fw.addFace()), syncPrefix, userPrefix[2]);
  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[0]->logic.addUserNode(userPrefix[1]);

  advanceClocks(ndn::time::milliseconds(10), 100);

  handler[0]->updateSeqNo(1);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1);

  handler[0]->logic.updateSeqNo(2, userPrefix[1]);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName(userPrefix[1])], 2);

  handler[1]->updateSeqNo(4);

  advanceClocks(ndn::time::milliseconds(10), 100);
  BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 4);

  handler[0]->logic.removeUserNode(userPrefix[0]);

  advanceClocks(ndn::time::milliseconds(50), 100);
  BOOST_CHECK_EQUAL(handler[1]->logic.getSessionNames().size(), 2);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace chronosync
