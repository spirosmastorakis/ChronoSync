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

#include "logic.hpp"

#include "boost-test.hpp"

namespace chronosync {
namespace test {

using std::vector;

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

  Logic logic;
  std::map<Name, SeqNo> map;
};

class LogicFixture
{
public:
  LogicFixture()
    : syncPrefix("/ndn/broadcast/sync")
    , scheduler(io)
  {
    syncPrefix.appendVersion();
    userPrefix[0] = Name("/user0");
    userPrefix[1] = Name("/user1");
    userPrefix[2] = Name("/user2");

    faces[0] = make_shared<ndn::Face>(ref(io));
    faces[1] = make_shared<ndn::Face>(ref(io));
    faces[2] = make_shared<ndn::Face>(ref(io));
  }

  Name syncPrefix;
  Name userPrefix[3];

  boost::asio::io_service io;
  shared_ptr<ndn::Face> faces[3];
  ndn::Scheduler scheduler;
  shared_ptr<Handler> handler[3];
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
  ndn::Face face;
  BOOST_REQUIRE_NO_THROW(Logic(face, syncPrefix, userPrefix,
                               bind(onUpdate, _1)));
}

BOOST_AUTO_TEST_CASE(TwoBasic)
{
  scheduler.scheduleEvent(ndn::time::milliseconds(100),
    [this] { handler[0] = make_shared<Handler>(ref(*faces[0]), syncPrefix, userPrefix[0]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(200),
    [this] { handler[1] = make_shared<Handler>(ref(*faces[1]), syncPrefix, userPrefix[1]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(300), [this] { handler[0]->updateSeqNo(1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1000),
    [this] { BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1100), [this] { handler[0]->updateSeqNo(2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1800),
    [this] { BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1900), [this] { handler[1]->updateSeqNo(2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2600),
    [this] { BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2800), [this] { io.stop(); });

  io.run();
}

BOOST_AUTO_TEST_CASE(ThreeBasic)
{
  scheduler.scheduleEvent(ndn::time::milliseconds(100),
    [this] { handler[0] = make_shared<Handler>(ref(*faces[0]), syncPrefix, userPrefix[0]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(200),
    [this] { handler[1] = make_shared<Handler>(ref(*faces[1]), syncPrefix, userPrefix[1]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(300),
    [this] { handler[2] = make_shared<Handler>(ref(*faces[2]), syncPrefix, userPrefix[2]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(500), [this] { handler[0]->updateSeqNo(1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1400),
    [this] { BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1450),
    [this] { BOOST_CHECK_EQUAL(handler[2]->map[handler[0]->logic.getSessionName()], 1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1500), [this] { handler[1]->updateSeqNo(2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2400),
    [this] { BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2450),
    [this] { BOOST_CHECK_EQUAL(handler[2]->map[handler[1]->logic.getSessionName()], 2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2500), [this] { handler[2]->updateSeqNo(4); });

  scheduler.scheduleEvent(ndn::time::milliseconds(4400),
    [this] { BOOST_CHECK_EQUAL(handler[0]->map[handler[2]->logic.getSessionName()], 4); });

  scheduler.scheduleEvent(ndn::time::milliseconds(4450),
    [this] { BOOST_CHECK_EQUAL(handler[1]->map[handler[2]->logic.getSessionName()], 4); });

  scheduler.scheduleEvent(ndn::time::milliseconds(4500), [this] { io.stop(); });

  io.run();
}

BOOST_AUTO_TEST_CASE(ResetRecover)
{
  scheduler.scheduleEvent(ndn::time::milliseconds(100),
    [this] { handler[0] = make_shared<Handler>(ref(*faces[0]), syncPrefix, userPrefix[0]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(200),
    [this] { handler[1] = make_shared<Handler>(ref(*faces[1]), syncPrefix, userPrefix[1]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(500), [this] { handler[0]->updateSeqNo(1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1400),
    [this] { BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1500), [this] { handler[1]->updateSeqNo(2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2400),
    [this] { BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2500),
    [this] { handler[2] = make_shared<Handler>(ref(*faces[2]), syncPrefix, userPrefix[2]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(3000),
    [this] { BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(3050),
    [this] { BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(3100), [this] { handler[2]->updateSeqNo(4); });

  scheduler.scheduleEvent(ndn::time::milliseconds(4000),
    [this] { BOOST_CHECK_EQUAL(handler[1]->map[handler[2]->logic.getSessionName()], 4); });

  scheduler.scheduleEvent(ndn::time::milliseconds(4050),
    [this] { BOOST_CHECK_EQUAL(handler[0]->map[handler[2]->logic.getSessionName()], 4); });


  scheduler.scheduleEvent(ndn::time::milliseconds(4500), [this] { io.stop(); });

  io.run();
}

BOOST_AUTO_TEST_CASE(RecoverConflict)
{
  scheduler.scheduleEvent(ndn::time::milliseconds(0),
    [this] { handler[0] = make_shared<Handler>(ref(*faces[0]), syncPrefix, userPrefix[0]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(50),
    [this] { handler[1] = make_shared<Handler>(ref(*faces[1]), syncPrefix, userPrefix[1]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(100),
    [this] { handler[2] = make_shared<Handler>(ref(*faces[2]), syncPrefix, userPrefix[2]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(500), [this] { handler[0]->updateSeqNo(1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1400),
    [this] { BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1400),
    [this] { BOOST_CHECK_EQUAL(handler[2]->map[handler[0]->logic.getSessionName()], 1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1500), [this] { handler[1]->updateSeqNo(2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1500), [this] { handler[2]->updateSeqNo(4); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2400),
    [this] { BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2450),
    [this] { BOOST_CHECK_EQUAL(handler[0]->map[handler[2]->logic.getSessionName()], 4); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2500),
    [this] { BOOST_CHECK_EQUAL(handler[1]->map[handler[2]->logic.getSessionName()], 4); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2550),
    [this] { BOOST_CHECK_EQUAL(handler[2]->map[handler[1]->logic.getSessionName()], 2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(4500), [this] { io.stop(); });

  io.run();
}

BOOST_AUTO_TEST_CASE(MultipleUserUnderOneLogic)
{
  scheduler.scheduleEvent(ndn::time::milliseconds(0),
    [this] { handler[0] = make_shared<Handler>(ref(*faces[0]), syncPrefix, userPrefix[0]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(50),
    [this] { handler[1] = make_shared<Handler>(ref(*faces[1]), syncPrefix, userPrefix[2]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(100),
    [this] { handler[0]->logic.addUserNode(userPrefix[1]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(500), [this] { handler[0]->updateSeqNo(1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1400),
    [this] { BOOST_CHECK_EQUAL(handler[1]->map[handler[0]->logic.getSessionName()], 1); });

  scheduler.scheduleEvent(ndn::time::milliseconds(1500),
    [this] { handler[0]->logic.updateSeqNo(2, userPrefix[1]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(2400),
    [this] {
             Name sessionName = handler[0]->logic.getSessionName(userPrefix[1]);
             BOOST_CHECK_EQUAL(handler[1]->map[sessionName], 2);
           });

  scheduler.scheduleEvent(ndn::time::milliseconds(2500), [this] { handler[1]->updateSeqNo(4); });

  scheduler.scheduleEvent(ndn::time::milliseconds(3200),
    [this] { BOOST_CHECK_EQUAL(handler[0]->map[handler[1]->logic.getSessionName()], 4); });

  scheduler.scheduleEvent(ndn::time::milliseconds(3300),
    [this] { handler[0]->logic.removeUserNode(userPrefix[0]); });

  scheduler.scheduleEvent(ndn::time::milliseconds(4500),
    [this] { BOOST_CHECK_EQUAL(handler[1]->logic.getSessionNames().size(), 2); });

  scheduler.scheduleEvent(ndn::time::milliseconds(5000), [this] { io.stop(); });

  io.run();
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace chronosync
