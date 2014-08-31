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

  void
  check(const Name& sessionName, const SeqNo& seqNo)
  {
    BOOST_CHECK_EQUAL(map[sessionName], seqNo);
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

  void
  createHandler(size_t idx)
  {
    handler[idx] = make_shared<Handler>(ref(*faces[idx]), syncPrefix, userPrefix[idx]);
  }

  void
  updateSeqNo(size_t idx, const SeqNo& seqNo)
  {
    handler[idx]->updateSeqNo(seqNo);
  }

  void
  checkSeqNo(size_t sIdx, size_t dIdx, const SeqNo& seqNo)
  {
    handler[sIdx]->check(handler[dIdx]->logic.getSessionName(), seqNo);
  }

  void
  terminate()
  {
    io.stop();
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
                          bind(&LogicFixture::createHandler, this, 0));

  scheduler.scheduleEvent(ndn::time::milliseconds(200),
                          bind(&LogicFixture::createHandler, this, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(300),
                          bind(&LogicFixture::updateSeqNo, this, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(1000),
                          bind(&LogicFixture::checkSeqNo, this, 1, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(1100),
                          bind(&LogicFixture::updateSeqNo, this, 0, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(1800),
                          bind(&LogicFixture::checkSeqNo, this, 1, 0, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(1900),
                          bind(&LogicFixture::updateSeqNo, this, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(2600),
                          bind(&LogicFixture::checkSeqNo, this, 0, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(2800),
                          bind(&LogicFixture::terminate, this));

  io.run();
}

BOOST_AUTO_TEST_CASE(ThreeBasic)
{
  scheduler.scheduleEvent(ndn::time::milliseconds(100),
                          bind(&LogicFixture::createHandler, this, 0));

  scheduler.scheduleEvent(ndn::time::milliseconds(200),
                          bind(&LogicFixture::createHandler, this, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(300),
                          bind(&LogicFixture::createHandler, this, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(500),
                          bind(&LogicFixture::updateSeqNo, this, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(1400),
                          bind(&LogicFixture::checkSeqNo, this, 1, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(1450),
                          bind(&LogicFixture::checkSeqNo, this, 2, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(1500),
                          bind(&LogicFixture::updateSeqNo, this, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(2400),
                          bind(&LogicFixture::checkSeqNo, this, 0, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(2450),
                          bind(&LogicFixture::checkSeqNo, this, 2, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(2500),
                          bind(&LogicFixture::updateSeqNo, this, 2, 4));

  scheduler.scheduleEvent(ndn::time::milliseconds(4400),
                          bind(&LogicFixture::checkSeqNo, this, 0, 2, 4));

  scheduler.scheduleEvent(ndn::time::milliseconds(4450),
                          bind(&LogicFixture::checkSeqNo, this, 1, 2, 4));

  scheduler.scheduleEvent(ndn::time::milliseconds(4500),
                          bind(&LogicFixture::terminate, this));

  io.run();
}

BOOST_AUTO_TEST_CASE(ResetRecover)
{
  scheduler.scheduleEvent(ndn::time::milliseconds(100),
                          bind(&LogicFixture::createHandler, this, 0));

  scheduler.scheduleEvent(ndn::time::milliseconds(200),
                          bind(&LogicFixture::createHandler, this, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(500),
                          bind(&LogicFixture::updateSeqNo, this, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(1400),
                          bind(&LogicFixture::checkSeqNo, this, 1, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(1500),
                          bind(&LogicFixture::updateSeqNo, this, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(2400),
                          bind(&LogicFixture::checkSeqNo, this, 0, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(2500),
                          bind(&LogicFixture::createHandler, this, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(3000),
                          bind(&LogicFixture::checkSeqNo, this, 1, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(3050),
                          bind(&LogicFixture::checkSeqNo, this, 0, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(3100),
                          bind(&LogicFixture::updateSeqNo, this, 2, 4));

  scheduler.scheduleEvent(ndn::time::milliseconds(4000),
                          bind(&LogicFixture::checkSeqNo, this, 1, 2, 4));

  scheduler.scheduleEvent(ndn::time::milliseconds(4050),
                          bind(&LogicFixture::checkSeqNo, this, 0, 2, 4));


  scheduler.scheduleEvent(ndn::time::milliseconds(4500),
                          bind(&LogicFixture::terminate, this));

  io.run();
}

BOOST_AUTO_TEST_CASE(RecoverConflict)
{
  scheduler.scheduleEvent(ndn::time::milliseconds(0),
                          bind(&LogicFixture::createHandler, this, 0));

  scheduler.scheduleEvent(ndn::time::milliseconds(50),
                          bind(&LogicFixture::createHandler, this, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(100),
                          bind(&LogicFixture::createHandler, this, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(500),
                          bind(&LogicFixture::updateSeqNo, this, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(1400),
                          bind(&LogicFixture::checkSeqNo, this, 1, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(1400),
                          bind(&LogicFixture::checkSeqNo, this, 2, 0, 1));

  scheduler.scheduleEvent(ndn::time::milliseconds(1500),
                          bind(&LogicFixture::updateSeqNo, this, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(1500),
                          bind(&LogicFixture::updateSeqNo, this, 2, 4));

  scheduler.scheduleEvent(ndn::time::milliseconds(2400),
                          bind(&LogicFixture::checkSeqNo, this, 0, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(2450),
                          bind(&LogicFixture::checkSeqNo, this, 0, 2, 4));

  scheduler.scheduleEvent(ndn::time::milliseconds(2500),
                          bind(&LogicFixture::checkSeqNo, this, 1, 2, 4));

  scheduler.scheduleEvent(ndn::time::milliseconds(2550),
                          bind(&LogicFixture::checkSeqNo, this, 2, 1, 2));

  scheduler.scheduleEvent(ndn::time::milliseconds(4500),
                          bind(&LogicFixture::terminate, this));

  io.run();
}


BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace chronosync
