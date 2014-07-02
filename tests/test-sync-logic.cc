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

#include <boost/test/unit_test.hpp>
#include <boost/test/output_test_stream.hpp>
#include <map>
using boost::test_tools::output_test_stream;

#include <boost/make_shared.hpp>

#include <ndn-cxx/security/validator-null.hpp>
#include "sync-logic.h"
#include "sync-seq-no.h"

using namespace std;
using namespace boost;
using namespace Sync;

struct Handler
{
  string instance;

  Handler (const string &_instance)
  : instance (_instance)
  {
  }

  void wrapper (const vector<MissingDataInfo> &v) {
    int n = v.size();
    for (int i = 0; i < n; i++) {
      onUpdate (v[i].prefix, v[i].high, v[i].low);
    }
  }

  void onUpdate (const string &p/*prefix*/, const SeqNo &seq/*newSeq*/, const SeqNo &oldSeq/*oldSeq*/)
  {
    m_map[p] = seq.getSeq ();

    // cout << instance << "\t";
    // if (!oldSeq.isValid ())
    //   cout << "Inserted: " << p << " (" << seq << ")" << endl;
    // else
    //   cout << "Updated: " << p << "  ( " << oldSeq << ".." << seq << ")" << endl;
  }

  void onRemove (const string &p/*prefix*/)
  {
    // cout << instance << "\tRemoved: " << p << endl;
    m_map.erase (p);
  }

  map<string, uint32_t> m_map;
};

class TestCore
{
public:
  TestCore(ndn::shared_ptr<boost::asio::io_service> ioService)
    : m_ioService(ioService)
  {
    m_l[0] = 0;
    m_l[1] = 0;

    m_validator = ndn::make_shared<ndn::ValidatorNull>();
  }

  ~TestCore()
  {
    if(m_l[0] != 0)
      delete m_l[0];

    if(m_l[1] != 0)
      delete m_l[1];
  }

  void
  finish(ndn::shared_ptr<boost::asio::io_service> ioService)
  {
    ioService->stop();
  }

  void
  createSyncLogic(int index,
                  ndn::shared_ptr<Handler> h)
  {
    ndn::Name identity("/tmp-" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
    ndn::shared_ptr<ndn::IdentityCertificate> cert = m_keyChain.getCertificate(m_keyChain.createIdentity(identity));
    m_faces[index] = ndn::make_shared<ndn::Face>(m_ioService);
    m_l[index] = new SyncLogic(ndn::Name("/bcast"),
                               *cert,
                               m_validator, m_faces[index],
                               bind (&Handler::wrapper, &*h, _1),
                               bind (&Handler::onRemove, &*h, _1));
  }

  void
  getOldDigestForOne()
  {
    m_oldDigest = m_l[0]->getRootDigest();
  }

  void
  getNewDigestForOne()
  {
    m_newDigest = m_l[0]->getRootDigest();
  }

  void
  addLocalNamesForOne(ndn::Name name, uint64_t session, uint64_t seq)
  {
    m_l[0]->addLocalNames(name, session, seq);
  }

  void
  removeForOne(ndn::Name name)
  {
    m_l[0]->remove(name);
  }

  void
  checkDigest()
  {
    BOOST_CHECK(m_oldDigest != m_newDigest);
  }


public:
  ndn::KeyChain m_keyChain;
  ndn::shared_ptr<boost::asio::io_service> m_ioService;
  SyncLogic* m_l[2];
  ndn::shared_ptr<ndn::Face> m_faces[2];
  ndn::shared_ptr<ndn::ValidatorNull> m_validator;
  string m_oldDigest;
  string m_newDigest;
};

void
checkMapSize(ndn::shared_ptr<Handler> h, int size)
{ BOOST_CHECK_EQUAL (h->m_map.size (), size); }


BOOST_AUTO_TEST_CASE (SyncLogicTest)
{
  ndn::shared_ptr<boost::asio::io_service> ioService = ndn::make_shared<boost::asio::io_service>();
  ndn::Scheduler scheduler(*ioService);
  TestCore testCore(ioService);

  ndn::shared_ptr<Handler> h1 = ndn::make_shared<Handler>("1");
  ndn::shared_ptr<Handler> h2 = ndn::make_shared<Handler>("2");

  scheduler.scheduleEvent(ndn::time::milliseconds(0), ndn::bind(&TestCore::createSyncLogic, &testCore, 0, h1));
  scheduler.scheduleEvent(ndn::time::milliseconds(100), ndn::bind(&TestCore::getOldDigestForOne, &testCore));
  scheduler.scheduleEvent(ndn::time::milliseconds(200), ndn::bind(&TestCore::addLocalNamesForOne, &testCore, "/one", 1, 2));
  scheduler.scheduleEvent(ndn::time::milliseconds(300), ndn::bind(&checkMapSize, h1, 0));
  scheduler.scheduleEvent(ndn::time::milliseconds(400), ndn::bind(&TestCore::createSyncLogic, &testCore, 1, h2));
  scheduler.scheduleEvent(ndn::time::milliseconds(500), ndn::bind(&checkMapSize, h1, 0));
  scheduler.scheduleEvent(ndn::time::milliseconds(600), ndn::bind(&checkMapSize, h2, 1));
  scheduler.scheduleEvent(ndn::time::milliseconds(700), ndn::bind(&TestCore::removeForOne, &testCore, "/one"));
  scheduler.scheduleEvent(ndn::time::milliseconds(800), ndn::bind(&TestCore::getNewDigestForOne, &testCore));
  scheduler.scheduleEvent(ndn::time::milliseconds(900), ndn::bind(&TestCore::checkDigest, &testCore));
  scheduler.scheduleEvent(ndn::time::milliseconds(1000), ndn::bind(&TestCore::finish, &testCore, ioService));

  ioService->run();

}
