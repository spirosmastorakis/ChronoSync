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

#include "socket.hpp"

#include "boost-test.hpp"

namespace chronosync {
namespace test {

using std::string;
using std::vector;
using std::map;

/**
 * @brief Emulate an app that use the Socket class
 *
 * The app has two types of data set: one is simply string while the other is integer array.
 * For each type of data set, the app has a specific fetching strategy.
 */
class SocketTestApp : noncopyable
{
public:
  SocketTestApp(const Name& syncPrefix,
                const Name& userPrefix,
                ndn::Face& face,
                bool isNum)
    : sum(0)
    , socket(syncPrefix,
             userPrefix,
             face,
             isNum ? bind(&SocketTestApp::fetchNumbers, this, _1) :
                     bind(&SocketTestApp::fetchAll, this, _1))
  {
  }

  void
  set(const shared_ptr<const Data>& dataPacket)
  {
    // std::cerr << "set Data" << std::endl;
    Name dataName(dataPacket->getName());
    string str2(reinterpret_cast<const char*>(dataPacket->getContent().value()),
                dataPacket->getContent().value_size());
    data.insert(make_pair(dataName, str2));
  }

  void
  set(Name name, const char* buf, int len)
  {
    string str2(buf, len);
    data.insert(make_pair(name, str2));
  }

  void
  setNum(const shared_ptr<const Data>& dataPacket)
  {
    // std::cerr << "setNum Data" << std::endl;
    size_t n = dataPacket->getContent().value_size() / 4;
    const uint32_t* numbers = reinterpret_cast<const uint32_t*>(dataPacket->getContent().value());
    for (size_t i = 0; i < n; i++) {
      sum += numbers[i];
    }
  }

  void
  setNum(Name name, const uint8_t* buf, int len)
  {
    BOOST_ASSERT(len >= 4);

    int n = len / 4;
    const uint32_t* numbers = reinterpret_cast<const uint32_t*>(buf);
    for (int i = 0; i < n; i++) {
      sum += numbers[i];
    }
  }

  void
  fetchAll(const vector<MissingDataInfo>& v)
  {
    // std::cerr << "fetchAll" << std::endl;
    for (int i = 0; i < v.size(); i++) {
      for(SeqNo s = v[i].low; s <= v[i].high; ++s) {
        socket.fetchData(v[i].session, s, [this] (const shared_ptr<const Data>& dataPacket) {
            this->set(dataPacket);
          });
      }
    }
  }

  void
  fetchNumbers(const vector<MissingDataInfo> &v)
  {
    // std::cerr << "fetchNumbers" << std::endl;
    for (int i = 0; i < v.size(); i++) {
      for(SeqNo s = v[i].low; s <= v[i].high; ++s) {
        socket.fetchData(v[i].session, s, [this] (const shared_ptr<const Data>& dataPacket) {
            this->setNum(dataPacket);
          });
      }
    }
  }

  string
  toString()
  {
    string str = "\n";
    for (map<Name, string>::iterator it = data.begin(); it != data.end(); ++it) {
      str += "<";
      str += it->first.toUri();
      str += "|";
      str += it->second;
      str += ">";
      str += "\n";
    }

    return str;
  }

  map<ndn::Name, string> data;
  uint32_t sum;
  Socket socket;
};

class SocketFixture
{
public:
  SocketFixture()
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
  createSocket(size_t idx, bool isNum)
  {
    app[idx] = make_shared<SocketTestApp>(syncPrefix, userPrefix[idx], ref(*faces[idx]), isNum);
    sessionName[idx] = app[idx]->socket.getLogic().getSessionName();
  }

  void
  publishAppData(size_t idx, const string& data)
  {
    app[idx]->socket.publishData(reinterpret_cast<const uint8_t*>(data.c_str()), data.size(),
                                 ndn::time::milliseconds(1000));
  }

  void
  setAppData(size_t idx, SeqNo seqNo, const string& data)
  {
    Name dataName = sessionName[idx];
    dataName.appendNumber(seqNo);
    app[idx]->set(dataName, data.c_str(), data.size());
  }

  void
  publishAppNum(size_t idx, const uint8_t* buf, size_t size)
  {
    app[idx]->socket.publishData(buf, size, ndn::time::milliseconds(1000));
  }

  void
  setAppNum(size_t idx, SeqNo seqNo, const uint8_t* buf, size_t size)
  {
    Name dataName = sessionName[idx];
    dataName.appendNumber(seqNo);
    app[idx]->setNum(dataName, buf, size);
  }

  void
  check(int round)
  {
    BOOST_CHECK_EQUAL(app[0]->toString(), app[1]->toString());
    BOOST_CHECK_EQUAL(app[0]->toString(), app[2]->toString());
  }

  void
  check2Num(int num)
  {
    BOOST_CHECK_EQUAL(app[0]->sum, app[1]->sum);
    BOOST_CHECK_EQUAL(app[1]->sum, num);
  }

  void
  terminate()
  {
    io.stop();
  }

  Name syncPrefix;
  Name userPrefix[3];
  Name sessionName[3];

  boost::asio::io_service io;
  shared_ptr<ndn::Face> faces[3];
  ndn::Scheduler scheduler;
  shared_ptr<SocketTestApp> app[3];
};



BOOST_FIXTURE_TEST_SUITE(SocketTests, SocketFixture)

BOOST_AUTO_TEST_CASE(BasicData)
{
  scheduler.scheduleEvent(ndn::time::milliseconds(0),
                          bind(&SocketFixture::createSocket, this, 0, false));

  scheduler.scheduleEvent(ndn::time::milliseconds(50),
                          bind(&SocketFixture::createSocket, this, 1, false));

  scheduler.scheduleEvent(ndn::time::milliseconds(100),
                          bind(&SocketFixture::createSocket, this, 2, false));

  string data0 = "Very funny Scotty, now beam down my clothes";
  scheduler.scheduleEvent(ndn::time::milliseconds(150),
                          bind(&SocketFixture::publishAppData, this, 0, data0));
  scheduler.scheduleEvent(ndn::time::milliseconds(1150),
                          bind(&SocketFixture::setAppData, this, 0, 1, data0));
  scheduler.scheduleEvent(ndn::time::milliseconds(1160),
                          bind(&SocketFixture::check, this, 1));

  string data1 = "Yes, give me that ketchup";
  string data2 = "Don't look conspicuous, it draws fire";
  scheduler.scheduleEvent(ndn::time::milliseconds(1170),
                          bind(&SocketFixture::publishAppData, this, 0, data1));
  scheduler.scheduleEvent(ndn::time::milliseconds(1180),
                          bind(&SocketFixture::publishAppData, this, 0, data2));
  scheduler.scheduleEvent(ndn::time::milliseconds(2150),
                          bind(&SocketFixture::setAppData, this, 0, 2, data1));
  scheduler.scheduleEvent(ndn::time::milliseconds(2160),
                          bind(&SocketFixture::setAppData, this, 0, 3, data2));
  scheduler.scheduleEvent(ndn::time::milliseconds(2170),
                          bind(&SocketFixture::check, this, 2));

  string data3 = "You surf the Internet, I surf the real world";
  string data4 = "I got a fortune cookie once that said 'You like Chinese food'";
  string data5 = "Real men wear pink. Why? Because their wives make them";
  scheduler.scheduleEvent(ndn::time::milliseconds(3180),
                          bind(&SocketFixture::publishAppData, this, 2, data3));
  scheduler.scheduleEvent(ndn::time::milliseconds(3200),
                          bind(&SocketFixture::publishAppData, this, 1, data4));
  scheduler.scheduleEvent(ndn::time::milliseconds(3210),
                          bind(&SocketFixture::publishAppData, this, 1, data5));
  scheduler.scheduleEvent(ndn::time::milliseconds(4710),
                          bind(&SocketFixture::setAppData, this, 2, 1, data3));
  scheduler.scheduleEvent(ndn::time::milliseconds(4720),
                          bind(&SocketFixture::setAppData, this, 1, 1, data4));
  scheduler.scheduleEvent(ndn::time::milliseconds(4730),
                          bind(&SocketFixture::setAppData, this, 1, 2, data5));
  scheduler.scheduleEvent(ndn::time::milliseconds(4800),
                          bind(&SocketFixture::check, this, 3));

  // not sure weither this is simultanous data generation from multiple sources
  string data6 = "Shakespeare says: 'Prose before hos.'";
  string data7 = "Pick good people, talent never wears out";
  scheduler.scheduleEvent(ndn::time::milliseconds(5500),
                          bind(&SocketFixture::publishAppData, this, 0, data6));
  scheduler.scheduleEvent(ndn::time::milliseconds(5500),
                          bind(&SocketFixture::publishAppData, this, 1, data7));
  scheduler.scheduleEvent(ndn::time::milliseconds(6800),
                          bind(&SocketFixture::setAppData, this, 0, 4, data6));
  scheduler.scheduleEvent(ndn::time::milliseconds(6800),
                          bind(&SocketFixture::setAppData, this, 1, 3, data7));
  scheduler.scheduleEvent(ndn::time::milliseconds(6900),
                          bind(&SocketFixture::check, this, 4));

  scheduler.scheduleEvent(ndn::time::milliseconds(7000),
                          bind(&SocketFixture::terminate, this));

  io.run();
}

BOOST_AUTO_TEST_CASE(BasicNumber)
{
  scheduler.scheduleEvent(ndn::time::milliseconds(0),
                          bind(&SocketFixture::createSocket, this, 0, true));
  scheduler.scheduleEvent(ndn::time::milliseconds(50),
                          bind(&SocketFixture::createSocket, this, 1, true));

  uint32_t num1[5] = {0, 1, 2, 3, 4};
  uint8_t* buf1 = reinterpret_cast<uint8_t*>(num1);
  size_t size1 = sizeof(num1);
  scheduler.scheduleEvent(ndn::time::milliseconds(100),
                          bind(&SocketFixture::publishAppNum, this, 0, buf1, size1));
  scheduler.scheduleEvent(ndn::time::milliseconds(150),
                          bind(&SocketFixture::setAppNum, this, 0, 0, buf1, size1));
  scheduler.scheduleEvent(ndn::time::milliseconds(1000),
                          bind(&SocketFixture::check2Num, this, 10));

  uint32_t num2[5] = {9, 7, 2, 1, 1};
  uint8_t* buf2 = reinterpret_cast<uint8_t*>(num2);
  size_t size2 = sizeof(num2);
  scheduler.scheduleEvent(ndn::time::milliseconds(1100),
                          bind(&SocketFixture::publishAppNum, this, 1, buf2, size2));
  scheduler.scheduleEvent(ndn::time::milliseconds(1150),
                          bind(&SocketFixture::setAppNum, this, 1, 0, buf2, size2));
  scheduler.scheduleEvent(ndn::time::milliseconds(2000),
                          bind(&SocketFixture::check2Num, this, 30));

  scheduler.scheduleEvent(ndn::time::milliseconds(7000),
                          bind(&SocketFixture::terminate, this));

  io.run();
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace chronosync
