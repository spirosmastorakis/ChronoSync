/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012 University of California, Los Angeles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Chaoyi Bian <bcy@pku.edu.cn>
 *	   Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include <boost/test/unit_test.hpp>
#include <boost/test/output_test_stream.hpp> 
using boost::test_tools::output_test_stream;

#include <boost/make_shared.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "sync-logging.h"
#include "sync-socket.h"
#include "sync-validator.h"
#include <ndn-cpp-dev/security/validator-null.hpp>

extern "C" {
#include <unistd.h>
}

using namespace Sync;
using namespace std;
using namespace boost;

INIT_LOGGER ("Test.AppSocket");

#define PRINT 
// std::cout << "Line: " << __LINE__ << std::endl;

class TestSocketApp {
public:
  TestSocketApp()
    : sum(0)
  {}

  map<ndn::Name, string> data;
  void set(const ndn::shared_ptr<const ndn::Data>& dataPacket) {
    // _LOG_FUNCTION (this << ", " << str1);
    ndn::Name dataName(dataPacket->getName());
    string str2(reinterpret_cast<const char*>(dataPacket->getContent().value()), dataPacket->getContent().value_size());
    data.insert(make_pair(dataName, str2));
    // cout << str1 << ", " << str2 << endl;
  }

  void set(ndn::Name name, const char * buf, int len) {
    string str2(buf, len);
    data.insert(make_pair(name, str2));
  }
  
  void setNum(const ndn::shared_ptr<const ndn::Data>& data) {
    int n = data->getContent().value_size() / 4;
    uint32_t *numbers = new uint32_t [n];
    memcpy(numbers, data->getContent().value(), data->getContent().value_size());
    for (int i = 0; i < n; i++) {
      sum += numbers[i];
    }
    delete numbers;

  }

  void setNum(ndn::Name name, const char * buf, int len) {
    int n = len / 4;
    int *numbers = new int [n];
    memcpy(numbers, buf, len);
    for (int i = 0; i < n; i++) {
      sum += numbers[i];
    }
    delete numbers;
  }

  uint32_t sum;

  void fetchAll(const vector<MissingDataInfo> &v, SyncSocket *socket) {
    int n = v.size();

    PRINT

    for (int i = 0; i < n; i++) {
      for(SeqNo s = v[i].low; s <= v[i].high; ++s) {
        //PRINT
        socket->fetchData(v[i].prefix, s, bind(&TestSocketApp::set, this, _1));
      }
    }
  }

  void fetchNumbers(const vector<MissingDataInfo> &v, SyncSocket *socket) {
    int n = v.size();

    PRINT

    // std::cout << "In fetchNumbers. size of v is:  " << n << std::endl;
    for (int i = 0; i < n; i++) {
      // std::cout << "In fetchNumbers. v[i].low is (" <<v[i].low.getSession() <<", " << v[i].low.getSeq() << ") v[i].high is ("<<v[i].high.getSession() <<", " <<v[i].high.getSeq()<<")" << std::endl;
      for(SeqNo s = v[i].low; s <= v[i].high; ++s) {
        PRINT
        socket->fetchData(v[i].prefix, s, bind(&TestSocketApp::setNum, this, _1));
      }
    }
  }

  void pass(const string &prefix) {
  }

  string toString(){
    map<ndn::Name, string>::iterator it = data.begin(); 
    string str = "\n";
    for (; it != data.end(); ++it){
      str += "<";
      str += it->first.toUri();
      str += "|";
      str += it->second;
      str += ">";
      str += "\n";
    }

    return str;
  }

};

class TestSet1{
public:
  TestSet1(ndn::shared_ptr<boost::asio::io_service> ioService)
    : m_face1(new ndn::Face(ioService))
    , m_face2(new ndn::Face(ioService))
    , m_face3(new ndn::Face(ioService))
    , m_name1("/irl.cs.ucla.edu/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()))
    , m_name2("/yakshi.org/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()))
    , m_name3("/google.com/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()))
  {
    m_id1 = m_keyChain.getCertificate(m_keyChain.createIdentity(m_name1));
    m_id2 = m_keyChain.getCertificate(m_keyChain.createIdentity(m_name2));
    m_id3 = m_keyChain.getCertificate(m_keyChain.createIdentity(m_name3));

    m_rule = ndn::make_shared<ndn::SecRuleRelative>("^(<>*)<><>$",
                                                    "^(<>*)<><KEY><ksk-.*><ID-CERT>$",
                                                    "==", "\\1", "\\1", true);
  }

  void
  createSyncSocket1()
  {
    _LOG_DEBUG ("s1");

    m_s1 = ndn::shared_ptr<SyncSocket>
      (new SyncSocket("/let/us/sync",
                      "/irl.cs.ucla.edu",
                      0,
                      false,
                      "/",
                      m_face1,
                      *m_id1,
                      m_rule,
                      bind(&TestSocketApp::fetchAll, &m_a1, _1, _2), 
                      bind(&TestSocketApp::pass, &m_a1, _1)));

    m_s1->addParticipant(*m_id2);
  }

  void
  createSyncSocket2()
  {
    _LOG_DEBUG ("s2");

    m_s2 = ndn::shared_ptr<SyncSocket>
      (new SyncSocket("/let/us/sync",
                      "/yakshi.org",
                      0,
                      false,
                      "/",
                      m_face2,
                      *m_id2,
                      m_rule,
                      bind(&TestSocketApp::fetchAll, &m_a2, _1, _2), 
                      bind(&TestSocketApp::pass, &m_a2, _1)));

    m_s2->addParticipant(*m_id1);
    m_s2->addParticipant(*m_id3);
  }
  
  void
  createSyncSocket3()
  {
    _LOG_DEBUG ("s3");

    m_s3 = ndn::shared_ptr<SyncSocket>
      (new SyncSocket("/let/us/sync",
                      "/google.com",
                      0,
                      false,
                      "/",
                      m_face3,
                      *m_id3,
                      m_rule,  
                      bind(&TestSocketApp::fetchAll, &m_a3, _1, _2), 
                      bind(&TestSocketApp::pass, &m_a3, _1)));

    m_s3->addParticipant(*m_id2);
  }

  void
  publishSocket1(string data)
  {
    _LOG_DEBUG ("s1 publish");
    m_s1->publishData (reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), 1000); 
  }

  void
  publishSocket2(string data)
  {
    _LOG_DEBUG ("s2 publish");
    m_s2->publishData (reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), 1000); 
  }

  void
  publishSocket3(string data)
  {
    _LOG_DEBUG ("s3 publish");
    m_s3->publishData (reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), 1000); 
  }

  void
  setSocket1(string suffix, string data)
  {
    _LOG_DEBUG ("a1 set");
    ndn::Name name("/irl.cs.ucla.edu");
    name.append(suffix);
    m_a1.set (name, data.c_str(), data.size()); 
  }

  void
  setSocket2(string suffix, string data)
  {
    _LOG_DEBUG ("a2 set");
    ndn::Name name("/yakshi.org");
    name.append(suffix);
    m_a2.set (name, data.c_str(), data.size()); 
  }

  void
  setSocket3(string suffix, string data)
  {
    _LOG_DEBUG ("a3 set");
    ndn::Name name("/google.com");
    name.append(suffix);
    m_a3.set (name, data.c_str(), data.size()); 
  }

  void
  check(int round)
  { 
    BOOST_CHECK_EQUAL(m_a1.toString(), m_a2.toString());
    BOOST_CHECK_EQUAL(m_a2.toString(), m_a3.toString());
  }

  void
  done(ndn::shared_ptr<boost::asio::io_service> ioService)
  {
    m_s1.reset();
    m_s2.reset();
    m_s3.reset();

    m_keyChain.deleteIdentity(m_name1);
    m_keyChain.deleteIdentity(m_name2);
    m_keyChain.deleteIdentity(m_name3);

    ioService->stop();
  }

  ndn::KeyChain m_keyChain;
  ndn::shared_ptr<ndn::SecRuleRelative> m_rule;

  ndn::shared_ptr<ndn::Face> m_face1, m_face2, m_face3;
  ndn::Name m_name1, m_name2, m_name3;
  TestSocketApp m_a1, m_a2, m_a3;
  ndn::shared_ptr<ndn::IdentityCertificate> m_id1, m_id2, m_id3;
  ndn::shared_ptr<SyncSocket> m_s1, m_s2, m_s3;
};

class TestSet2{
public:
  TestSet2(ndn::shared_ptr<boost::asio::io_service> ioService)
    : m_face1(new ndn::Face(ioService))
    , m_face2(new ndn::Face(ioService))
    , m_name1("/xiaonei.com/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()))
    , m_name2("/mitbbs.com/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()))
  {
    m_id1 = m_keyChain.getCertificate(m_keyChain.createIdentity(m_name1));
    m_id2 = m_keyChain.getCertificate(m_keyChain.createIdentity(m_name2));

    m_rule = ndn::make_shared<ndn::SecRuleRelative>("^(<>*)<><>$",
                                                    "^(<>*)<><KEY><ksk-.*><ID-CERT>$",
                                                    "==", "\\1", "\\1", true);
  }

  void
  createSyncSocket1()
  {
    _LOG_DEBUG ("s1");
    
    m_s1 = ndn::shared_ptr<SyncSocket>
      (new SyncSocket("/this/is/the/prefix",
                      "/xiaonei.com",
                      0,
                      false,
                      "/",                                        
                      m_face1,
                      *m_id1,
                      m_rule,
                      bind(&TestSocketApp::fetchNumbers, &m_a1, _1, _2), 
                      bind(&TestSocketApp::pass, &m_a1, _1)));

    m_s1->addParticipant(*m_id2);
  }

  void
  createSyncSocket2()
  {
    _LOG_DEBUG ("s2");

    m_s2 = ndn::shared_ptr<SyncSocket>
      (new SyncSocket("/this/is/the/prefix",
                      "/mitbbs.com",
                      0,
                      false,
                      "/",
                      m_face2,
                      *m_id2,
                      m_rule,
                      bind(&TestSocketApp::fetchNumbers, &m_a2, _1, _2), 
                      bind(&TestSocketApp::pass, &m_a2, _1)));

    m_s2->addParticipant(*m_id1);
  }
  
  void
  publishSocket1(string data)
  {
    _LOG_DEBUG ("s1 publish");
    m_s1->publishData (reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), 1000); 
  }

  void
  publishSocket2(string data)
  {
    _LOG_DEBUG ("s2 publish");
    m_s2->publishData (reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), 1000); 
  }

  void
  setSocket1(const char* ptr, size_t size)
  {
    _LOG_DEBUG ("a1 setNum");
    m_a1.setNum ("/xiaonei.com", ptr, size); 
  }

  void
  setSocket2(const char* ptr, size_t size)
  {
    _LOG_DEBUG ("a2 setNum");
    m_a2.setNum ("/mitbbs.com", ptr, size); 
  }

  void
  check(int num)
  { 
    _LOG_DEBUG ("codnum " << num);
    _LOG_DEBUG ("a1 sum " << m_a1.sum);
    _LOG_DEBUG ("a2 sum " << m_a2.sum);

    BOOST_CHECK(m_a1.sum == m_a2.sum && m_a1.sum == num);
  }

  void
  done(ndn::shared_ptr<boost::asio::io_service> ioService)
  {
    m_s1.reset();
    m_s2.reset();

    m_keyChain.deleteIdentity(m_name1);
    m_keyChain.deleteIdentity(m_name2);

    ioService->stop();
  }

  ndn::KeyChain m_keyChain;
  ndn::shared_ptr<ndn::SecRuleRelative> m_rule;

  TestSocketApp m_a1, m_a2;
  ndn::shared_ptr<ndn::IdentityCertificate> m_id1, m_id2;
  ndn::shared_ptr<ndn::Face> m_face1, m_face2;
  ndn::Name m_name1, m_name2;
  ndn::shared_ptr<SyncSocket> m_s1, m_s2;
};



class TestSet3{
public:
  TestSet3(ndn::shared_ptr<boost::asio::io_service> ioService)
    : m_face1(new ndn::Face(ioService))
    , m_face2(new ndn::Face(ioService))
    , m_name1("/xiaonei.com/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()))
    , m_name2("/mitbbs.com/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()))
  {
    m_id1 = m_keyChain.getCertificate(m_keyChain.createIdentity(m_name1));
    m_id2 = m_keyChain.getCertificate(m_keyChain.createIdentity(m_name2));

    m_rule = ndn::make_shared<ndn::SecRuleRelative>("^(<>*)<><>$",
                                                    "^(<>*)<><KEY><ksk-.*><ID-CERT>$",
                                                    "==", "\\1", "\\1", true);
  }

  void
  createSyncSocket1()
  {
    _LOG_DEBUG ("s1");
    
    m_s1 = ndn::shared_ptr<SyncSocket>
      (new SyncSocket("/this/is/the/prefix",
                      "/xiaonei.com",
                      1,
                      true,
                      "/abc",                                        
                      m_face1,
                      *m_id1,
                      m_rule,
                      bind(&TestSocketApp::fetchNumbers, &m_a1, _1, _2), 
                      bind(&TestSocketApp::pass, &m_a1, _1)));

    m_s1->addParticipant(*m_id2);
  }

  void
  createSyncSocket2()
  {
    _LOG_DEBUG ("s2");

    m_s2 = ndn::shared_ptr<SyncSocket>
      (new SyncSocket("/this/is/the/prefix",
                      "/mitbbs.com",
                      1,
                      false,
                      "/",
                      m_face2,
                      *m_id2,
                      m_rule,
                      bind(&TestSocketApp::fetchNumbers, &m_a2, _1, _2), 
                      bind(&TestSocketApp::pass, &m_a2, _1)));

    m_s2->addParticipant(*m_id1);
  }
  
  void
  publishSocket1(string data)
  {
    _LOG_DEBUG ("s1 publish");
    m_s1->publishData (reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), 1000); 
  }

  void
  publishSocket2(string data)
  {
    _LOG_DEBUG ("s2 publish");
    m_s2->publishData (reinterpret_cast<const uint8_t*>(data.c_str()), data.size(), 1000); 
  }

  void
  setSocket1(const char* ptr, size_t size)
  {
    _LOG_DEBUG ("a1 setNum");
    m_a1.setNum ("/xiaonei.com", ptr, size); 
  }

  void
  setSocket2(const char* ptr, size_t size)
  {
    _LOG_DEBUG ("a2 setNum");
    m_a2.setNum ("/mitbbs.com", ptr, size); 
  }

  void
  check(int num)
  { 
    _LOG_DEBUG ("codnum " << num);
    _LOG_DEBUG ("a1 sum " << m_a1.sum);
    _LOG_DEBUG ("a2 sum " << m_a2.sum);

    BOOST_CHECK(m_a1.sum == m_a2.sum && m_a1.sum == num);
  }

  void
  done(ndn::shared_ptr<boost::asio::io_service> ioService)
  {
    m_s1.reset();
    m_s2.reset();

    m_keyChain.deleteIdentity(m_name1);
    m_keyChain.deleteIdentity(m_name2);

    ioService->stop();
  }

  ndn::KeyChain m_keyChain;
  ndn::shared_ptr<ndn::SecRuleRelative> m_rule;

  TestSocketApp m_a1, m_a2;
  ndn::shared_ptr<ndn::IdentityCertificate> m_id1, m_id2;
  ndn::shared_ptr<ndn::Face> m_face1, m_face2;
  ndn::Name m_name1, m_name2;
  ndn::shared_ptr<SyncSocket> m_s1, m_s2;
};

BOOST_AUTO_TEST_CASE (AppSocketTest1)
{
  INIT_LOGGERS ();

  ndn::shared_ptr<boost::asio::io_service> ioService = ndn::make_shared<boost::asio::io_service>();
  ndn::Scheduler scheduler(*ioService);
  TestSet1 testSet1(ioService);

  scheduler.scheduleEvent(ndn::time::milliseconds(0), ndn::bind(&TestSet1::createSyncSocket1, &testSet1));
  scheduler.scheduleEvent(ndn::time::milliseconds(50), ndn::bind(&TestSet1::createSyncSocket2, &testSet1));
  scheduler.scheduleEvent(ndn::time::milliseconds(100), ndn::bind(&TestSet1::createSyncSocket3, &testSet1));
  string data0 = "Very funny Scotty, now beam down my clothes";
  scheduler.scheduleEvent(ndn::time::milliseconds(150), ndn::bind(&TestSet1::publishSocket1, &testSet1, data0));
  scheduler.scheduleEvent(ndn::time::milliseconds(1150), ndn::bind(&TestSet1::setSocket1, &testSet1, "/0/1", data0));
  scheduler.scheduleEvent(ndn::time::milliseconds(1160), ndn::bind(&TestSet1::check, &testSet1, 1)); 
  string data1 = "Yes, give me that ketchup";
  string data2 = "Don't look conspicuous, it draws fire";
  scheduler.scheduleEvent(ndn::time::milliseconds(1170), ndn::bind(&TestSet1::publishSocket1, &testSet1, data1));
  scheduler.scheduleEvent(ndn::time::milliseconds(1180), ndn::bind(&TestSet1::publishSocket1, &testSet1, data2));
  scheduler.scheduleEvent(ndn::time::milliseconds(2150), ndn::bind(&TestSet1::setSocket1, &testSet1, "/0/2", data1));
  scheduler.scheduleEvent(ndn::time::milliseconds(2160), ndn::bind(&TestSet1::setSocket1, &testSet1, "/0/3", data2));
  scheduler.scheduleEvent(ndn::time::milliseconds(2170), ndn::bind(&TestSet1::check, &testSet1, 2));
  string data3 = "You surf the Internet, I surf the real world";
  string data4 = "I got a fortune cookie once that said 'You like Chinese food'";
  string data5 = "Real men wear pink. Why? Because their wives make them";
  scheduler.scheduleEvent(ndn::time::milliseconds(3180), ndn::bind(&TestSet1::publishSocket3, &testSet1, data3));
  scheduler.scheduleEvent(ndn::time::milliseconds(3200), ndn::bind(&TestSet1::publishSocket2, &testSet1, data4));
  scheduler.scheduleEvent(ndn::time::milliseconds(3210), ndn::bind(&TestSet1::publishSocket2, &testSet1, data5));
  scheduler.scheduleEvent(ndn::time::milliseconds(4710), ndn::bind(&TestSet1::setSocket3, &testSet1, "/0/1", data3));
  scheduler.scheduleEvent(ndn::time::milliseconds(4720), ndn::bind(&TestSet1::setSocket2, &testSet1, "/0/2", data4));
  scheduler.scheduleEvent(ndn::time::milliseconds(4730), ndn::bind(&TestSet1::setSocket2, &testSet1, "/0/3", data5));
  scheduler.scheduleEvent(ndn::time::milliseconds(4800), ndn::bind(&TestSet1::check, &testSet1, 3));
  // not sure weither this is simultanous data generation from multiple sources
  _LOG_DEBUG ("Simultaneous publishing");
  string data6 = "Shakespeare says: 'Prose before hos.'";
  string data7 = "Pick good people, talent never wears out";
  scheduler.scheduleEvent(ndn::time::milliseconds(5500), ndn::bind(&TestSet1::publishSocket1, &testSet1, data6));
  scheduler.scheduleEvent(ndn::time::milliseconds(5500), ndn::bind(&TestSet1::publishSocket2, &testSet1, data7));
  scheduler.scheduleEvent(ndn::time::milliseconds(6800), ndn::bind(&TestSet1::setSocket1, &testSet1, "/0/4", data6));
  scheduler.scheduleEvent(ndn::time::milliseconds(6800), ndn::bind(&TestSet1::setSocket2, &testSet1, "/0/4", data7));
  scheduler.scheduleEvent(ndn::time::milliseconds(6900), ndn::bind(&TestSet1::check, &testSet1, 4));
  scheduler.scheduleEvent(ndn::time::milliseconds(7000), ndn::bind(&TestSet1::done, &testSet1, ioService));

  ioService->run();
}

BOOST_AUTO_TEST_CASE (AppSocketTest2)
{
  ndn::shared_ptr<boost::asio::io_service> ioService = ndn::make_shared<boost::asio::io_service>();
  ndn::Scheduler scheduler(*ioService);
  TestSet2 testSet2(ioService);

  scheduler.scheduleEvent(ndn::time::milliseconds(0), ndn::bind(&TestSet2::createSyncSocket1, &testSet2));
  scheduler.scheduleEvent(ndn::time::milliseconds(50), ndn::bind(&TestSet2::createSyncSocket2, &testSet2));
  uint32_t num[5] = {0, 1, 2, 3, 4};
  string data0((const char *) num, sizeof(num));
  scheduler.scheduleEvent(ndn::time::milliseconds(100), ndn::bind(&TestSet2::publishSocket1, &testSet2, data0));
  scheduler.scheduleEvent(ndn::time::milliseconds(150), ndn::bind(&TestSet2::setSocket1, &testSet2, (const char *) num, sizeof (num)));
  scheduler.scheduleEvent(ndn::time::milliseconds(1000), ndn::bind(&TestSet2::check, &testSet2, 10));
  uint32_t newNum[5] = {9, 7, 2, 1, 1};
  string data1((const char *) newNum, sizeof(newNum));
  scheduler.scheduleEvent(ndn::time::milliseconds(1100), ndn::bind(&TestSet2::publishSocket2, &testSet2, data1));
  scheduler.scheduleEvent(ndn::time::milliseconds(1150), ndn::bind(&TestSet2::setSocket2, &testSet2, (const char *) newNum, sizeof (newNum)));
  scheduler.scheduleEvent(ndn::time::milliseconds(2000), ndn::bind(&TestSet2::check, &testSet2, 30));
  scheduler.scheduleEvent(ndn::time::milliseconds(7000), ndn::bind(&TestSet2::done, &testSet2, ioService));

  ioService->run();
}

BOOST_AUTO_TEST_CASE (AppSocketTest3)
{
  ndn::shared_ptr<boost::asio::io_service> ioService = ndn::make_shared<boost::asio::io_service>();
  ndn::Scheduler scheduler(*ioService);
  TestSet3 testSet3(ioService);

  scheduler.scheduleEvent(ndn::time::milliseconds(0), ndn::bind(&TestSet3::createSyncSocket1, &testSet3));
  scheduler.scheduleEvent(ndn::time::milliseconds(200), ndn::bind(&TestSet3::createSyncSocket2, &testSet3));
  uint32_t num[5] = {0, 1, 2, 3, 4};
  string data0((const char *) num, sizeof(num));
  scheduler.scheduleEvent(ndn::time::milliseconds(1000), ndn::bind(&TestSet3::publishSocket1, &testSet3, data0));
  scheduler.scheduleEvent(ndn::time::milliseconds(1500), ndn::bind(&TestSet3::setSocket1, &testSet3, (const char *) num, sizeof (num)));
  scheduler.scheduleEvent(ndn::time::milliseconds(2000), ndn::bind(&TestSet3::check, &testSet3, 10));
  uint32_t newNum[5] = {9, 7, 2, 1, 1};
  string data1((const char *) newNum, sizeof(newNum));
  scheduler.scheduleEvent(ndn::time::milliseconds(3000), ndn::bind(&TestSet3::publishSocket2, &testSet3, data1));
  scheduler.scheduleEvent(ndn::time::milliseconds(3500), ndn::bind(&TestSet3::setSocket2, &testSet3, (const char *) newNum, sizeof (newNum)));
  scheduler.scheduleEvent(ndn::time::milliseconds(5000), ndn::bind(&TestSet3::check, &testSet3, 30));
  scheduler.scheduleEvent(ndn::time::milliseconds(7000), ndn::bind(&TestSet3::done, &testSet3, ioService));

  ioService->run();
}
