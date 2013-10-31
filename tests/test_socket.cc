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

#include "ccnx/sync-socket.h"

extern "C" {
#include <unistd.h>
}

using namespace Sync;
using namespace std;
using namespace boost;

INIT_LOGGER ("Test.AppSocket");

#define PRINT 
//std::cout << "Line: " << __LINE__ << std::endl;

class TestSocketApp {
public:
  map<string, string> data;
  void set(ndn::Ptr<ndn::Data> dataPacket) {
    // _LOG_FUNCTION (this << ", " << str1);
    string str1(dataPacket->getName().toUri());
    string str2(dataPacket->content().buf(), dataPacket->content().size());
    data.insert(make_pair(str1, str2));
    // cout << str1 << ", " << str2 << endl;
  }

  void set(string str1, const char * buf, int len) {
    string str2(buf, len);
    data.insert(make_pair(str1, str2));
  }
  
  void setNum(ndn::Ptr<ndn::Data> dataPacket) {
    int n = dataPacket->content().size() / 4;
    int *numbers = new int [n];
    memcpy(numbers, dataPacket->content().buf(), dataPacket->content().size());
    for (int i = 0; i < n; i++) {
      sum += numbers[i];
    }
    delete numbers;

  }

  void setNum(string str1, const char * buf, int len) {
    int n = len / 4;
    int *numbers = new int [n];
    memcpy(numbers, buf, len);
    for (int i = 0; i < n; i++) {
      sum += numbers[i];
    }
    delete numbers;
  }

  int sum;

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

    std::cout << "In fetchNumbers. size of v is:  " << n << std::endl;
    for (int i = 0; i < n; i++) {
      std::cout << "In fetchNumbers. v[i].low is (" <<v[i].low.getSession() <<", " << v[i].low.getSeq() << ") v[i].high is ("<<v[i].high.getSession() <<", " <<v[i].high.getSeq()<<")" << std::endl;
      for(SeqNo s = v[i].low; s <= v[i].high; ++s) {
        PRINT
        socket->fetchData(v[i].prefix, s, bind(&TestSocketApp::setNum, this, _1));
      }
    }
  }

  void pass(const string &prefix) {
  }

  string toString(){
    map<string, string>::iterator it = data.begin(); 
    string str = "\n";
    for (; it != data.end(); ++it){
      str += "<";
      str += it->first;
      str += "|";
      str += it->second;
      str += ">";
      str += "\n";
    }

    return str;
  }

};

BOOST_AUTO_TEST_CASE (AppSocketTest)
{
  INIT_LOGGERS ();
  
  TestSocketApp a1, a2, a3;
	
  string syncPrefix("/let/us/sync");
  string p1("/irl.cs.ucla.edu"), p2("/yakshi.org"), p3("/google.com");

  ndn::Ptr<SyncPolicyManager> policyManager1 = ndn::Ptr<SyncPolicyManager>(new SyncPolicyManager(ndn::Name("/ndn/ucla.edu/alice"), ndn::Name("/ndn/ucla.edu/alice/KEY/dsk-1382934202/ID-CERT/%FD%FF%FF%FF%FF%DEk%C0%0B"), ndn::Name(syncPrefix)));

  _LOG_DEBUG ("s1");
  SyncSocket s1 (syncPrefix, policyManager1, bind(&TestSocketApp::fetchAll, &a1, _1, _2), bind(&TestSocketApp::pass, &a1, _1));
  this_thread::sleep (posix_time::milliseconds (50));
  _LOG_DEBUG ("s2");
  SyncSocket s2 (syncPrefix, policyManager1, bind(&TestSocketApp::fetchAll, &a2, _1, _2), bind(&TestSocketApp::pass, &a2, _1));
  this_thread::sleep (posix_time::milliseconds (50));
  SyncSocket s3 (syncPrefix, policyManager1, bind(&TestSocketApp::fetchAll, &a3, _1, _2), bind(&TestSocketApp::pass, &a3, _1));
  this_thread::sleep (posix_time::milliseconds (50));

  // single source
  string data0 = "Very funny Scotty, now beam down my clothes";
  _LOG_DEBUG ("s1 publish");
  s1.publishData (p1, 0, data0.c_str(), data0.size(), 10); 
  this_thread::sleep (posix_time::milliseconds (1000));

  // from code logic, we won't be fetching our own data
  a1.set(p1 + "/0/0", data0.c_str(), data0.size());
  BOOST_CHECK_EQUAL(a1.toString(), a2.toString());
  BOOST_CHECK_EQUAL(a2.toString(), a3.toString());

  // single source, multiple data at once
  string data1 = "Yes, give me that ketchup";
  string data2 = "Don't look conspicuous, it draws fire";

  _LOG_DEBUG ("s1 publish");
  s1.publishData (p1, 0, data1.c_str(), data1.size(), 10);
  _LOG_DEBUG ("s1 publish");
  s1.publishData (p1, 0, data2.c_str(), data2.size(), 10);
  this_thread::sleep (posix_time::milliseconds (1000));
  
  // from code logic, we won't be fetching our own data
  a1.set(p1 + "/0/1", data1.c_str(), data1.size());
  a1.set(p1 + "/0/2", data2.c_str(), data2.size());
  BOOST_CHECK_EQUAL(a1.toString(), a2.toString());
  BOOST_CHECK_EQUAL(a2.toString(), a3.toString());

  // another single source
  string data3 = "You surf the Internet, I surf the real world";
  string data4 = "I got a fortune cookie once that said 'You like Chinese food'";
  string data5 = "Real men wear pink. Why? Because their wives make them";
  _LOG_DEBUG ("s3 publish");
  s3.publishData(p3, 0, data3.c_str(), data3.size(), 10); 
  this_thread::sleep (posix_time::milliseconds (200));
  
  // another single source, multiple data at once
  s2.publishData(p2, 0, data4.c_str(), data4.size(), 10); 
  s2.publishData(p2, 0, data5.c_str(), data5.size(), 10);
  this_thread::sleep (posix_time::milliseconds (1000));

  // from code logic, we won't be fetching our own data
  a3.set(p3 + "/0/0", data3.c_str(), data3.size());
  a2.set(p2 + "/0/0", data4.c_str(), data4.size());
  a2.set(p2 + "/0/1", data5.c_str(), data5.size());
  BOOST_CHECK_EQUAL(a1.toString(), a2.toString());
  BOOST_CHECK_EQUAL(a2.toString(), a3.toString());

  // not sure weither this is simultanous data generation from multiple sources
  _LOG_DEBUG ("Simultaneous publishing");
  string data6 = "Shakespeare says: 'Prose before hos.'";
  string data7 = "Pick good people, talent never wears out";
  s1.publishData(p1, 0, data6.c_str(), data6.size(), 10); 
  // this_thread::sleep (posix_time::milliseconds (1000));
  s2.publishData(p2, 0, data7.c_str(), data7.size(), 10); 
  this_thread::sleep (posix_time::milliseconds (1500));

  // from code logic, we won't be fetching our own data
  a1.set(p1 + "/0/3", data6.c_str(), data6.size());
  a2.set(p2 + "/0/2", data7.c_str(), data7.size());
  // a1.set(p1 + "/0/1", data6);
  // a2.set(p2 + "/0/0", data7);
  BOOST_CHECK_EQUAL(a1.toString(), a2.toString());
  BOOST_CHECK_EQUAL(a2.toString(), a3.toString());

  _LOG_DEBUG("Begin new test");
  std::cout << "Begin new Test " << std::endl;
  string syncRawPrefix = "/this/is/the/prefix";
  ndn::Ptr<SyncPolicyManager> policyManager2 = ndn::Ptr<SyncPolicyManager>(new SyncPolicyManager(ndn::Name("/ndn/ucla.edu/alice"), ndn::Name("/ndn/ucla.edu/alice/KEY/dsk-1382934202/ID-CERT/%FD%FF%FF%FF%FF%DEk%C0%0B"), ndn::Name(syncRawPrefix)));

  a1.sum = 0;
  a2.sum = 0;
  SyncSocket s4 (syncRawPrefix, policyManager2, bind(&TestSocketApp::fetchNumbers, &a1, _1, _2), bind(&TestSocketApp::pass, &a1, _1));
  SyncSocket s5 (syncRawPrefix, policyManager2, bind(&TestSocketApp::fetchNumbers, &a2, _1, _2), bind(&TestSocketApp::pass, &a2, _1));

  int num[5] = {0, 1, 2, 3, 4};

  string p4 = "/xiaonei.com";
  string p5 = "/mitbbs.com";

  s4.publishData(p4, 0,(const char *) num, sizeof(num), 10);
  a1.setNum(p4, (const char *) num, sizeof (num));

  this_thread::sleep (posix_time::milliseconds (1000));
  BOOST_CHECK(a1.sum == a2.sum && a1.sum == 10);

  int newNum[5] = {9, 7, 2, 1, 1};

  s5.publishData(p5, 0,(const char *) newNum, sizeof(newNum), 10);
  a2.setNum(p5, (const char *)newNum, sizeof (newNum));
  this_thread::sleep (posix_time::milliseconds (1000));
  BOOST_CHECK_EQUAL(a1.sum, a2.sum);
  BOOST_CHECK_EQUAL(a1.sum, 30);

  _LOG_DEBUG ("Finish");
}
