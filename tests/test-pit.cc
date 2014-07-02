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
using boost::test_tools::output_test_stream;
#include <vector>

#include <boost/make_shared.hpp>

#include "sync-interest-table.h"
#include "sync-logging.h"

using namespace Sync;
using namespace std;
using namespace boost;

// string sitToString(SyncInterestTable *sit) {
//   vector<string> ent = sit->fetchAll();
//   sort(ent.begin(), ent.end());
//   string str = "";
//   while(!ent.empty()){
//     str += ent.back();
//     ent.pop_back();
//   }
//   return str;
// }

BOOST_AUTO_TEST_CASE (SyncInterestTableTest)
{
  cerr << "SyncInterestTableTest is broken" << endl;

  // INIT_LOGGERS ();
  // INIT_LOGGER ("Test.Pit");

  // SyncInterestTable sit;
  // sit.insert("/ucla.edu/0");
  // sit.insert("/ucla.edu/1");
  // string str = sitToString(&sit);
  // BOOST_CHECK_EQUAL(str, "/ucla.edu/1/ucla.edu/0");

  // str = sitToString(&sit);
  // BOOST_CHECK_EQUAL(str, "");

  // _LOG_DEBUG ("Adding 0 and 1");
  // sit.insert("/ucla.edu/0");
  // sit.insert("/ucla.edu/1");
  // sleep(2);
  // _LOG_DEBUG ("Adding 0 and 2");
  // sit.insert("/ucla.edu/0");
  // sit.insert("/ucla.edu/2");
  // sleep(3);
  // _LOG_DEBUG ("Checking");
  // str = sitToString(&sit);
  // BOOST_CHECK_EQUAL(str, "/ucla.edu/2/ucla.edu/0");
}
