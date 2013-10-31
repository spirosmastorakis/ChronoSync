/* -*- Mode: C32++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
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
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "sync-socket.h"

using namespace std;
using namespace ndn;

namespace Sync {

SyncSocket::SyncSocket (const string &syncPrefix, 
                        Ptr<SyncPolicyManager> syncPolicyManager, 
                        NewDataCallback dataCallback, 
                        RemoveCallback rmCallback )
  : m_newDataCallback(dataCallback)
  , m_syncPolicyManager(syncPolicyManager)
  , m_syncLogic (syncPrefix,
                 syncPolicyManager,
                 bind(&SyncSocket::passCallback, this, _1),
                 rmCallback)
{
  Ptr<security::Keychain> keychain = Ptr<security::Keychain>(new security::Keychain(Ptr<security::IdentityManager>::Create(), m_syncPolicyManager, NULL));
  m_handler = Ptr<Wrapper>(new Wrapper(keychain));
}

SyncSocket::~SyncSocket()
{}

bool 
SyncSocket::publishData(const std::string &prefix, uint32_t session, const char *buf, size_t len, int freshness)
{
  uint32_t sequence = getNextSeq(prefix, session);
  ostringstream contentNameWithSeqno;
  contentNameWithSeqno << prefix << "/" << session << "/" << sequence;
  
  Name dataName(contentNameWithSeqno.str ());
  Blob blob(buf, len);
  Name signingIdentity = m_syncPolicyManager->inferSigningIdentity(dataName);
  
  m_handler->publishDataByIdentity (dataName, 
                                    blob, 
                                    signingIdentity, 
                                    freshness);
  
  SeqNo s(session, sequence + 1);
  m_sequenceLog[prefix] = s;
  m_syncLogic.addLocalNames (prefix, session, sequence);
  return true;
}

void 
SyncSocket::fetchData(const string &prefix, const SeqNo &seq, const DataCallback& callback, int retry)
{
  ostringstream interestName;
  interestName << prefix << "/" << seq.getSession() << "/" << seq.getSeq();
  //std::cout << "Socket " << this << " Send Interest <" << interestName.str() << "> for raw data " << endl;
  
  
  Ptr<ndn::Interest> interestPtr = Ptr<ndn::Interest>(new ndn::Interest(interestName.str()));
  Ptr<Closure> closure = Ptr<Closure> (new Closure(callback,
						   boost::bind(&SyncSocket::onChatDataTimeout,
                                                               this,
                                                               _1, 
                                                               _2,
                                                               retry),
						   boost::bind(&SyncSocket::onChatDataUnverified,
                                                               this,
                                                               _1)));
  m_handler->sendInterest(interestPtr, closure);
}

void
SyncSocket::onChatDataTimeout(Ptr<Closure> closure, Ptr<ndn::Interest> interest, int retry)
{
  if(retry > 0)
    {
      Ptr<Closure> newClosure = Ptr<Closure>(new Closure(closure->m_dataCallback,
                                                         boost::bind(&SyncSocket::onChatDataTimeout, 
                                                                     this, 
                                                                     _1, 
                                                                     _2, 
                                                                     retry - 1),
                                                         closure->m_unverifiedCallback,
                                                         closure->m_stepCount)
                                             );
      m_handler->sendInterest(interest, newClosure);
    }
}

void
SyncSocket::onChatDataUnverified(Ptr<Data> data)
{}


uint32_t
SyncSocket::getNextSeq (const string &prefix, uint32_t session)
{
  SequenceLog::iterator i = m_sequenceLog.find (prefix);

  if (i != m_sequenceLog.end ())
    {
      SeqNo s = i->second;
      if (s.getSession() == session)
        return s.getSeq();
    }
  return 0;
}

}//Sync
