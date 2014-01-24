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
#include "sync-logging.h"

using namespace std;
using namespace ndn;
using namespace ndn::ptr_lib;

INIT_LOGGER ("SyncSocket");

namespace Sync {

SyncSocket::SyncSocket (const string &syncPrefix, 
                        shared_ptr<SecPolicySync> policy,
                        shared_ptr<Face> face,
                        NewDataCallback dataCallback, 
                        RemoveCallback rmCallback )
  : m_newDataCallback(dataCallback)
  , m_policy(policy)
  , m_verifier(new Verifier(policy))
  , m_keyChain(new KeyChain())
  , m_face(face)
  , m_syncLogic (syncPrefix,
                 policy,
                 face,
                 bind(&SyncSocket::passCallback, this, _1),
                 rmCallback)
{
  m_verifier->setFace(face);
}

SyncSocket::~SyncSocket()
{
}

bool 
SyncSocket::publishData(const Name &prefix, uint32_t session, const char *buf, size_t len, int freshness)
{
  uint32_t sequence = getNextSeq(prefix, session);
  ostringstream sessionStream;
  ostringstream seqStream;
  sessionStream <<  session;
  seqStream << sequence;
  
  Name dataName = prefix;
  dataName.append(sessionStream.str()).append(seqStream.str());
  
  Name signingIdentity = m_policy->inferSigningIdentity(dataName);

  Data data(dataName);
  data.setContent(reinterpret_cast<const uint8_t*>(buf), len);

  m_keyChain->signByIdentity(data, signingIdentity);
  
  m_face->put(data);
  
  SeqNo s(session, sequence + 1);
  m_sequenceLog[prefix] = s;
  m_syncLogic.addLocalNames (prefix, session, sequence);
  return true;
}

void 
SyncSocket::fetchData(const Name &prefix, const SeqNo &seq, const OnVerified& onVerified, int retry)
{
  ostringstream sessionStream;
  ostringstream seqStream;
  sessionStream << seq.getSession();
  seqStream << seq.getSeq();

  Name interestName = prefix;
  interestName.append(sessionStream.str()).append(seqStream.str());

  const OnVerifyFailed& onVerifyFailed = bind(&SyncSocket::onDataVerifyFailed, this, _1);
  
  
  ndn::Interest interest(interestName);
  m_face->expressInterest(interest, 
                          bind(&SyncSocket::onData, this, _1, _2, onVerified, onVerifyFailed), 
                          bind(&SyncSocket::onDataTimeout, this, _1, retry, onVerified, onVerifyFailed));

}

void
SyncSocket::onData(const shared_ptr<const ndn::Interest>& interest, 
                   const shared_ptr<Data>& data,
                   const OnVerified& onVerified,
                   const OnVerifyFailed& onVerifyFailed)
{
  m_verifier->verifyData(data, onVerified, onVerifyFailed);
}

void
SyncSocket::onDataTimeout(const shared_ptr<const ndn::Interest>& interest, 
                          int retry,
                          const OnVerified& onVerified,
                          const OnVerifyFailed& onVerifyFailed)
{
  if(retry > 0)
    {
      m_face->expressInterest(*interest,
                              bind(&SyncSocket::onData,
                                   this,
                                   _1,
                                   _2,
                                   onVerified,
                                   onVerifyFailed),
                              bind(&SyncSocket::onDataTimeout, 
                                   this,
                                   _1,
                                   retry - 1,
                                   onVerified,
                                   onVerifyFailed));
                              
    }
  else
    _LOG_DEBUG("interest eventually time out!");
}

void
SyncSocket::onDataVerifyFailed(const shared_ptr<Data>& data)
{
  _LOG_DEBUG("data cannot be verified!");
}


uint32_t
SyncSocket::getNextSeq (const Name &prefix, uint32_t session)
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
