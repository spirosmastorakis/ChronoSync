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
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef _SYNC_SOCKET_H
#define _SYNC_SOCKET_H

#include <ndn-cpp-dev/face.hpp>
#include <ndn-cpp-dev/security/validator.hpp>
#include <ndn-cpp-dev/security/validator-null.hpp>
#include <ndn-cpp-dev/security/key-chain.hpp>

#include "sync-logic.h"
#include "sync-seq-no.h"
#include "sync-validator.h"

#include <utility>
#include <map>
#include <vector>
#include <sstream>

namespace Sync {

/**
 * \ingroup sync
 * @brief A simple interface to interact with client code
 */
class SyncSocket
{
public:
  struct Error : public std::runtime_error { Error(const std::string &what) : std::runtime_error(what) {} };

  typedef ndn::function< void (const std::vector<MissingDataInfo> &, SyncSocket * ) > NewDataCallback;
  typedef ndn::function< void (const std::string &/*prefix*/ ) > RemoveCallback;

  static const ndn::Name EMPTY_NAME;

  SyncSocket(const ndn::Name& syncPrefix, 
             const ndn::Name& dataPrefix,
             uint64_t dataSession,
             bool withRoutingPrefix,
             const ndn::Name& routingPrefix,
             ndn::shared_ptr<ndn::Face> face,
             const ndn::IdentityCertificate& myCertificate,
             ndn::shared_ptr<ndn::SecRuleRelative> dataRule,
             NewDataCallback dataCallback, 
             RemoveCallback rmCallback);

  ~SyncSocket();

  void
  publishData(const uint8_t* buf, size_t len, int freshness, bool isCert = false);

  void 
  leave() 
  { 
    m_syncLogic->remove(m_withRoutingPrefix ? m_routableDataPrefix : m_dataPrefix); 
  }

  void
  remove(const ndn::Name& prefix)
  {
    m_syncLogic->remove(prefix);
  }

  void 
  fetchData(const ndn::Name &prefix, const SeqNo &seq, const ndn::OnDataValidated& onValidated, int retry = 0);

  std::string 
  getRootDigest() 
  { 
    return m_syncLogic->getRootDigest(); 
  }

  uint64_t
  getNextSeq()
  {
    // If DNS works, we should use pure m_dataprefix rather than the one with routing prefix.
    SequenceLog::iterator i = m_sequenceLog.find (m_withRoutingPrefix ? m_routableDataPrefix : m_dataPrefix);
    
    if (i != m_sequenceLog.end ())
      {
        SeqNo s = i->second;
        if (s.getSession() == m_dataSession)
          return s.getSeq();
      }
    return 0;
  }

  SyncLogic &
  getLogic() 
  { 
    return *m_syncLogic; 
  }

  void
  addParticipant(const ndn::IdentityCertificate& introducee)
  {
    if(m_withSecurity)
      {
        ndn::dynamic_pointer_cast<SyncValidator>(m_syncValidator)->addParticipant(introducee);
      }
  }

  void
  addParticipant(const IntroCertificate& introCert)
  {
    if(m_withSecurity)
      {
        ndn::dynamic_pointer_cast<SyncValidator>(m_syncValidator)->addParticipant(introCert);
      }
  }

  void
  getIntroCertNames(std::vector<ndn::Name>& list)
  {
    if(m_withSecurity)
      {
        ndn::dynamic_pointer_cast<SyncValidator>(m_syncValidator)->getIntroCertNames(list);
      }
  }

  const IntroCertificate&
  getIntroCertificate(const ndn::Name& name)
  {
    if(m_withSecurity)
      {
        return ndn::dynamic_pointer_cast<SyncValidator>(m_syncValidator)->getIntroCertificate(name);
      }
    throw Error("You are running SyncSocket without security!");
  }

  // // make this a static function so we don't have to create socket instance without
  // // knowing the local prefix. it's a wrong place for this function anyway
  // static std::string
  // GetLocalPrefix (); 
  
private:
  void
  publishDataInternal(ndn::shared_ptr<ndn::Data> data, bool isCert);

  void 
  passCallback(const std::vector<MissingDataInfo> &v) 
  { 
    m_newDataCallback(v, this); 
  }

  void
  onData(const ndn::Interest& interest, ndn::Data& data, const ndn::OnDataValidated& dataCallback);

  void
  onDataTimeout(const ndn::Interest& interest, int retry, const ndn::OnDataValidated& dataCallback);


  void
  onDataValidated(const ndn::shared_ptr<const ndn::Data>& data,
                  size_t interestNameSize,
                  const ndn::OnDataValidated& onValidated);

  void
  onDataValidationFailed(const ndn::shared_ptr<const ndn::Data>& data,
                         const std::string& failureInfo);

private:
  typedef std::map<ndn::Name, SeqNo> SequenceLog;

  ndn::Name m_dataPrefix;
  uint64_t m_dataSession;
  ndn::Name m_routableDataPrefix;
  bool m_withRoutingPrefix;
  NewDataCallback m_newDataCallback;
  SequenceLog m_sequenceLog;
  ndn::IdentityCertificate m_myCertificate;
  ndn::KeyChain m_keyChain;
  ndn::shared_ptr<ndn::Face> m_face;
  ndn::shared_ptr<boost::asio::io_service> m_ioService;
  bool m_withSecurity;
  ndn::shared_ptr<ndn::Validator> m_syncValidator;
  ndn::shared_ptr<SyncLogic>      m_syncLogic;
};

} // Sync

#endif // SYNC_SOCKET_H
