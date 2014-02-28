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

INIT_LOGGER ("SyncSocket");

namespace Sync {

using ndn::shared_ptr;

SyncSocket::SyncSocket (const Name& syncPrefix,
                        const ndn::Name& dataPrefix,
                        uint64_t dataSession,
                        const IdentityCertificate& myCertificate,
                        shared_ptr<SecRuleRelative> dataRule,
                        shared_ptr<Face> face,
                        NewDataCallback dataCallback, 
                        RemoveCallback rmCallback )
  : m_dataPrefix(dataPrefix)
  , m_dataSession(dataSession)
  , m_newDataCallback(dataCallback)
  , m_myCertificate(myCertificate)
  , m_face(face)
  , m_ioService(face->ioService())
  , m_syncValidator(new SyncValidator(syncPrefix, 
                                      m_myCertificate, 
                                      m_face, 
                                      bind(&SyncSocket::publishData, this, _1, _2, _3, true),
                                      dataRule))
  , m_syncLogic (syncPrefix,
                 myCertificate,
                 m_syncValidator,
                 face,
                 bind(&SyncSocket::passCallback, this, _1),
                 rmCallback)
{}

SyncSocket::~SyncSocket()
{
}

void
SyncSocket::publishData(const uint8_t* buf, size_t len, int freshness, bool isCert)
{
  shared_ptr<Data> data = make_shared<Data>();
  data->setContent(reinterpret_cast<const uint8_t*>(buf), len);
  data->setFreshnessPeriod(1000*freshness);

  m_ioService->post(bind(&SyncSocket::publishDataInternal, this, 
                         data, m_dataPrefix, m_dataSession, isCert));
}

void
SyncSocket::publishDataInternal(shared_ptr<Data> data, const Name &prefix, uint64_t session, bool isCert)
{
  uint64_t sequence = getNextSeq(prefix, session);
  Name dataName = prefix;
  dataName.append(boost::lexical_cast<string>(session)).append(boost::lexical_cast<string>(sequence));
  if(isCert)
    dataName.append("INTRO-CERT");
  data->setName(dataName);

  m_keyChain.sign(*data, m_myCertificate.getName());
  m_face->put(*data);

  SeqNo s(session, sequence + 1);

  m_sequenceLog[prefix] = s;
  m_syncLogic.addLocalNames (prefix, session, sequence);
}

void 
SyncSocket::fetchData(const Name &prefix, const SeqNo &seq, const OnDataValidated& dataCallback, int retry)
{
  Name interestName = prefix;
  interestName.append(boost::lexical_cast<string>(seq.getSession())).append(boost::lexical_cast<string>(seq.getSeq()));

  ndn::Interest interest(interestName);
  interest.setMustBeFresh(true);

  const OnDataValidated& onValidated = bind(&SyncSocket::onDataValidated, this, _1, interestName.size(), dataCallback);
  const OnDataValidationFailed& onValidationFailed = bind(&SyncSocket::onDataValidationFailed, this, _1, _2);

  m_face->expressInterest(interest, 
                          bind(&SyncSocket::onData, this, _1, _2, onValidated, onValidationFailed), 
                          bind(&SyncSocket::onDataTimeout, this, _1, retry, onValidated, onValidationFailed));

}

void
SyncSocket::onData(const ndn::Interest& interest, Data& data,
                   const OnDataValidated& onValidated,
                   const OnDataValidationFailed& onValidationFailed)
{
  m_syncValidator->validate(data, onValidated, onValidationFailed);
}

void
SyncSocket::onDataTimeout(const ndn::Interest& interest, 
                          int retry,
                          const OnDataValidated& onValidated,
                          const OnDataValidationFailed& onValidationFailed)
{
  if(retry > 0)
    {
      m_face->expressInterest(interest,
                              bind(&SyncSocket::onData,
                                   this,
                                   _1,
                                   _2,
                                   onValidated,
                                   onValidationFailed),
                              bind(&SyncSocket::onDataTimeout, 
                                   this,
                                   _1,
                                   retry - 1,
                                   onValidated,
                                   onValidationFailed));
                              
    }
  else
    _LOG_DEBUG("interest eventually time out!");
}

void
SyncSocket::onDataValidated(const shared_ptr<const Data>& data,
                            size_t interestNameSize,
                            const OnDataValidated& onValidated)
{
  _LOG_DEBUG("--------------------" << data->getName());
  if(data->getName().size() > interestNameSize 
     && data->getName().get(interestNameSize).toEscapedString() == "INTRO-CERT")
    {
      Data rawData;
      rawData.wireDecode(data->getContent().blockFromValue());
      IntroCertificate introCert(rawData);
      m_syncValidator->addParticipant(introCert);
    }
  else
    {
      onValidated(data);
    }
}

void
SyncSocket::onDataValidationFailed(const shared_ptr<const Data>& data,
                                   const std::string& failureInfo)
{
  _LOG_DEBUG("data cannot be verified!: " << failureInfo);
}

}//Sync
