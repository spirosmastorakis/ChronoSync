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

using namespace ndn;

INIT_LOGGER ("SyncSocket");

namespace Sync {

using ndn::shared_ptr;

static const uint8_t ROUTING_PREFIX_SEPARATOR[2] = {0xF0, 0x2E};

const Name SyncSocket::EMPTY_NAME = Name();

SyncSocket::SyncSocket (const Name& syncPrefix,
                        const Name& dataPrefix,
                        uint64_t dataSession,
                        bool withRoutingPrefix,
                        const Name& routingPrefix,
                        shared_ptr<Face> face,
                        const IdentityCertificate& myCertificate,
                        shared_ptr<SecRuleRelative> dataRule,
                        NewDataCallback dataCallback,
                        RemoveCallback rmCallback )
  : m_dataPrefix(dataPrefix)
  , m_dataSession(dataSession)
  , m_withRoutingPrefix(false)
  , m_newDataCallback(dataCallback)
  , m_myCertificate(myCertificate)
  , m_face(face)
  , m_ioService(face->ioService())
{
  if(withRoutingPrefix && !routingPrefix.isPrefixOf(m_dataPrefix))
    {
      m_withRoutingPrefix = true;
      m_routableDataPrefix.append(routingPrefix).append(ROUTING_PREFIX_SEPARATOR, 2).append(m_dataPrefix);
    }


  if(static_cast<bool>(dataRule))
    {
      m_withSecurity = true;
      m_syncValidator = shared_ptr<Validator>(new SyncValidator(syncPrefix,
                                                                m_myCertificate,
                                                                *m_face,
                                                                bind(&SyncSocket::publishData, this, _1, _2, _3, true),
                                                                dataRule));
    }
  else
    {
      m_withSecurity = false;
      m_syncValidator = shared_ptr<Validator>(new ValidatorNull());
    }


  m_syncLogic = shared_ptr<SyncLogic>(new SyncLogic(syncPrefix,
                                                    myCertificate,
                                                    m_syncValidator,
                                                    m_face,
                                                    bind(&SyncSocket::passCallback, this, _1),
                                                    rmCallback));
}

SyncSocket::~SyncSocket()
{
}

void
SyncSocket::publishData(const uint8_t* buf, size_t len, int freshness, bool isCert)
{
  shared_ptr<Data> data = make_shared<Data>();
  data->setContent(reinterpret_cast<const uint8_t*>(buf), len);
  data->setFreshnessPeriod(time::milliseconds(1000*freshness));

  m_ioService->post(bind(&SyncSocket::publishDataInternal, this,
                         data, isCert));
}

void
SyncSocket::publishDataInternal(shared_ptr<Data> data, bool isCert)
{
  Name dataPrefix = (m_withRoutingPrefix ? m_routableDataPrefix : m_dataPrefix);

  uint64_t sequence = getNextSeq();

  Name dataName;
  dataName.append(m_dataPrefix)
    .append(boost::lexical_cast<std::string>(m_dataSession))
    .append(boost::lexical_cast<std::string>(sequence));
  if(isCert)
    dataName.append("INTRO-CERT");
  data->setName(dataName);
  m_keyChain.sign(*data, m_myCertificate.getName());

  if(m_withRoutingPrefix)
    {
      Name wrappedName;
      wrappedName.append(m_routableDataPrefix)
        .append(boost::lexical_cast<std::string>(m_dataSession))
        .append(boost::lexical_cast<std::string>(sequence));

      Data wrappedData(wrappedName);
      wrappedData.setContent(data->wireEncode());
      m_keyChain.sign(wrappedData, m_myCertificate.getName());

      m_face->put(wrappedData);
    }
  else
    {
      m_face->put(*data);
    }

  SeqNo s(m_dataSession, sequence + 1);
  m_sequenceLog[dataPrefix] = s;
  m_syncLogic->addLocalNames (dataPrefix, m_dataSession, sequence); // If DNS works, we should use pure m_dataprefix rather than the one with routing prefix.
}

void
SyncSocket::fetchData(const Name& prefix, const SeqNo& seq, const OnDataValidated& dataCallback, int retry)
{
  Name interestName = prefix;
  interestName.append(boost::lexical_cast<std::string>(seq.getSession())).append(boost::lexical_cast<std::string>(seq.getSeq()));

  ndn::Interest interest(interestName);
  interest.setMustBeFresh(true);

  m_face->expressInterest(interest,
                          bind(&SyncSocket::onData, this, _1, _2, dataCallback),
                          bind(&SyncSocket::onDataTimeout, this, _1, retry, dataCallback));

}

void
SyncSocket::onData(const ndn::Interest& interest, Data& data, const OnDataValidated& dataCallback)
{
  bool encaped = false;

  Name interestName = interest.getName();
  Name::const_iterator it = interestName.begin();
  Name::const_iterator end = interestName.end();

  size_t offset = interestName.size();
  for(; it != end; it++)
    {
      offset--;
      if(it->toEscapedString() == "%F0.")
        {
          encaped = true;
          break;
        }
    }

  if(!encaped)
    offset = interestName.size();

  const OnDataValidated& onValidated = bind(&SyncSocket::onDataValidated, this, _1, offset, dataCallback);
  const OnDataValidationFailed& onValidationFailed = bind(&SyncSocket::onDataValidationFailed, this, _1, _2);

  if(encaped)
    {
      shared_ptr<Data> innerData = make_shared<Data>();
      innerData->wireDecode(data.getContent().blockFromValue());
      m_syncValidator->validate(*innerData, onValidated, onValidationFailed);
    }
  else
    m_syncValidator->validate(data, onValidated, onValidationFailed);
}

void
SyncSocket::onDataTimeout(const ndn::Interest& interest, int retry, const OnDataValidated& dataCallback)
{
  if(retry > 0)
    {
      m_face->expressInterest(interest,
                              bind(&SyncSocket::onData,
                                   this,
                                   _1,
                                   _2,
                                   dataCallback),
                              bind(&SyncSocket::onDataTimeout,
                                   this,
                                   _1,
                                   retry - 1,
                                   dataCallback));

    }
  else
    _LOG_DEBUG("interest eventually time out!");
}

void
SyncSocket::onDataValidated(const shared_ptr<const Data>& data,
                            size_t interestNameSize,
                            const OnDataValidated& onValidated)
{
  if(data->getName().size() > interestNameSize
     && data->getName().get(interestNameSize).toEscapedString() == "INTRO-CERT")
    {
      if(!m_withSecurity)
        return;

      Data rawData;
      rawData.wireDecode(data->getContent().blockFromValue());
      IntroCertificate introCert(rawData);
      dynamic_pointer_cast<SyncValidator>(m_syncValidator)->addParticipant(introCert);
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
