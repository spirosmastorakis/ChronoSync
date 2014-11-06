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
 *
 * @author Zhenkai Zhu <http://irl.cs.ucla.edu/~zhenkai/>
 * @author Chaoyi Bian <bcy@pku.edu.cn>
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 * @author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "socket.hpp"
#include "logger.hpp"

INIT_LOGGER("Socket");


namespace chronosync {

const ndn::Name Socket::DEFAULT_NAME;
const ndn::shared_ptr<ndn::Validator> Socket::DEFAULT_VALIDATOR;

Socket::Socket(const Name& syncPrefix,
               const Name& userPrefix,
               ndn::Face& face,
               const UpdateCallback& updateCallback,
               const Name& signingId,
               ndn::shared_ptr<ndn::Validator> validator)
  : m_userPrefix(userPrefix)
  , m_face(face)
  , m_logic(face, syncPrefix, userPrefix, updateCallback)
  , m_signingId(signingId)
  , m_validator(validator)
{
}


void
Socket::publishData(const uint8_t* buf, size_t len, const ndn::time::milliseconds& freshness)
{
  publishData(ndn::dataBlock(ndn::tlv::Content, buf, len), freshness);
}

void
Socket::publishData(const Block& content, const ndn::time::milliseconds& freshness)
{
  shared_ptr<Data> data = make_shared<Data>();
  data->setContent(content);
  data->setFreshnessPeriod(freshness);

  SeqNo newSeq = m_logic.getSeqNo() + 1;
  Name dataName;
  dataName.append(m_logic.getSessionName()).appendNumber(newSeq);
  data->setName(dataName);

  if (m_signingId.empty())
    m_keyChain.sign(*data);
  else
    m_keyChain.signByIdentity(*data, m_signingId);

  m_face.put(*data);

  m_logic.updateSeqNo(newSeq);
}

void
Socket::fetchData(const Name& sessionName, const SeqNo& seqNo,
                  const ndn::OnDataValidated& dataCallback,
                  int nRetries)
{
  Name interestName;
  interestName.append(sessionName).appendNumber(seqNo);

  Interest interest(interestName);
  interest.setMustBeFresh(true);

  ndn::OnDataValidationFailed failureCallback =
    bind(&Socket::onDataValidationFailed, this, _1, _2);

  m_face.expressInterest(interest,
                         bind(&Socket::onData, this, _1, _2, dataCallback, failureCallback),
                         bind(&Socket::onDataTimeout, this, _1, nRetries,
                              dataCallback, failureCallback));
}

void
Socket::fetchData(const Name& sessionName, const SeqNo& seqNo,
                  const ndn::OnDataValidated& dataCallback,
                  const ndn::OnDataValidationFailed& failureCallback,
                  const ndn::OnTimeout& onTimeout,
                  int nRetries)
{
  _LOG_DEBUG(">> Socket::fetchData");
  Name interestName;
  interestName.append(sessionName).appendNumber(seqNo);

  Interest interest(interestName);
  interest.setMustBeFresh(true);

  m_face.expressInterest(interest,
                         bind(&Socket::onData, this, _1, _2, dataCallback, failureCallback),
                         onTimeout);

  _LOG_DEBUG("<< Socket::fetchData");
}

void
Socket::onData(const Interest& interest, Data& data,
               const ndn::OnDataValidated& onValidated,
               const ndn::OnDataValidationFailed& onFailed)
{
  _LOG_DEBUG("Socket::onData");

  if (static_cast<bool>(m_validator))
    m_validator->validate(data, onValidated, onFailed);
  else
    onValidated(data.shared_from_this());
}

void
Socket::onDataTimeout(const Interest& interest, int nRetries,
                      const ndn::OnDataValidated& onValidated,
                      const ndn::OnDataValidationFailed& onFailed)
{
  _LOG_DEBUG("Socket::onDataTimeout");
  if (nRetries <= 0)
    return;

  m_face.expressInterest(interest,
                         bind(&Socket::onData, this, _1, _2, onValidated, onFailed),
                         bind(&Socket::onDataTimeout, this, _1, nRetries - 1,
                              onValidated, onFailed));
}

void
Socket::onDataValidationFailed(const shared_ptr<const Data>& data,
                               const std::string& failureInfo)
{
}

ndn::ConstBufferPtr
Socket::getRootDigest() const
{
  return m_logic.getRootDigest();
}

} // namespace chronosync
