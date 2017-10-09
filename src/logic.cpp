/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2017 University of California, Los Angeles
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
 * @author Sonu Mishra <https://www.linkedin.com/in/mishrasonu>
 */

#include "logic.hpp"
#include "logger.hpp"

#include <ndn-cxx/util/string-helper.hpp>

INIT_LOGGER(Logic);

#ifdef _DEBUG
#define _LOG_DEBUG_ID(v) _LOG_DEBUG("Instance" << m_instanceId << ": " << v)
#else
#define _LOG_DEBUG_ID(v) _LOG_DEBUG(v)
#endif

namespace chronosync {

using ndn::EventId;

const uint8_t EMPTY_DIGEST_VALUE[] = {
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
  0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
  0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

#ifdef _DEBUG
int Logic::s_instanceCounter = 0;
#endif

const ndn::Name Logic::DEFAULT_NAME;
const ndn::Name Logic::EMPTY_NAME;
const std::shared_ptr<Validator> Logic::DEFAULT_VALIDATOR;
const time::steady_clock::Duration Logic::DEFAULT_RESET_TIMER = time::seconds(0);
const time::steady_clock::Duration Logic::DEFAULT_CANCEL_RESET_TIMER = time::milliseconds(500);
const time::milliseconds Logic::DEFAULT_RESET_INTEREST_LIFETIME(1000);
const time::milliseconds Logic::DEFAULT_SYNC_INTEREST_LIFETIME(1000);
const time::milliseconds Logic::DEFAULT_SYNC_REPLY_FRESHNESS(1000);
const time::milliseconds Logic::DEFAULT_RECOVERY_INTEREST_LIFETIME(1000);

const ConstBufferPtr Logic::EMPTY_DIGEST(new ndn::Buffer(EMPTY_DIGEST_VALUE, 32));
const ndn::name::Component Logic::RESET_COMPONENT("reset");
const ndn::name::Component Logic::RECOVERY_COMPONENT("recovery");

Logic::Logic(ndn::Face& face,
             const Name& syncPrefix,
             const Name& defaultUserPrefix,
             const UpdateCallback& onUpdate,
             const Name& defaultSigningId,
             std::shared_ptr<Validator> validator,
             const time::steady_clock::Duration& resetTimer,
             const time::steady_clock::Duration& cancelResetTimer,
             const time::milliseconds& resetInterestLifetime,
             const time::milliseconds& syncInterestLifetime,
             const time::milliseconds& syncReplyFreshness,
             const time::milliseconds& recoveryInterestLifetime)
  : m_face(face)
  , m_syncPrefix(syncPrefix)
  , m_defaultUserPrefix(defaultUserPrefix)
  , m_interestTable(m_face.getIoService())
  , m_outstandingInterestId(0)
  , m_isInReset(false)
  , m_needPeriodReset(resetTimer > time::steady_clock::Duration::zero())
  , m_onUpdate(onUpdate)
  , m_scheduler(m_face.getIoService())
  , m_randomGenerator(static_cast<unsigned int>(std::time(0)))
  , m_rangeUniformRandom(m_randomGenerator, boost::uniform_int<>(100,500))
  , m_reexpressionJitter(m_randomGenerator, boost::uniform_int<>(100,500))
  , m_resetTimer(resetTimer)
  , m_cancelResetTimer(cancelResetTimer)
  , m_resetInterestLifetime(resetInterestLifetime)
  , m_syncInterestLifetime(syncInterestLifetime)
  , m_syncReplyFreshness(syncReplyFreshness)
  , m_recoveryInterestLifetime(recoveryInterestLifetime)
  , m_validator(validator)
{
#ifdef _DEBUG
  m_instanceId = s_instanceCounter++;
#endif

  _LOG_DEBUG_ID(">> Logic::Logic");

  addUserNode(m_defaultUserPrefix, defaultSigningId);


  m_syncReset = m_syncPrefix;
  m_syncReset.append("reset");

  _LOG_DEBUG_ID("Listen to: " << m_syncPrefix);
  m_syncRegisteredPrefixId =
    m_face.setInterestFilter(m_syncPrefix,
                             bind(&Logic::onSyncInterest, this, _1, _2),
                             bind(&Logic::onSyncRegisterFailed, this, _1, _2));

  sendSyncInterest();
  _LOG_DEBUG_ID("<< Logic::Logic");
}

Logic::~Logic()
{
  m_scheduler.cancelAllEvents();
  m_interestTable.clear();
  m_face.shutdown();
}

void
Logic::reset(bool isOnInterest)
{
  m_isInReset = true;

  m_state.reset();
  m_log.clear();

  if (!isOnInterest)
    sendResetInterest();

  // reset outstanding interest name, so that data for previous interest will be dropped.
  if (m_outstandingInterestId != 0) {
    m_face.removePendingInterest(m_outstandingInterestId);
    m_outstandingInterestId = 0;
  }

  sendSyncInterest();

  if (static_cast<bool>(m_delayedInterestProcessingId))
    m_scheduler.cancelEvent(m_delayedInterestProcessingId);

  m_delayedInterestProcessingId =
    m_scheduler.scheduleEvent(m_cancelResetTimer,
                              bind(&Logic::cancelReset, this));
}

void
Logic::setDefaultUserPrefix(const Name& defaultUserPrefix)
{
  if (defaultUserPrefix != EMPTY_NAME) {
    if (m_nodeList.find(defaultUserPrefix) != m_nodeList.end()) {
      m_defaultUserPrefix = defaultUserPrefix;
    }
  }
}

void
Logic::addUserNode(const Name& userPrefix, const Name& signingId)
{
  if (userPrefix == EMPTY_NAME)
    return;
  if (m_defaultUserPrefix == EMPTY_NAME) {
    m_defaultUserPrefix = userPrefix;
  }
  if (m_nodeList.find(userPrefix) == m_nodeList.end()) {
    m_nodeList[userPrefix].userPrefix = userPrefix;
    m_nodeList[userPrefix].signingId = signingId;
    Name sessionName = userPrefix;
    sessionName.appendNumber(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count());
    m_nodeList[userPrefix].sessionName = sessionName;
    m_nodeList[userPrefix].seqNo = 0;
    reset(false);
  }
}

void
Logic::removeUserNode(const Name& userPrefix)
{
  auto userNode = m_nodeList.find(userPrefix);
  if (userNode != m_nodeList.end()) {
    m_nodeList.erase(userNode);
    if (m_defaultUserPrefix == userPrefix) {
      if (!m_nodeList.empty()) {
        m_defaultUserPrefix = m_nodeList.begin()->second.userPrefix;
      }
      else {
        m_defaultUserPrefix = EMPTY_NAME;
      }
    }
    reset(false);
  }
}

const Name&
Logic::getSessionName(Name prefix)
{
  if (prefix == EMPTY_NAME)
    prefix = m_defaultUserPrefix;
  auto node = m_nodeList.find(prefix);
  if (node != m_nodeList.end())
    return node->second.sessionName;
  else
    BOOST_THROW_EXCEPTION(Error("Refer to non-existent node:" + prefix.toUri()));
}

const SeqNo&
Logic::getSeqNo(Name prefix)
{
  if (prefix == EMPTY_NAME)
    prefix = m_defaultUserPrefix;
  auto node = m_nodeList.find(prefix);
  if (node != m_nodeList.end())
    return node->second.seqNo;
  else
    BOOST_THROW_EXCEPTION(Logic::Error("Refer to non-existent node:" + prefix.toUri()));

}

void
Logic::updateSeqNo(const SeqNo& seqNo, const Name& updatePrefix)
{
  Name prefix;
  if (updatePrefix == EMPTY_NAME) {
    if (m_defaultUserPrefix == EMPTY_NAME)
      return;
    prefix = m_defaultUserPrefix;
  }
  else
    prefix = updatePrefix;

  auto it = m_nodeList.find(prefix);
  if (it != m_nodeList.end()) {
    NodeInfo& node = it->second;
    _LOG_DEBUG_ID(">> Logic::updateSeqNo");
    _LOG_DEBUG_ID("seqNo: " << seqNo << " m_seqNo: " << node.seqNo);
    if (seqNo < node.seqNo || seqNo == 0)
      return;

    node.seqNo = seqNo;
    _LOG_DEBUG_ID("updateSeqNo: m_seqNo " << node.seqNo);

    if (!m_isInReset) {
      _LOG_DEBUG_ID("updateSeqNo: not in Reset ");
      ConstBufferPtr previousRoot = m_state.getRootDigest();
      {
        std::string hash = ndn::toHex(previousRoot->data(), previousRoot->size(), false);
        _LOG_DEBUG_ID("Hash: " << hash);
      }

      bool isInserted = false;
      bool isUpdated = false;
      SeqNo oldSeq;
      std::tie(isInserted, isUpdated, oldSeq) = m_state.update(node.sessionName, node.seqNo);

      _LOG_DEBUG_ID("Insert: " << std::boolalpha << isInserted);
      _LOG_DEBUG_ID("Updated: " << std::boolalpha << isUpdated);
      if (isInserted || isUpdated) {
        DiffStatePtr commit = make_shared<DiffState>();
        commit->update(node.sessionName, node.seqNo);
        commit->setRootDigest(m_state.getRootDigest());
        insertToDiffLog(commit, previousRoot);

        satisfyPendingSyncInterests(prefix, commit);
        formAndSendExcludeInterest(prefix, *commit, previousRoot);
      }
    }
  }
}

ConstBufferPtr
Logic::getRootDigest() const
{
  return m_state.getRootDigest();
}

void
Logic::printState(std::ostream& os) const
{
  BOOST_FOREACH(ConstLeafPtr leaf, m_state.getLeaves())
    {
      os << *leaf << "\n";
    }
}

std::set<Name>
Logic::getSessionNames() const
{
  std::set<Name> sessionNames;

  BOOST_FOREACH(ConstLeafPtr leaf, m_state.getLeaves())
    {
      sessionNames.insert(leaf->getSessionName());
    }

  return sessionNames;
}

void
Logic::onSyncInterest(const Name& prefix, const Interest& interest)
{
  _LOG_DEBUG_ID(">> Logic::onSyncInterest");
  Name name = interest.getName();

  _LOG_DEBUG_ID("InterestName: " << name);

  if (name.size() >= 1 && RESET_COMPONENT == name.get(-1)) {
    processResetInterest(interest);
  }
  else if (name.size() >= 2 && RECOVERY_COMPONENT == name.get(-2)) {
    processRecoveryInterest(interest);
  }
  // Do not process exclude interests, they should be answered by CS
  else if (interest.getExclude().empty()) {
    processSyncInterest(interest);
  }

  _LOG_DEBUG_ID("<< Logic::onSyncInterest");
}

void
Logic::onSyncRegisterFailed(const Name& prefix, const std::string& msg)
{
  //Sync prefix registration failed
  _LOG_DEBUG_ID(">> Logic::onSyncRegisterFailed");
}

void
Logic::onSyncData(const Interest& interest, const Data& data)
{
  _LOG_DEBUG_ID(">> Logic::onSyncData");
  // if (static_cast<bool>(m_validator))
  //   m_validator->validate(data,
  //                         bind(&Logic::onSyncDataValidated, this, _1),
  //                         bind(&Logic::onSyncDataValidationFailed, this, _1));
  // else
  //   onSyncDataValidated(data);

  if (interest.getExclude().empty()) {
    _LOG_DEBUG_ID("First data");
    onSyncDataValidated(data);
  }
  else {
    _LOG_DEBUG_ID("Data obtained using exclude filter");
    onSyncDataValidated(data, false);
  }
  sendExcludeInterest(interest, data);

  _LOG_DEBUG_ID("<< Logic::onSyncData");
}

void
Logic::onResetData(const Interest& interest, const Data& data)
{
  // This should not happened, drop the received data.
}

void
Logic::onSyncTimeout(const Interest& interest)
{
  // It is OK. Others will handle the time out situation.
  _LOG_DEBUG_ID(">> Logic::onSyncTimeout");
  _LOG_DEBUG_ID("Interest: " << interest.getName());
  _LOG_DEBUG_ID("<< Logic::onSyncTimeout");
}

void
Logic::onSyncDataValidationFailed(const Data& data)
{
  // SyncReply cannot be validated.
}

void
Logic::onSyncDataValidated(const Data& data, bool firstData)
{
  Name name = data.getName();
  ConstBufferPtr digest = make_shared<ndn::Buffer>(name.get(-1).value(), name.get(-1).value_size());

  processSyncData(name, digest, data.getContent().blockFromValue(), firstData);
}

void
Logic::processSyncInterest(const Interest& interest, bool isTimedProcessing/*=false*/)
{
  _LOG_DEBUG_ID(">> Logic::processSyncInterest");

  Name name = interest.getName();
  ConstBufferPtr digest = make_shared<ndn::Buffer>(name.get(-1).value(), name.get(-1).value_size());

  ConstBufferPtr rootDigest = m_state.getRootDigest();

  // If the digest of the incoming interest is the same as root digest
  // Put the interest into InterestTable
  if (*rootDigest == *digest) {
    _LOG_DEBUG_ID("Oh, we are in the same state");
    m_interestTable.insert(interest, digest, false);

    if (!m_isInReset)
      return;

    if (!isTimedProcessing) {
      _LOG_DEBUG_ID("Non timed processing in reset");
      // Still in reset, our own seq has not been put into state yet
      // Do not hurry, some others may be also resetting and may send their reply
      if (static_cast<bool>(m_delayedInterestProcessingId))
        m_scheduler.cancelEvent(m_delayedInterestProcessingId);

      time::milliseconds after(m_rangeUniformRandom());
      _LOG_DEBUG_ID("After: " << after);
      m_delayedInterestProcessingId =
        m_scheduler.scheduleEvent(after,
                                  bind(&Logic::processSyncInterest, this, interest, true));
    }
    else {
      _LOG_DEBUG_ID("Timed processing in reset");
      // Now we can get out of reset state by putting our own stuff into m_state.
      cancelReset();
    }

    return;
  }

  // If the digest of incoming interest is an "empty" digest
  if (*digest == *EMPTY_DIGEST) {
    _LOG_DEBUG_ID("Poor guy, he knows nothing");
    sendSyncData(m_defaultUserPrefix, name, m_state);
    return;
  }

  DiffStateContainer::iterator stateIter = m_log.find(digest);
  // If the digest of incoming interest can be found from the log
  if (stateIter != m_log.end()) {
    _LOG_DEBUG_ID("It is ok, you are so close");
    sendSyncData(m_defaultUserPrefix, name, *(*stateIter)->diff());
    return;
  }

  if (!isTimedProcessing) {
    _LOG_DEBUG_ID("Let's wait, just wait for a while");
    // Do not hurry, some incoming SyncReplies may help us to recognize the digest
    bool doesExist = m_interestTable.has(digest);
    m_interestTable.insert(interest, digest, true);
    if (doesExist)
      // Original comment (not sure): somebody else replied, so restart random-game timer
      // YY: Get the same SyncInterest again, refresh the timer
      m_scheduler.cancelEvent(m_delayedInterestProcessingId);

    m_delayedInterestProcessingId =
      m_scheduler.scheduleEvent(time::milliseconds(m_rangeUniformRandom()),
                                bind(&Logic::processSyncInterest, this, interest, true));
  }
  else {
    // OK, nobody is helping us, just tell the truth.
    _LOG_DEBUG_ID("OK, nobody is helping us, let us try to recover");
    m_interestTable.erase(digest);
    sendRecoveryInterest(digest);
  }

  _LOG_DEBUG_ID("<< Logic::processSyncInterest");
}

void
Logic::processResetInterest(const Interest& interest)
{
  _LOG_DEBUG_ID(">> Logic::processResetInterest");
  reset(true);
}

void
Logic::processSyncData(const Name& name,
                       ConstBufferPtr digest,
                       const Block& syncReplyBlock,
                       bool firstData)
{
  _LOG_DEBUG_ID(">> Logic::processSyncData");
  DiffStatePtr commit = make_shared<DiffState>();
  ConstBufferPtr previousRoot = m_state.getRootDigest();

  try {
    m_interestTable.erase(digest); // Remove satisfied interest from PIT

    State reply;
    reply.wireDecode(syncReplyBlock);

    std::vector<MissingDataInfo> v;
    BOOST_FOREACH(ConstLeafPtr leaf, reply.getLeaves().get<ordered>())
      {
        BOOST_ASSERT(leaf != 0);

        const Name& info = leaf->getSessionName();
        SeqNo seq = leaf->getSeq();

        bool isInserted = false;
        bool isUpdated = false;
        SeqNo oldSeq;
        std::tie(isInserted, isUpdated, oldSeq) = m_state.update(info, seq);
        if (isInserted || isUpdated) {
          commit->update(info, seq);

          oldSeq++;
          MissingDataInfo mdi = {info, oldSeq, seq};
          v.push_back(mdi);
        }
      }

    if (!v.empty()) {
      m_onUpdate(v);

      commit->setRootDigest(m_state.getRootDigest());
      insertToDiffLog(commit, previousRoot);
    }
    else {
      _LOG_DEBUG_ID("What? nothing new");
    }
  }
  catch (const State::Error&) {
    _LOG_DEBUG_ID("Something really fishy happened during state decoding");
    // Something really fishy happened during state decoding;
    commit.reset();
    return;
  }

  if (static_cast<bool>(commit) && !commit->getLeaves().empty() && firstData) {
    // state changed and it is safe to express a new interest
    time::steady_clock::Duration after = time::milliseconds(m_reexpressionJitter());
    _LOG_DEBUG_ID("Reschedule sync interest after: " << after);
    EventId eventId = m_scheduler.scheduleEvent(after,
                                                bind(&Logic::sendSyncInterest, this));

    m_scheduler.cancelEvent(m_reexpressingInterestId);
    m_reexpressingInterestId = eventId;
  }
}

void
Logic::satisfyPendingSyncInterests(const Name& updatedPrefix, ConstDiffStatePtr commit)
{
  _LOG_DEBUG_ID(">> Logic::satisfyPendingSyncInterests");
  try {
    _LOG_DEBUG_ID("InterestTable size: " << m_interestTable.size());
    auto it = m_interestTable.begin();
    while (it != m_interestTable.end()) {
      ConstUnsatisfiedInterestPtr request = *it;
      ++it;
      if (request->isUnknown)
        sendSyncData(updatedPrefix, request->interest.getName(), m_state);
      else
        sendSyncData(updatedPrefix, request->interest.getName(), *commit);
    }
    m_interestTable.clear();
  }
  catch (const InterestTable::Error&) {
    // ok. not really an error
  }
  _LOG_DEBUG_ID("<< Logic::satisfyPendingSyncInterests");
}

void
Logic::insertToDiffLog(DiffStatePtr commit, ConstBufferPtr previousRoot)
{
  _LOG_DEBUG_ID(">> Logic::insertToDiffLog");
  // Connect to the history
  if (!m_log.empty())
    (*m_log.find(previousRoot))->setNext(commit);

  // Insert the commit
  m_log.erase(commit->getRootDigest());
  m_log.insert(commit);
  _LOG_DEBUG_ID("<< Logic::insertToDiffLog");
}

void
Logic::sendResetInterest()
{
  _LOG_DEBUG_ID(">> Logic::sendResetInterest");

  if (m_needPeriodReset) {
    _LOG_DEBUG_ID("Need Period Reset");
    _LOG_DEBUG_ID("ResetTimer: " << m_resetTimer);

    EventId eventId =
      m_scheduler.scheduleEvent(m_resetTimer + ndn::time::milliseconds(m_reexpressionJitter()),
                                bind(&Logic::sendResetInterest, this));
    m_scheduler.cancelEvent(m_resetInterestId);
    m_resetInterestId = eventId;
  }

  Interest interest(m_syncReset);
  interest.setMustBeFresh(true);
  interest.setInterestLifetime(m_resetInterestLifetime);
  m_face.expressInterest(interest,
                         bind(&Logic::onResetData, this, _1, _2),
                         bind(&Logic::onSyncTimeout, this, _1), // Nack
                         bind(&Logic::onSyncTimeout, this, _1));

  _LOG_DEBUG_ID("<< Logic::sendResetInterest");
}

void
Logic::sendSyncInterest()
{
  _LOG_DEBUG_ID(">> Logic::sendSyncInterest");

  Name interestName;
  interestName.append(m_syncPrefix)
    .append(ndn::name::Component(*m_state.getRootDigest()));

  m_outstandingInterestName = interestName;

#ifdef _DEBUG
  printDigest(m_state.getRootDigest());
#endif

  EventId eventId =
    m_scheduler.scheduleEvent(m_syncInterestLifetime / 2 +
                              ndn::time::milliseconds(m_reexpressionJitter()),
                              bind(&Logic::sendSyncInterest, this));
  m_scheduler.cancelEvent(m_reexpressingInterestId);
  m_reexpressingInterestId = eventId;

  Interest interest(interestName);
  interest.setMustBeFresh(true);
  interest.setInterestLifetime(m_syncInterestLifetime);

  m_outstandingInterestId = m_face.expressInterest(interest,
                                                   bind(&Logic::onSyncData, this, _1, _2),
                                                   bind(&Logic::onSyncTimeout, this, _1), // Nack
                                                   bind(&Logic::onSyncTimeout, this, _1));

  _LOG_DEBUG_ID("Send interest: " << interest.getName());
  _LOG_DEBUG_ID("<< Logic::sendSyncInterest");
}

void
Logic::sendSyncData(const Name& nodePrefix, const Name& name, const State& state)
{
  _LOG_DEBUG_ID(">> Logic::sendSyncData");
  Data syncReply(name);
  syncReply.setContent(state.wireEncode());
  syncReply.setFreshnessPeriod(m_syncReplyFreshness);
  if (m_nodeList.find(nodePrefix) == m_nodeList.end())
    return;
  if (m_nodeList[nodePrefix].signingId.empty())
    m_keyChain.sign(syncReply);
  else
    m_keyChain.sign(syncReply, security::signingByIdentity(m_nodeList[nodePrefix].signingId));

  m_face.put(syncReply);

  // checking if our own interest got satisfied
  if (m_outstandingInterestName == name) {
    // remove outstanding interest
    if (m_outstandingInterestId != 0) {
      m_face.removePendingInterest(m_outstandingInterestId);
      m_outstandingInterestId = 0;
    }

    // re-schedule sending Sync interest
    time::milliseconds after(m_reexpressionJitter());
    _LOG_DEBUG_ID("Satisfy our own interest");
    _LOG_DEBUG_ID("Reschedule sync interest after " << after);
    EventId eventId = m_scheduler.scheduleEvent(after, bind(&Logic::sendSyncInterest, this));
    m_scheduler.cancelEvent(m_reexpressingInterestId);
    m_reexpressingInterestId = eventId;
  }
  _LOG_DEBUG_ID("<< Logic::sendSyncData");
}

void
Logic::cancelReset()
{
  _LOG_DEBUG_ID(">> Logic::cancelReset");
  if (!m_isInReset)
    return;

  m_isInReset = false;
  for (const auto& node : m_nodeList) {
    updateSeqNo(node.second.seqNo, node.first);
  }
  _LOG_DEBUG_ID("<< Logic::cancelReset");
}

void
Logic::printDigest(ConstBufferPtr digest)
{
  std::string hash = ndn::toHex(digest->data(), digest->size(), false);
  _LOG_DEBUG_ID("Hash: " << hash);
}

void
Logic::sendRecoveryInterest(ConstBufferPtr digest)
{
  _LOG_DEBUG_ID(">> Logic::sendRecoveryInterest");

  Name interestName;
  interestName.append(m_syncPrefix)
              .append(RECOVERY_COMPONENT)
              .append(ndn::name::Component(*digest));

  Interest interest(interestName);
  interest.setMustBeFresh(true);
  interest.setInterestLifetime(m_recoveryInterestLifetime);

  m_face.expressInterest(interest,
                         bind(&Logic::onRecoveryData, this, _1, _2),
                         bind(&Logic::onRecoveryTimeout, this, _1), // Nack
                         bind(&Logic::onRecoveryTimeout, this, _1));

  _LOG_DEBUG_ID("interest: " << interest.getName());
  _LOG_DEBUG_ID("<< Logic::sendRecoveryInterest");
}

void
Logic::processRecoveryInterest(const Interest& interest)
{
  _LOG_DEBUG_ID(">> Logic::processRecoveryInterest");

  Name name = interest.getName();
  ConstBufferPtr digest = make_shared<ndn::Buffer>(name.get(-1).value(), name.get(-1).value_size());

  ConstBufferPtr rootDigest = m_state.getRootDigest();

  DiffStateContainer::iterator stateIter = m_log.find(digest);

  if (stateIter != m_log.end() || *digest == *EMPTY_DIGEST || *rootDigest == *digest) {
    _LOG_DEBUG_ID("I can help you recover");
    sendSyncData(m_defaultUserPrefix, name, m_state);
    return;
  }
  _LOG_DEBUG_ID("<< Logic::processRecoveryInterest");
}

void
Logic::onRecoveryData(const Interest& interest, const Data& data)
{
  _LOG_DEBUG_ID(">> Logic::onRecoveryData");
  onSyncDataValidated(data);
  _LOG_DEBUG_ID("<< Logic::onRecoveryData");
}

void
Logic::onRecoveryTimeout(const Interest& interest)
{
  _LOG_DEBUG_ID(">> Logic::onRecoveryTimeout");
  _LOG_DEBUG_ID("Interest: " << interest.getName());
  _LOG_DEBUG_ID("<< Logic::onRecoveryTimeout");
}

void
Logic::sendExcludeInterest(const Interest& interest, const Data& data)
{
  _LOG_DEBUG_ID(">> Logic::sendExcludeInterest");

  Name interestName = interest.getName();
  Interest excludeInterest(interestName);

  Exclude exclude = interest.getExclude();
  exclude.excludeOne(data.getFullName().get(-1));
  excludeInterest.setExclude(exclude);

  excludeInterest.setInterestLifetime(m_syncInterestLifetime);

  if (excludeInterest.wireEncode().size() > ndn::MAX_NDN_PACKET_SIZE) {
    return;
  }

  m_face.expressInterest(excludeInterest,
                         bind(&Logic::onSyncData, this, _1, _2),
                         bind(&Logic::onSyncTimeout, this, _1), // Nack
                         bind(&Logic::onSyncTimeout, this, _1));

  _LOG_DEBUG_ID("Send interest: " << excludeInterest.getName());
  _LOG_DEBUG_ID("<< Logic::sendExcludeInterest");
}

void
Logic::formAndSendExcludeInterest(const Name& nodePrefix, const State& commit, ConstBufferPtr previousRoot)
{
  _LOG_DEBUG_ID(">> Logic::formAndSendExcludeInterest");
  Name interestName;
  interestName.append(m_syncPrefix)
              .append(ndn::name::Component(*previousRoot));
  Interest interest(interestName);

  Data data(interestName);
  data.setContent(commit.wireEncode());
  data.setFreshnessPeriod(m_syncReplyFreshness);
  if (m_nodeList.find(nodePrefix) == m_nodeList.end())
    return;
  if (m_nodeList[nodePrefix].signingId.empty())
    m_keyChain.sign(data);
  else
    m_keyChain.sign(data, security::signingByIdentity(m_nodeList[nodePrefix].signingId));

  sendExcludeInterest(interest, data);

  _LOG_DEBUG_ID("<< Logic::formAndSendExcludeInterest");
}

} // namespace chronosync
