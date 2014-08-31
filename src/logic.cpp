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

#include "logic.hpp"
#include "logger.hpp"

INIT_LOGGER("Logic");

#ifdef _DEBUG
#define _LOG_DEBUG_ID(v) _LOG_DEBUG("Instance" << m_instanceId << ": " << v)
#else
#define _LOG_DEBUG_ID(v) _LOG_DEBUG(v)
#endif

namespace chronosync {

using ndn::ConstBufferPtr;
using ndn::EventId;

const uint8_t EMPTY_DIGEST_VALUE[] = {
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
  0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
  0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

#ifdef _DEBUG
int Logic::m_instanceCounter = 0;
#endif

const time::steady_clock::Duration Logic::DEFAULT_RESET_TIMER = time::seconds(0);
const time::steady_clock::Duration Logic::DEFAULT_CANCEL_RESET_TIMER = time::milliseconds(500);
const time::milliseconds Logic::DEFAULT_RESET_INTEREST_LIFETIME(1000);
const time::milliseconds Logic::DEFAULT_SYNC_INTEREST_LIFETIME(1000);
const time::milliseconds Logic::DEFAULT_SYNC_REPLY_FRESHNESS(1000);

const ndn::ConstBufferPtr Logic::EMPTY_DIGEST(new ndn::Buffer(EMPTY_DIGEST_VALUE, 32));
const ndn::name::Component Logic::RESET_COMPONENT("reset");

Logic::Logic(ndn::Face& face,
             const Name& syncPrefix,
             const Name& userPrefix,
             const UpdateCallback& onUpdate,
             const time::steady_clock::Duration& resetTimer,
             const time::steady_clock::Duration& cancelResetTimer,
             const time::milliseconds& resetInterestLifetime,
             const time::milliseconds& syncInterestLifetime,
             const time::milliseconds& syncReplyFreshness)
  : m_face(face)
  , m_syncPrefix(syncPrefix)
  , m_userPrefix(userPrefix)
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
{
#ifdef _DEBUG
  m_instanceId = m_instanceCounter++;
#endif

  _LOG_DEBUG_ID(">> Logic::Logic");

  m_syncReset = m_syncPrefix;
  m_syncReset.append("reset");

  _LOG_DEBUG_ID("Listen to: " << m_syncPrefix);
  m_syncRegisteredPrefixId =
    m_face.setInterestFilter(m_syncPrefix,
                             bind(&Logic::onSyncInterest, this, _1, _2),
                             bind(&Logic::onSyncRegisterFailed, this, _1, _2));

  setUserPrefix(m_userPrefix);

  _LOG_DEBUG_ID("<< Logic::Logic");
}

Logic::~Logic()
{
  m_face.unsetInterestFilter(m_syncRegisteredPrefixId);
  m_scheduler.cancelAllEvents();
}

void
Logic::reset()
{
  m_isInReset = true;

  m_state.reset();
  m_log.clear();

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
Logic::setUserPrefix(const Name& userPrefix)
{
  m_userPrefix = userPrefix;

  m_sessionName = m_userPrefix;
  m_sessionName.appendNumber(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count());

  m_seqNo = 0;

  reset();
}

void
Logic::updateSeqNo(const SeqNo& seqNo)
{
  _LOG_DEBUG_ID(">> Logic::updateSeqNo");
  _LOG_DEBUG_ID("seqNo: " << seqNo << " m_seqNo: " << m_seqNo);
  if (seqNo < m_seqNo || seqNo == 0)
    return;

  m_seqNo = seqNo;

  _LOG_DEBUG_ID("updateSeqNo: m_seqNo " << m_seqNo);

  if (!m_isInReset) {
    _LOG_DEBUG_ID("updateSeqNo: not in Reset ");
    ndn::ConstBufferPtr previousRoot = m_state.getRootDigest();
    {
      using namespace CryptoPP;

      std::string hash;
      StringSource(previousRoot->buf(), previousRoot->size(), true,
                   new HexEncoder(new StringSink(hash), false));
      _LOG_DEBUG_ID("Hash: " << hash);
    }

    bool isInserted = false;
    bool isUpdated = false;
    SeqNo oldSeq;
    boost::tie(isInserted, isUpdated, oldSeq) = m_state.update(m_sessionName, seqNo);

    _LOG_DEBUG_ID("Insert: " << std::boolalpha << isInserted);
    _LOG_DEBUG_ID("Updated: " << std::boolalpha << isUpdated);
    if (isInserted || isUpdated) {
      DiffStatePtr commit = make_shared<DiffState>();
      commit->update(m_sessionName, seqNo);
      commit->setRootDigest(m_state.getRootDigest());
      insertToDiffLog(commit, previousRoot);

      satisfyPendingSyncInterests(commit);
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

  if (RESET_COMPONENT != name.get(-1)) {
    // normal sync interest
    processSyncInterest(interest.shared_from_this());
  }
  else
    // reset interest
    processResetInterest(interest);

  _LOG_DEBUG_ID("<< Logic::onSyncInterest");
}

void
Logic::onSyncRegisterFailed(const Name& prefix, const std::string& msg)
{
  //Sync prefix registration failed
  _LOG_DEBUG_ID(">> Logic::onSyncRegisterFailed");
}

void
Logic::onSyncData(const Interest& interest, Data& data)
{
  _LOG_DEBUG_ID(">> Logic::onSyncData");
  // Place holder for validator.
  onSyncDataValidated(data.shared_from_this());
  _LOG_DEBUG_ID("<< Logic::onSyncData");
}

void
Logic::onResetData(const Interest& interest, Data& data)
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
Logic::onSyncDataValidationFailed(const shared_ptr<const Data>& data)
{
  // SyncReply cannot be validated.
}

void
Logic::onSyncDataValidated(const shared_ptr<const Data>& data)
{
  Name name = data->getName();
  ConstBufferPtr digest = make_shared<ndn::Buffer>(name.get(-1).value(), name.get(-1).value_size());

  processSyncData(name, digest, data->getContent().blockFromValue());
}

void
Logic::processSyncInterest(const shared_ptr<const Interest>& interest,
                           bool isTimedProcessing/*=false*/)
{
  _LOG_DEBUG_ID(">> Logic::processSyncInterest");

  const Name& name = interest->getName();
  ConstBufferPtr digest =
      make_shared<ndn::Buffer>(name.get(-1).value(), name.get(-1).value_size());

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
  if (digest == EMPTY_DIGEST) {
    _LOG_DEBUG_ID("Poor guy, he knows nothing");
    sendSyncData(name, m_state);
    return;
  }

  DiffStateContainer::iterator stateIter = m_log.find(digest);
  // If the digest of incoming interest can be found from the log
  if (stateIter != m_log.end()) {
    _LOG_DEBUG_ID("It is ok, you are so close");
    sendSyncData(name, *(*stateIter)->diff());
    return;
  }

  if (!isTimedProcessing) {
    _LOG_DEBUG_ID("Let's wait, just wait for a while");
    // Do not hurry, some incoming SyncReplies may help us to recognize the digest
    bool doesExist = m_interestTable.insert(interest, digest, true);
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
    _LOG_DEBUG_ID("OK, nobody is helping us, just tell the truth");
    m_interestTable.erase(digest);
    sendSyncData(name, m_state);
  }

  _LOG_DEBUG_ID("<< Logic::processSyncInterest");
}

void
Logic::processResetInterest(const Interest& interest)
{
  _LOG_DEBUG_ID(">> Logic::processResetInterest");
  reset();
}

void
Logic::processSyncData(const Name& name,
                       ndn::ConstBufferPtr digest,
                       const Block& syncReplyBlock)
{
  _LOG_DEBUG_ID(">> Logic::processSyncData");

  DiffStatePtr commit = make_shared<DiffState>();
  ndn::ConstBufferPtr previousRoot = m_state.getRootDigest();

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
        boost::tie(isInserted, isUpdated, oldSeq) = m_state.update(info, seq);

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
  catch (State::Error&) {
    _LOG_DEBUG_ID("Something really fishy happened during state decoding");
    // Something really fishy happened during state decoding;
    commit.reset();
    return;
  }

  if (static_cast<bool>(commit) && !commit->getLeaves().empty()) {
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
Logic::satisfyPendingSyncInterests(ConstDiffStatePtr commit)
{
  _LOG_DEBUG_ID(">> Logic::satisfyPendingSyncInterests");
  try {
    _LOG_DEBUG_ID("InterestTable size: " << m_interestTable.size());
    for (InterestTable::const_iterator it = m_interestTable.begin();
         it != m_interestTable.end(); it++) {
      ConstUnsatisfiedInterestPtr request = *it;

      if (request->isUnknown)
        sendSyncData(request->interest->getName(), m_state);
      else
        sendSyncData(request->interest->getName(), *commit);
    }
    m_interestTable.clear();
  }
  catch (InterestTable::Error&) {
    // ok. not really an error
  }
  _LOG_DEBUG_ID("<< Logic::satisfyPendingSyncInterests");
}

void
Logic::insertToDiffLog(DiffStatePtr commit, ndn::ConstBufferPtr previousRoot)
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
    m_scheduler.scheduleEvent(m_syncInterestLifetime +
                              ndn::time::milliseconds(m_reexpressionJitter()),
                              bind(&Logic::sendSyncInterest, this));
  m_scheduler.cancelEvent(m_reexpressingInterestId);
  m_reexpressingInterestId = eventId;

  Interest interest(interestName);
  interest.setMustBeFresh(true);
  interest.setInterestLifetime(m_syncInterestLifetime);

  m_outstandingInterestId = m_face.expressInterest(interest,
                                                   bind(&Logic::onSyncData, this, _1, _2),
                                                   bind(&Logic::onSyncTimeout, this, _1));

  _LOG_DEBUG_ID("Send interest: " << interest.getName());
  _LOG_DEBUG_ID("<< Logic::sendSyncInterest");
}

void
Logic::sendSyncData(const Name& name, const State& state)
{
  _LOG_DEBUG_ID(">> Logic::sendSyncData");
  shared_ptr<Data> syncReply = make_shared<Data>(name);
  syncReply->setContent(state.wireEncode());
  syncReply->setFreshnessPeriod(m_syncReplyFreshness);
  m_keyChain.sign(*syncReply);

  m_face.put(*syncReply);

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
  updateSeqNo(m_seqNo);
  _LOG_DEBUG_ID("<< Logic::cancelReset");
}

void
Logic::printDigest(ndn::ConstBufferPtr digest)
{
  using namespace CryptoPP;

  std::string hash;
  StringSource(digest->buf(), digest->size(), true,
               new HexEncoder(new StringSink(hash), false));
  _LOG_DEBUG_ID("Hash: " << hash);
}

} // namespace chronosync
