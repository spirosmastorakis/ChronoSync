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

#ifndef CHRONOSYNC_LOGIC_HPP
#define CHRONOSYNC_LOGIC_HPP

#include "boost-header.h"
#include <memory>
#include <map>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/security/key-chain.hpp>

#include "interest-table.hpp"
#include "diff-state-container.hpp"

namespace chronosync {

/**
 * @brief The missing sequence numbers for a session
 *
 * This class is used to notify the clients of Logic
 * the details of state changes.
 *
 * Instances of this class is usually used as elements of some containers
 * such as std::vector, thus it is copyable.
 */
class MissingDataInfo
{
public:
  /// @brief session name
  Name session;
  /// @brief the lowest one of missing sequence numbers
  SeqNo low;
  /// @brief the highest one of missing sequence numbers
  SeqNo high;
};

/**
 * @brief The callback function to handle state updates
 *
 * The parameter is a set of MissingDataInfo, of which each corresponds to
 * a session that has changed its state.
 */
typedef function<void(const std::vector<MissingDataInfo>&)> UpdateCallback;

/**
 * @brief Logic of ChronoSync
 */
class Logic : noncopyable
{
public:
  static const time::steady_clock::Duration DEFAULT_RESET_TIMER;
  static const time::steady_clock::Duration DEFAULT_CANCEL_RESET_TIMER;
  static const time::milliseconds DEFAULT_RESET_INTEREST_LIFETIME;
  static const time::milliseconds DEFAULT_SYNC_INTEREST_LIFETIME;
  static const time::milliseconds DEFAULT_SYNC_REPLY_FRESHNESS;

  /**
   * @brief Constructor
   *
   * @param syncPrefix The prefix of the sync group
   * @param userPrefix The prefix of the user who owns the session
   * @param onUpdate The callback function to handle state updates
   * @param resetTimer The timer to periodically send Reset Interest
   * @param syncReplyFreshness The FreshnessPeriod of sync reply
   * @param resetInterestLifetime The lifetime of sync interest
   * @param resetInterestLifetime The lifetime of Reset Interest
   * @param cancelResetTimer The timer to exit from Reset state
   */
  Logic(ndn::Face& face,
        const Name& syncPrefix,
        const Name& userPrefix,
        const UpdateCallback& onUpdate,
        const time::steady_clock::Duration& resetTimer = DEFAULT_RESET_TIMER,
        const time::steady_clock::Duration& cancelResetTimer = DEFAULT_CANCEL_RESET_TIMER,
        const time::milliseconds& resetInterestLifetime = DEFAULT_RESET_INTEREST_LIFETIME,
        const time::milliseconds& syncInterestLifetime = DEFAULT_SYNC_INTEREST_LIFETIME,
        const time::milliseconds& syncReplyFreshness = DEFAULT_SYNC_REPLY_FRESHNESS);

  ~Logic();

  /// @brief Reset the sync tree (and restart synchronization again)
  void
  reset();

  /**
   * @brief Set user prefix
   *
   * This method will also change the session name and trigger reset.
   *
   * @param userPrefix The prefix of user.
   */
  void
  setUserPrefix(const Name& userPrefix);

  /// @brief Get the name of the local session.
  const Name&
  getSessionName() const
  {
    return m_sessionName;
  }

  /// @brief Get current seqNo of the local session.
  const SeqNo&
  getSeqNo() const
  {
    return m_seqNo;
  }

  /**
   * @brief Update the seqNo of the local session
   *
   * The method updates the existing seqNo with the supplied seqNo.
   *
   * @param seq The new seqNo.
   */
  void
  updateSeqNo(const SeqNo& seq);

  /// @brief Get root digest of current sync tree
  ndn::ConstBufferPtr
  getRootDigest() const;

  /// @brief Get the name of all sessions
  std::set<Name>
  getSessionNames() const;

CHRONOSYNC_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  printState(std::ostream& os) const;

  ndn::Scheduler&
  getScheduler()
  {
    return m_scheduler;
  }

  State&
  getState()
  {
    return m_state;
  }

private:
  /**
   * @brief Callback to handle Sync Interest
   *
   * This method checks whether an incoming interest is a normal one or a reset
   * and dispatches the incoming interest to corresponding processing methods.
   *
   * @param prefix   The prefix of the sync group.
   * @param interest The incoming sync interest.
   */
  void
  onSyncInterest(const Name& prefix, const Interest& interest);

  /**
   * @brief Callback to handle Sync prefix registration failure
   *
   * This method does nothing for now.
   *
   * @param prefix The prefix of the sync group.
   * @param msg    The error message.
   */
  void
  onSyncRegisterFailed(const Name& prefix, const std::string& msg);

  /**
   * @brief Callback to handle Sync Reply
   *
   * This method calls validator to validate Sync Reply.
   * For now, validation is disabled, Logic::onSyncDataValidated is called
   * directly.
   *
   * @param interest The Sync Interest
   * @param data     The reply to the Sync Interest
   */
  void
  onSyncData(const Interest& interest, Data& data);

  /**
   * @brief Callback to handle reply to Reset Interest.
   *
   * This method does nothing, since reply to Reset Interest is not useful for now.
   *
   * @param interest The Reset Interest
   * @param data     The reply to the Reset Interest
   */
  void
  onResetData(const Interest& interest, Data& data);

  /**
   * @brief Callback to handle Sync Interest timeout.
   *
   * This method does nothing, since Logic per se handles timeout explicitly.
   *
   * @param interest The Sync Interest
   */
  void
  onSyncTimeout(const Interest& interest);

  /**
   * @brief Callback to invalid Sync Reply.
   *
   * This method does nothing but drops the invalid reply.
   *
   * @param data The invalid Sync Reply
   */
  void
  onSyncDataValidationFailed(const shared_ptr<const Data>& data);

  /**
   * @brief Callback to valid Sync Reply.
   *
   * This method simply passes the valid reply to processSyncData.
   *
   * @param data The valid Sync Reply.
   */
  void
  onSyncDataValidated(const shared_ptr<const Data>& data);

  /**
   * @brief Process normal Sync Interest
   *
   * This method extracts the digest from the incoming Sync Interest,
   * compares it against current local digest, and process the Sync
   * Interest according to the comparison result.  See docs/design.rst
   * for more details.
   *
   * @param interest          The incoming interest
   * @param isTimedProcessing True if the interest needs an immediate reply,
   *                          otherwise hold the interest for a while before
   *                          making a reply (to avoid unnecessary recovery)
   */
  void
  processSyncInterest(const shared_ptr<const Interest>& interest,
                      bool isTimedProcessing = false);

  /**
   * @brief Process reset Sync Interest
   *
   * This method simply call Logic::reset()
   *
   * @param interest The incoming interest.
   */
  void
  processResetInterest(const Interest& interest);

  /**
   * @brief Process Sync Reply.
   *
   * This method extracts state update information from Sync Reply and applies
   * it to the Sync Tree and re-express Sync Interest.
   *
   * @param name           The data name of the Sync Reply.
   * @param digest         The digest in the data name.
   * @param syncReplyBlock The content of the Sync Reply.
   */
  void
  processSyncData(const Name& name,
                  ndn::ConstBufferPtr digest,
                  const Block& syncReplyBlock);

  /**
   * @brief Insert state diff into log
   *
   * @param diff         The diff .
   * @param previousRoot The root digest before state changes.
   */
  void
  insertToDiffLog(DiffStatePtr diff,
                  ndn::ConstBufferPtr previousRoot);

  /**
   * @brief Reply to all pending Sync Interests with a particular commit (or diff)
   *
   * @param commit The diff.
   */
  void
  satisfyPendingSyncInterests(ConstDiffStatePtr commit);

  /// @brief Helper method to send normal Sync Interest
  void
  sendSyncInterest();

  /// @brief Helper method to send reset Sync Interest
  void
  sendResetInterest();

  /// @brief Helper method to send Sync Reply
  void
  sendSyncData(const Name& name, const State& state);

  /**
   * @brief Unset reset status
   *
   * By invoking this method, one can add its own state into the Sync Tree, thus
   * jumping out of the reset status
   */
  void
  cancelReset();

  void
  printDigest(ndn::ConstBufferPtr digest);

private:

  static const ndn::ConstBufferPtr EMPTY_DIGEST;
  static const ndn::name::Component RESET_COMPONENT;

  // Communication
  ndn::Face& m_face;
  Name m_syncPrefix;
  const ndn::RegisteredPrefixId* m_syncRegisteredPrefixId;
  Name m_syncReset;
  Name m_userPrefix;

  // State
  Name m_sessionName;
  SeqNo m_seqNo;
  State m_state;
  DiffStateContainer m_log;
  InterestTable m_interestTable;
  Name m_outstandingInterestName;
  const ndn::PendingInterestId* m_outstandingInterestId;
  bool m_isInReset;
  bool m_needPeriodReset;

  // Callback
  UpdateCallback m_onUpdate;

  // Event
  ndn::Scheduler m_scheduler;
  ndn::EventId m_delayedInterestProcessingId;
  ndn::EventId m_reexpressingInterestId;
  ndn::EventId m_resetInterestId;

  // Timer
  boost::mt19937 m_randomGenerator;
  boost::variate_generator<boost::mt19937&, boost::uniform_int<> > m_rangeUniformRandom;
  boost::variate_generator<boost::mt19937&, boost::uniform_int<> > m_reexpressionJitter;
  /// @brief Timer to send next reset 0 for no reset
  time::steady_clock::Duration m_resetTimer;
  /// @brief Timer to cancel reset state
  time::steady_clock::Duration m_cancelResetTimer;
  /// @brief Lifetime of reset interest
  time::milliseconds m_resetInterestLifetime;
  /// @brief Lifetime of sync interest
  time::milliseconds m_syncInterestLifetime;
  /// @brief FreshnessPeriod of SyncReply
  time::milliseconds m_syncReplyFreshness;

  // Others
  ndn::KeyChain m_keyChain;

#ifdef _DEBUG
  int m_instanceId;
  static int m_instanceCounter;
#endif
};


} // namespace chronosync

#endif // CHRONOSYNC_LOGIC_HPP
