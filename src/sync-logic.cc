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
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Chaoyi Bian <bcy@pku.edu.cn>
 *	   Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 *         Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifdef NS3_MODULE
#include <ns3/ccnx-pit.h>
#include <ns3/ccnx.h>
#endif

#include "sync-logic.h"
#include "sync-diff-leaf.h"
#include "sync-full-leaf.h"
#include "sync-logging.h"
#include "sync-state.h"

#include <boost/make_shared.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <vector>

using namespace std;
using namespace ndn;

INIT_LOGGER ("SyncLogic");

#ifdef NS3_MODULE
#define GET_RANDOM(var) var.GetValue ()
#else
#define GET_RANDOM(var) var ()
#endif

#define TIME_SECONDS_WITH_JITTER(sec) \
  (TIME_SECONDS (sec) + TIME_MILLISECONDS (GET_RANDOM (m_reexpressionJitter)))

#define TIME_MILLISECONDS_WITH_JITTER(ms) \
  (TIME_MILLISECONDS (ms) + TIME_MILLISECONDS (GET_RANDOM (m_reexpressionJitter)))


namespace Sync
{

  SyncLogic::SyncLogic (const Name& syncPrefix,
                        shared_ptr<Validator> validator, 
                        shared_ptr<Face> face,
                        LogicUpdateCallback onUpdate,
                        LogicRemoveCallback onRemove)
    : m_state (new FullState)
    , m_syncInterestTable (TIME_SECONDS (m_syncInterestReexpress))
    , m_syncPrefix (syncPrefix)
    , m_onUpdate (onUpdate)
    , m_onRemove (onRemove)
    , m_perBranch (false)
    , m_validator(validator)
    , m_keyChain(new KeyChain())
    , m_face(face)
    , m_scheduler(*face->ioService())
#ifndef NS3_MODULE
    , m_randomGenerator (static_cast<unsigned int> (std::time (0)))
    , m_rangeUniformRandom (m_randomGenerator, boost::uniform_int<> (200,1000))
    , m_reexpressionJitter (m_randomGenerator, boost::uniform_int<> (100,500))
#else
    , m_rangeUniformRandom (200,1000)
    , m_reexpressionJitter (10,500)
#endif
    , m_recoveryRetransmissionInterval (m_defaultRecoveryRetransmitInterval)
{ 
#ifndef NS3_MODULE
  // In NS3 module these functions are moved to StartApplication method

  m_syncRegisteredPrefixId = m_face->setInterestFilter (m_syncPrefix, 
                                                        bind(&SyncLogic::onSyncInterest, this, _1, _2), 
                                                        bind(&SyncLogic::onSyncRegisterFailed, this, _1));
  

  m_reexpressingInterestId = m_scheduler.scheduleEvent (time::seconds (0), // no need to add jitter
                                                        bind (&SyncLogic::sendSyncInterest, this));
#endif
}

SyncLogic::SyncLogic (const Name& syncPrefix,
                      shared_ptr<Validator> validator,
                      shared_ptr<Face> face,
                      LogicPerBranchCallback onUpdateBranch)
  : m_state (new FullState)
  , m_syncInterestTable (TIME_SECONDS (m_syncInterestReexpress))
  , m_syncPrefix (syncPrefix)
  , m_onUpdateBranch (onUpdateBranch)
  , m_perBranch(true)
  , m_validator(validator)
  , m_keyChain(new KeyChain())
  , m_face(face)
  , m_scheduler(*face->ioService())
#ifndef NS3_MODULE
  , m_randomGenerator (static_cast<unsigned int> (std::time (0)))
  , m_rangeUniformRandom (m_randomGenerator, boost::uniform_int<> (200,1000))
  , m_reexpressionJitter (m_randomGenerator, boost::uniform_int<> (100,500))
#else
  , m_rangeUniformRandom (200,1000)
  , m_reexpressionJitter (10,500)
#endif
  , m_recoveryRetransmissionInterval (m_defaultRecoveryRetransmitInterval)
{ 
#ifndef NS3_MODULE
  // In NS3 module these functions are moved to StartApplication method
  
  m_syncRegisteredPrefixId = m_face->setInterestFilter (m_syncPrefix, 
                                                        bind(&SyncLogic::onSyncInterest, this, _1, _2), 
                                                        bind(&SyncLogic::onSyncRegisterFailed, this, _1));

  m_reexpressingInterestId = m_scheduler.scheduleEvent (time::seconds (0), // no need to add jitter
                                                        bind (&SyncLogic::sendSyncInterest, this));
#endif
}

SyncLogic::~SyncLogic ()
{ 
  // m_face->unsetInterestFilter(m_syncRegisteredPrefixId); 
}

#ifdef NS3_MODULE
void
SyncLogic::StartApplication ()
{
  m_ccnxHandle->SetNode (GetNode ());
  m_ccnxHandle->StartApplication ();

  m_ccnxHandle->setInterestFilter (m_syncPrefix,
                                   func_lib::bind (&SyncLogic::respondSyncInterest, this, _1));

  m_scheduler.schedule (TIME_SECONDS (0), // need to send first interests at exactly the same time
                        func_lib::bind (&SyncLogic::sendSyncInterest, this),
                        REEXPRESSING_INTEREST);
}

void
SyncLogic::StopApplication ()
{
  m_ccnxHandle->clearInterestFilter (m_syncPrefix);
  m_ccnxHandle->StopApplication ();
  m_scheduler.cancel (REEXPRESSING_INTEREST);
  m_scheduler.cancel (DELAYED_INTEREST_PROCESSING);
}
#endif

void
SyncLogic::stop()
{
  m_face->unsetInterestFilter(m_syncRegisteredPrefixId);
  m_scheduler.cancelEvent (m_reexpressingInterestId);
  m_scheduler.cancelEvent (m_delayedInterestProcessingId);
}

/**
 * Two types of intersts
 *
 * Normal name:    .../<hash>  
 * Recovery name:  .../recovery/<hash>
 */
boost::tuple<DigestConstPtr, std::string>
SyncLogic::convertNameToDigestAndType (const Name &name)
{
  BOOST_ASSERT (m_syncPrefix.isPrefixOf(name));

  int nameLengthDiff = name.size() - m_syncPrefix.size();
  BOOST_ASSERT (nameLengthDiff > 0);
  BOOST_ASSERT (nameLengthDiff < 3);
  
  string hash = name.get(-1).toEscapedString();
  string interestType;
  
  if(nameLengthDiff == 1)
    interestType = "normal";
  else
    interestType = name.get(-2).toEscapedString();

  _LOG_TRACE (hash << ", " << interestType);

  DigestPtr digest = boost::make_shared<Digest> ();
  istringstream is (hash);
  is >> *digest;

  return make_tuple (digest, interestType);
}

void
SyncLogic::onSyncInterest (const shared_ptr<const Name>& prefix, 
                           const shared_ptr<const ndn::Interest>& interest)
{
  Name name = interest->getName();

  _LOG_DEBUG("respondSyncInterest: " << name);

  try
    {
      _LOG_TRACE ("<< I " << name);

      DigestConstPtr digest;
      string type;
      tie (digest, type) = convertNameToDigestAndType (name);

      if (type == "normal") // kind of ineffective...
        {
          processSyncInterest (name, digest);
        }
      else if (type == "recovery") 
        {
          processSyncRecoveryInterest (name, digest);
        }
    }
  catch (Error::DigestCalculationError &e)
    {
      _LOG_TRACE ("Something fishy happened...");
      // log error. ignoring it for now, later we should log it
      return ;
    }
}

void
SyncLogic::onSyncRegisterFailed(const shared_ptr<const Name>& prefix)
{
  _LOG_DEBUG("Sync prefix registration failed!");
}

void
SyncLogic::onSyncData(const shared_ptr<const ndn::Interest>& interest, 
                      const shared_ptr<Data>& data,
                      const OnDataValidated& onValidated,
                      const OnDataValidationFailed& onValidationFailed)
{ m_validator->validate(data, onValidated, onValidationFailed); }

void
SyncLogic::onSyncTimeout(const shared_ptr<const ndn::Interest>& interest)
{ 
  // It is OK. Others will handle the time out situation. 
}

void
SyncLogic::onSyncDataValidationFailed(const shared_ptr<const Data>& data)
{
  _LOG_DEBUG("Sync data cannot be verified!");
}

void
SyncLogic::onSyncDataValidated(const shared_ptr<const Data>& data)
{
  Name name = data->getName();
  const char* wireData = (const char*)data->getContent().value();
  size_t len = data->getContent().value_size();

  try
    {
      _LOG_TRACE ("<< D " << name);
  
      DigestConstPtr digest;
      string type;
      tie (digest, type) = convertNameToDigestAndType (name);

      if (type == "normal")
        {
          processSyncData (name, digest, wireData, len);
        }
      else
        {
          // timer is always restarted when we schedule recovery
          m_scheduler.cancelEvent (m_reexpressingRecoveryInterestId);
          processSyncData (name, digest, wireData, len);
        }
    }
  catch (Error::DigestCalculationError &e)
    {
      _LOG_TRACE ("Something fishy happened...");
      // log error. ignoring it for now, later we should log it
      return;
    }
}

void
SyncLogic::processSyncInterest (const Name &name, DigestConstPtr digest, bool timedProcessing/*=false*/)
{
  _LOG_DEBUG("processSyncInterest");
  DigestConstPtr rootDigest;
  {
    boost::recursive_mutex::scoped_lock lock (m_stateMutex);
    rootDigest = m_state->getDigest();
  }

  // Special case when state is not empty and we have received request with zero-root digest
  if (digest->isZero () && !rootDigest->isZero ())
    {
      
      SyncStateMsg ssm;
      {
        boost::recursive_mutex::scoped_lock lock (m_stateMutex);
        ssm << (*m_state);
      }
      sendSyncData (name, digest, ssm);
      return;
    }

  if (*rootDigest == *digest)
    {
      _LOG_TRACE ("processSyncInterest (): Same state. Adding to PIT");
      m_syncInterestTable.insert (digest, name.toUri(), false);
      return;
    }
  
  DiffStateContainer::iterator stateInDiffLog = m_log.find (digest);

  if (stateInDiffLog != m_log.end ())
  {
    DiffStateConstPtr stateDiff = (*stateInDiffLog)->diff ();

    sendSyncData (name, digest, stateDiff);
    return;
  }

  if (!timedProcessing)
    {
      bool exists = m_syncInterestTable.insert (digest, name.toUri(), true);
      if (exists) // somebody else replied, so restart random-game timer
        {
          _LOG_DEBUG ("Unknown digest, but somebody may have already replied, so restart our timer");
          m_scheduler.cancelEvent (m_delayedInterestProcessingId);
        }

      uint32_t waitDelay = GET_RANDOM (m_rangeUniformRandom);      
      _LOG_DEBUG ("Digest is not in the log. Schedule processing after small delay: " << waitDelay << "ms");

      m_delayedInterestProcessingId = m_scheduler.scheduleEvent (time::milliseconds (waitDelay),
                                                                 bind (&SyncLogic::processSyncInterest, this, name, digest, true));
    }
  else
    {
      _LOG_TRACE ("                                                      (timed processing)");
      
      m_recoveryRetransmissionInterval = m_defaultRecoveryRetransmitInterval;
      sendSyncRecoveryInterests (digest);
    }
}

void
SyncLogic::processSyncData (const Name &name, DigestConstPtr digest, const char *wireData, size_t len)
{
  DiffStatePtr diffLog = boost::make_shared<DiffState> ();
  bool ownInterestSatisfied = false;
  
  try
    {

      m_syncInterestTable.remove (name.toUri()); // Remove satisfied interest from PIT

      ownInterestSatisfied = (name == m_outstandingInterestName);

      DiffState diff;
      SyncStateMsg msg;
      if (!msg.ParseFromArray(wireData, len) || !msg.IsInitialized()) 
      {
        //Throw
        BOOST_THROW_EXCEPTION (Error::SyncStateMsgDecodingFailure () );
      }
      msg >> diff;

      vector<MissingDataInfo> v;
      BOOST_FOREACH (LeafConstPtr leaf, diff.getLeaves().get<ordered>())
        {
          DiffLeafConstPtr diffLeaf = boost::dynamic_pointer_cast<const DiffLeaf> (leaf);
          BOOST_ASSERT (diffLeaf != 0);

          NameInfoConstPtr info = diffLeaf->getInfo();
          if (diffLeaf->getOperation() == UPDATE)
            {
              SeqNo seq = diffLeaf->getSeq();

              bool inserted = false;
              bool updated = false;
              SeqNo oldSeq;
              {
                boost::recursive_mutex::scoped_lock lock (m_stateMutex);
                boost::tie (inserted, updated, oldSeq) = m_state->update (info, seq);
              }

              if (inserted || updated)
                {
                  diffLog->update (info, seq);
                  if (!oldSeq.isValid())
                  {
                    oldSeq = SeqNo(seq.getSession(), 0);
                  }
                  else
                  {
                    ++oldSeq;
                  }
                  // there is no need for application to process update on forwarder node
                  if (info->toString() != forwarderPrefix)
                  {
                    MissingDataInfo mdi = {info->toString(), oldSeq, seq};
                    if (m_perBranch)
                    {
                       ostringstream interestName;
                       interestName << mdi.prefix << "/" << mdi.high.getSession() << "/" << mdi.high.getSeq();
                       m_onUpdateBranch(interestName.str());
                    }
                    else
                    {
                      v.push_back(mdi);
                    }
                  }
                }
            }
          else if (diffLeaf->getOperation() == REMOVE)
            {
              boost::recursive_mutex::scoped_lock lock (m_stateMutex);
              if (m_state->remove (info))
                {
                  diffLog->remove (info);
                  if (!m_perBranch)
                  {
                    m_onRemove (info->toString ());
                  }
                }
            }
          else
            {
            }
        }

      if (!v.empty()) 
      {
        if (!m_perBranch)
        {
           m_onUpdate(v);
        }
      }

      insertToDiffLog (diffLog);
    }
  catch (Error::SyncStateMsgDecodingFailure &e)
    {
      _LOG_TRACE ("Something really fishy happened during state decoding " <<
                  diagnostic_information (e));
      diffLog.reset ();
      // don't do anything
    }

  if ((diffLog != 0 && diffLog->getLeaves ().size () > 0) ||
      ownInterestSatisfied)
    {
      // Do it only if everything went fine and state changed

      // this is kind of wrong
      // satisfyPendingSyncInterests (diffLog); // if there are interests in PIT, there is a point to satisfy them using new state
  
      // if state has changed, then it is safe to express a new interest
      m_scheduler.cancelEvent (m_reexpressingInterestId);
      m_reexpressingInterestId = m_scheduler.scheduleEvent (time::milliseconds(GET_RANDOM (m_reexpressionJitter)),
                                                            bind (&SyncLogic::sendSyncInterest, this));
    }
}

void
SyncLogic::processSyncRecoveryInterest (const Name &name, DigestConstPtr digest)
{
  _LOG_DEBUG("processSyncRecoveryInterest");
  DiffStateContainer::iterator stateInDiffLog = m_log.find (digest);

  if (stateInDiffLog == m_log.end ())
    {
      _LOG_TRACE ("Could not find " << *digest << " in digest log");
      return;
    }

  SyncStateMsg ssm;
  {
    boost::recursive_mutex::scoped_lock lock (m_stateMutex);
    ssm << (*m_state);
  }
  sendSyncData (name, digest, ssm);
}

void
SyncLogic::satisfyPendingSyncInterests (DiffStateConstPtr diffLog)
{
  DiffStatePtr fullStateLog = boost::make_shared<DiffState> ();
  {
    boost::recursive_mutex::scoped_lock lock (m_stateMutex);
    BOOST_FOREACH (LeafConstPtr leaf, m_state->getLeaves ()/*.get<timed> ()*/)
      {
        fullStateLog->update (leaf->getInfo (), leaf->getSeq ());
        /// @todo Impose limit on how many state info should be send out
      }
  }
  
  try
    {
      uint32_t counter = 0;
      while (m_syncInterestTable.size () > 0)
        {
          Sync::Interest interest = m_syncInterestTable.pop ();

          if (!interest.m_unknown)
            {
              _LOG_TRACE (">> D " << interest.m_name);
              sendSyncData (interest.m_name, interest.m_digest, diffLog);
            }
          else
            {
              _LOG_TRACE (">> D (unknown)" << interest.m_name);
              sendSyncData (interest.m_name, interest.m_digest, fullStateLog);
            }
          counter ++;
        }
      _LOG_DEBUG ("Satisfied " << counter << " pending interests");
    }
  catch (Error::InterestTableIsEmpty &e)
    {
      // ok. not really an error
    }
}

void
SyncLogic::insertToDiffLog (DiffStatePtr diffLog) 
{
  diffLog->setDigest (m_state->getDigest());  
  if (m_log.size () > 0)
    {
      m_log.get<sequenced> ().front ()->setNext (diffLog);
    }
  m_log.erase (m_state->getDigest()); // remove diff state with the same digest.  next pointers are still valid
  /// @todo Optimization
  m_log.get<sequenced> ().push_front (diffLog);
}

void
SyncLogic::addLocalNames (const Name &prefix, uint64_t session, uint64_t seq)
{
  DiffStatePtr diff;
  {
    //cout << "Add local names" <<endl;
    boost::recursive_mutex::scoped_lock lock (m_stateMutex);
    NameInfoConstPtr info = StdNameInfo::FindOrCreate(prefix.toUri());

    _LOG_DEBUG ("addLocalNames (): old state " << *m_state->getDigest ());

    SeqNo seqN (session, seq);
    m_state->update(info, seqN);

    _LOG_DEBUG ("addLocalNames (): new state " << *m_state->getDigest ());
    
    diff = boost::make_shared<DiffState>();
    diff->update(info, seqN);
    insertToDiffLog (diff);
  }

  // _LOG_DEBUG ("PIT size: " << m_syncInterestTable.size ());
  satisfyPendingSyncInterests (diff);  
}

void
SyncLogic::remove(const Name &prefix) 
{
  DiffStatePtr diff;
  {
    boost::recursive_mutex::scoped_lock lock (m_stateMutex);
    NameInfoConstPtr info = StdNameInfo::FindOrCreate(prefix.toUri());
    m_state->remove(info);	

    // increment the sequence number for the forwarder node
    NameInfoConstPtr forwarderInfo = StdNameInfo::FindOrCreate(forwarderPrefix);

    LeafContainer::iterator item = m_state->getLeaves ().find (forwarderInfo);
    SeqNo seqNo (0);
    if (item != m_state->getLeaves ().end ())
      {
        seqNo = (*item)->getSeq ();
        ++seqNo;
      }
    m_state->update (forwarderInfo, seqNo);

    diff = boost::make_shared<DiffState>();
    diff->remove(info);
    diff->update(forwarderInfo, seqNo);

    insertToDiffLog (diff);
  }

  satisfyPendingSyncInterests (diff);  
}

void
SyncLogic::sendSyncInterest ()
{
  _LOG_DEBUG("sendSyncInterest");

  {
    boost::recursive_mutex::scoped_lock lock (m_stateMutex);
    m_outstandingInterestName = m_syncPrefix;
    ostringstream os;
    os << *m_state->getDigest();
    m_outstandingInterestName.append(os.str());
    _LOG_TRACE (">> I " << m_outstandingInterestName);
  }

  _LOG_DEBUG("sendSyncInterest: " << m_outstandingInterestName);

  m_scheduler.cancelEvent (m_reexpressingInterestId);
  m_reexpressingInterestId = m_scheduler.scheduleEvent (time::seconds(m_syncInterestReexpress)+time::milliseconds(GET_RANDOM (m_reexpressionJitter)),
                                                        bind (&SyncLogic::sendSyncInterest, this));

  ndn::Interest interest(m_outstandingInterestName);
  interest.setMustBeFresh(true);

  OnDataValidated onValidated = bind(&SyncLogic::onSyncDataValidated, this, _1);
  OnDataValidationFailed onValidationFailed = bind(&SyncLogic::onSyncDataValidationFailed, this, _1);

  m_face->expressInterest(interest,
                          bind(&SyncLogic::onSyncData, this, _1, _2, onValidated, onValidationFailed),
                          bind(&SyncLogic::onSyncTimeout, this, _1));
}

void
SyncLogic::sendSyncRecoveryInterests (DigestConstPtr digest)
{
  ostringstream os;
  os << *digest;
  
  Name interestName = m_syncPrefix;
  interestName.append("recovery").append(os.str());

  time::Duration nextRetransmission = time::milliseconds (m_recoveryRetransmissionInterval + GET_RANDOM (m_reexpressionJitter));

  m_recoveryRetransmissionInterval <<= 1;
    
  m_scheduler.cancelEvent (m_reexpressingRecoveryInterestId);
  if (m_recoveryRetransmissionInterval < 100*1000) // <100 seconds
    m_reexpressingRecoveryInterestId = m_scheduler.scheduleEvent (nextRetransmission,
                                                                  bind (&SyncLogic::sendSyncRecoveryInterests, this, digest));

  ndn::Interest interest(interestName);
  interest.setMustBeFresh(true);

  OnDataValidated onValidated = bind(&SyncLogic::onSyncDataValidated, this, _1);
  OnDataValidationFailed onValidationFailed = bind(&SyncLogic::onSyncDataValidationFailed, this, _1);

  m_face->expressInterest(interest,
                          bind(&SyncLogic::onSyncData, this, _1, _2, onValidated, onValidationFailed),
                          bind(&SyncLogic::onSyncTimeout, this, _1));
}


void
SyncLogic::sendSyncData (const Name &name, DigestConstPtr digest, StateConstPtr state)
{
  SyncStateMsg msg;
  msg << (*state);
  sendSyncData(name, digest, msg);
}

// pass in state msg instead of state, so that there is no need to lock the state until
// this function returns
void
SyncLogic::sendSyncData (const Name &name, DigestConstPtr digest, SyncStateMsg &ssm)
{
  _LOG_TRACE (">> D " << name);
  int size = ssm.ByteSize();
  char *wireData = new char[size];
  ssm.SerializeToArray(wireData, size);

  Data syncData(name);
  syncData.setContent(reinterpret_cast<const uint8_t*>(wireData), size);
  
  m_keyChain->sign(syncData);
  
  m_face->put(syncData);
  
  delete []wireData;

  // checking if our own interest got satisfied
  bool satisfiedOwnInterest = false;
  {
    boost::recursive_mutex::scoped_lock lock (m_stateMutex);
    satisfiedOwnInterest = (m_outstandingInterestName == name);
  }
  
  if (satisfiedOwnInterest)
    {
      _LOG_TRACE ("Satisfied our own Interest. Re-expressing (hopefully with a new digest)");
      
      m_scheduler.cancelEvent (m_reexpressingInterestId);
      m_reexpressingInterestId = m_scheduler.scheduleEvent (time::milliseconds(GET_RANDOM (m_reexpressionJitter)),
                                                            bind (&SyncLogic::sendSyncInterest, this));
    }
}

string
SyncLogic::getRootDigest() 
{
  ostringstream os;
  boost::recursive_mutex::scoped_lock lock (m_stateMutex);
  os << *m_state->getDigest();
  return os.str();
}

size_t
SyncLogic::getNumberOfBranches () const
{
  boost::recursive_mutex::scoped_lock lock (m_stateMutex);
  return m_state->getLeaves ().size ();
}

void
SyncLogic::printState () const
{
  boost::recursive_mutex::scoped_lock lock (m_stateMutex);

  BOOST_FOREACH (const boost::shared_ptr<Sync::Leaf> leaf, m_state->getLeaves ())
    {
      std::cout << *leaf << std::endl;
    }
}

std::map<std::string, bool>
SyncLogic::getBranchPrefixes() const
{
  boost::recursive_mutex::scoped_lock lock (m_stateMutex);

  std::map<std::string, bool> m;

  BOOST_FOREACH (const boost::shared_ptr<Sync::Leaf> leaf, m_state->getLeaves ())
    {
      std::string prefix = leaf->getInfo()->toString();
      // do not return forwarder prefix
      if (prefix != forwarderPrefix)
      {
        m.insert(pair<std::string, bool>(prefix, false));
      }
    }

  return m;
}

}
