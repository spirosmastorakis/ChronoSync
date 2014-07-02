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
 * @author Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/web/index.html>
 */

#include "sync-validator.h"
#include "sync-logging.h"
#include <ndn-cxx/security/certificate-cache-ttl.hpp>
#include <queue>

using namespace ndn;

INIT_LOGGER ("SyncValidator");

namespace Sync {

using ndn::shared_ptr;

const shared_ptr<CertificateCache> SyncValidator::DefaultCertificateCache = shared_ptr<CertificateCache>();
const shared_ptr<SecRuleRelative> SyncValidator::DefaultDataRule = shared_ptr<SecRuleRelative>();

SyncValidator::SyncValidator(const Name& prefix,
                             const IdentityCertificate& anchor,
                             Face& face,
                             const PublishCertCallback& publishCertCallback,
                             shared_ptr<SecRuleRelative> rule,
                             shared_ptr<CertificateCache> certificateCache,
                             const int stepLimit)
  : Validator(face)
  , m_prefix(prefix)
  , m_anchor(anchor)
  , m_stepLimit(stepLimit)
  , m_certificateCache(certificateCache)
  , m_publishCertCallback(publishCertCallback)
  , m_dataRule(rule)
{
  if(!static_cast<bool>(m_certificateCache))
    m_certificateCache = make_shared<CertificateCacheTtl>(boost::ref(m_face.getIoService()));

  Name certPrefix = prefix;
  certPrefix.append("CHRONOS-INTRO-CERT");
  m_prefixId = m_face.setInterestFilter(certPrefix,
                                         bind(&SyncValidator::onCertInterest, this, _1, _2),
                                         bind(&SyncValidator::onCertRegisterFailed, this, _1, _2));

  setAnchor(m_anchor);
}

void
SyncValidator::deriveTrustNodes()
{
  std::queue<Name> nodeQueue;

  // Clear existing trust nodes.
  m_trustedNodes.clear();

  // Add the trust anchor.
  IntroNode origin(m_anchor);
  m_trustedNodes[origin.name()] = m_anchor.getPublicKeyInfo();
  nodeQueue.push(origin.name());

  // BFS trusted nodes.
  while(!nodeQueue.empty())
    {
      // Get next trusted node to process.
      Nodes::const_iterator it = m_introNodes.find(nodeQueue.front());
      const PublicKey& publicKey = m_trustedNodes[nodeQueue.front()];

      if(it != m_introNodes.end())
        {
          // If the trusted node exists in the graph.
          IntroNode::const_iterator eeIt = it->second.introduceeBegin();
          IntroNode::const_iterator eeEnd = it->second.introduceeEnd();
          for(; eeIt != eeEnd; eeIt++)
            {
              // Check the nodes introduced by the trusted node.
              Edges::const_iterator edgeIt = m_introCerts.find(*eeIt);
              if(edgeIt != m_introCerts.end()
                 && m_trustedNodes.find(edgeIt->second.getIntroduceeCertName()) == m_trustedNodes.end()
                 && verifySignature(edgeIt->second, publicKey))
                {
                  // If the introduced node can be validated, add it into trusted node set and the node queue.
                  m_trustedNodes[edgeIt->second.getIntroduceeCertName()] = edgeIt->second.getIntroduceeCert().getPublicKeyInfo();
                  nodeQueue.push(edgeIt->second.getIntroduceeCertName());
                }
            }
        }
      nodeQueue.pop();
    }
}

void
SyncValidator::checkPolicy (const Data& data,
                            int stepCount,
                            const OnDataValidated& onValidated,
                            const OnDataValidationFailed& onValidationFailed,
                            std::vector<shared_ptr<ValidationRequest> >& nextSteps)
{
  if(m_stepLimit == stepCount)
    return onValidationFailed(data.shared_from_this(),
                              "Maximum steps of validation reached: " + data.getName().toUri());

  if(m_prefix.isPrefixOf(data.getName()) || (static_cast<bool>(m_dataRule) && m_dataRule->satisfy(data)))
    {
      try
        {
          SignatureSha256WithRsa sig(data.getSignature());
          Name keyLocatorName = sig.getKeyLocator().getName();

          TrustNodes::const_iterator it = m_trustedNodes.find(keyLocatorName);
          if(m_trustedNodes.end() != it)
            {
              if(verifySignature(data, sig, it->second))
                return onValidated(data.shared_from_this());
              else
                return onValidationFailed(data.shared_from_this(),
                                          "Cannot verify signature: " + data.getName().toUri());
            }
          else
            {
              _LOG_DEBUG("I am: " << m_anchor.getName().get(0).toEscapedString() << " for " << data.getName());

              Name interestName = m_prefix;
              interestName.append("CHRONOS-INTRO-CERT").append(keyLocatorName.wireEncode());
              Interest interest(interestName);
              interest.setInterestLifetime(time::milliseconds(500));

              OnDataValidated onKeyValidated = bind(&SyncValidator::onCertificateValidated, this,
                                                    _1, data.shared_from_this(), onValidated, onValidationFailed);

              OnDataValidationFailed onKeyValidationFailed = bind(&SyncValidator::onCertificateValidationFailed, this,
                                                                  _1, _2, data.shared_from_this(), onValidationFailed);

              shared_ptr<ValidationRequest> nextStep = make_shared<ValidationRequest>(interest,
                                                                                      onKeyValidated,
                                                                                      onKeyValidationFailed,
                                                                                      1,
                                                                                      stepCount + 1);
              nextSteps.push_back(nextStep);

              return;
            }
        }
      catch(SignatureSha256WithRsa::Error& e)
        {
          return onValidationFailed(data.shared_from_this(),
                                    "Not SignatureSha256WithRsa signature: " + std::string(e.what()));
        }
      catch(KeyLocator::Error& e)
        {
          return onValidationFailed(data.shared_from_this(),
                                    "Key Locator is not a name: " + data.getName().toUri());
        }
    }
  else
    return onValidationFailed(data.shared_from_this(),
                              "No rule or rule is not satisfied: " + data.getName().toUri());
}

void
SyncValidator::checkPolicy (const Interest& interest,
                            int stepCount,
                            const OnInterestValidated& onValidated,
                            const OnInterestValidationFailed& onValidationFailed,
                            std::vector<shared_ptr<ValidationRequest> >& nextSteps)
{
  onValidationFailed(interest.shared_from_this(),  "No policy for signed interest checking");
}

void
SyncValidator::onCertificateValidated(const shared_ptr<const Data>& signCertificate,
                                      const shared_ptr<const Data>& data,
                                      const OnDataValidated& onValidated,
                                      const OnDataValidationFailed& onValidationFailed)
{
  try
    {
      IntroCertificate introCert(*signCertificate);
      addParticipant(introCert);

      if(verifySignature(*data, introCert.getIntroduceeCert().getPublicKeyInfo()))
        return onValidated(data);
      else
        return onValidationFailed(data,
                                  "Cannot verify signature: " + data->getName().toUri());
    }
  catch(IntroCertificate::Error& e)
    {
      return onValidationFailed(data,
                                "Intro cert decoding error: " + std::string(e.what()));
    }
}

void
SyncValidator::onCertificateValidationFailed(const shared_ptr<const Data>& signCertificate,
                                             const std::string& failureInfo,
                                             const shared_ptr<const Data>& data,
                                             const OnDataValidationFailed& onValidationFailed)
{
  onValidationFailed(data, failureInfo);
}

void
SyncValidator::onCertInterest(const Name& prefix, const Interest& interest)
{
  Name name = interest.getName();
  Edges::const_iterator it = m_introCerts.begin();
  for(; it != m_introCerts.end(); it++)
    {
      if(name.isPrefixOf(it->first))
        {
          m_face.put(it->second);
          return;
        }
    }
}

void
SyncValidator::onCertRegisterFailed(const Name& prefix, const std::string& msg)
{
  _LOG_DEBUG("SyncValidator::onCertRegisterFailed: " << msg);
}

} // namespace Sync
