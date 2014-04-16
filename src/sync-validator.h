/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SYNC_VALIDATOR_H
#define SYNC_VALIDATOR_H

#include "sync-intro-certificate.h"
#include <ndn-cpp-dev/security/validator.hpp>
#include <ndn-cpp-dev/security/key-chain.hpp>
#include <ndn-cpp-dev/security/sec-rule-relative.hpp>
#include <ndn-cpp-dev/security/certificate-cache.hpp>
#include <map>

namespace Sync {

class SyncValidator : public ndn::Validator
{
public:
  typedef ndn::function< void (const uint8_t*, size_t, int) > PublishCertCallback;

  struct Error : public ndn::Validator::Error { Error(const std::string &what) : ndn::Validator::Error(what) {} };

  static const ndn::shared_ptr<ndn::CertificateCache> DefaultCertificateCache;
  static const ndn::shared_ptr<ndn::SecRuleRelative> DefaultDataRule;

  SyncValidator(const ndn::Name& prefix,
                const ndn::IdentityCertificate& anchor,
                ndn::Face& face,
                const PublishCertCallback& publishCertCallback,
                ndn::shared_ptr<ndn::SecRuleRelative> rule = DefaultDataRule,
                ndn::shared_ptr<ndn::CertificateCache> certificateCache = DefaultCertificateCache,
                const int stepLimit = 10);

  virtual
  ~SyncValidator()
  {
    m_face.unsetInterestFilter(m_prefixId);
  }

  /**
   * @brief Set the trust anchor
   *
   * The anchor should be the participant's own certificate.
   * This anchor node is the origin of the derived trust graph.
   * Once the new anchor is set, derive the TrustNode set.
   *
   * @param anchor.
   */
  inline void
  setAnchor(const ndn::IdentityCertificate& anchor);

  /**
   * @brief Add a node into the trust graph.
   *
   * The method also create an edge from trust anchor to the node.
   *
   * @param introducee.
   * @return IntroCertificate for the introducee.
   */
  inline ndn::shared_ptr<const IntroCertificate>
  addParticipant(const ndn::IdentityCertificate& introducee);

  /**
   * @brief Add an edge into the trust graph.
   *
   * Create nodes if it is one of the edge's ends and does not exist in the graph.
   *
   * @param introCert.
   */
  inline void
  addParticipant(const IntroCertificate& introCert);

  inline void
  getIntroCertNames(std::vector<ndn::Name>& list);

  inline const IntroCertificate&
  getIntroCertificate(const ndn::Name& name);

#ifdef _TEST
  bool
  canTrust(const ndn::Name& certName)
  {
    return (m_trustedNodes.find(certName.getPrefix(-1)) != m_trustedNodes.end());
  }
#endif //_DEBUG

protected:
  /***********************
   * From ndn::Validator *
   ***********************/
  virtual void
  checkPolicy (const ndn::Data& data,
               int stepCount,
               const ndn::OnDataValidated& onValidated,
               const ndn::OnDataValidationFailed& onValidationFailed,
               std::vector<ndn::shared_ptr<ndn::ValidationRequest> >& nextSteps);

  virtual void
  checkPolicy (const ndn::Interest& interest,
               int stepCount,
               const ndn::OnInterestValidated& onValidated,
               const ndn::OnInterestValidationFailed& onValidationFailed,
               std::vector<ndn::shared_ptr<ndn::ValidationRequest> >& nextSteps);
private:
  void
  deriveTrustNodes();


  void
  onCertificateValidated(const ndn::shared_ptr<const ndn::Data>& signCertificate,
                         const ndn::shared_ptr<const ndn::Data>& data,
                         const ndn::OnDataValidated& onValidated,
                         const ndn::OnDataValidationFailed& onValidationFailed);

  void
  onCertificateValidationFailed(const ndn::shared_ptr<const ndn::Data>& signCertificate,
                                const std::string& failureInfo,
                                const ndn::shared_ptr<const ndn::Data>& data,
                                const ndn::OnDataValidationFailed& onValidationFailed);

  void
  onCertInterest (const ndn::Name& prefix, const ndn::Interest& interest);

  void
  onCertRegisterFailed(const ndn::Name& prefix, const std::string& msg);

private:
  class IntroNode;

  // Syncprefix
  ndn::Name m_prefix;

  // The map
  typedef std::map<const ndn::Name, IntroNode> Nodes;
  typedef std::map<const ndn::Name, IntroCertificate> Edges;
  Nodes m_introNodes;
  Edges m_introCerts;

  // The derived trust info
  typedef std::map<const ndn::Name, ndn::PublicKey> TrustNodes;
  ndn::IdentityCertificate m_anchor;
  TrustNodes m_trustedNodes;

  // others
  int m_stepLimit;
  ndn::shared_ptr<ndn::CertificateCache> m_certificateCache;
  ndn::KeyChain m_keychain;
  const ndn::RegisteredPrefixId* m_prefixId;
  PublishCertCallback m_publishCertCallback;
  ndn::shared_ptr<ndn::SecRuleRelative> m_dataRule;

  class IntroNode
  {
  public:
    typedef std::vector<ndn::Name>::const_iterator const_iterator;

    IntroNode()
    {}

    IntroNode(const ndn::IdentityCertificate& idCert)
      : m_nodeName(idCert.getName().getPrefix(-1))
    {}

    IntroNode(const IntroCertificate& introCert, bool isIntroducer)
    {
      if(isIntroducer)
        {
          m_nodeName = introCert.getIntroducerCertName();
          m_introduceeCerts.push_back(introCert.getName());
        }
      else
        {
          m_nodeName = introCert.getIntroduceeCertName();
          m_introducerCerts.push_back(introCert.getName());
        }
    }

    ~IntroNode()
    {}

    const ndn::Name&
    name() const
    {
      return m_nodeName;
    }

    const_iterator
    introducerBegin() const
    {
      return m_introducerCerts.begin();
    }

    const_iterator
    introducerEnd() const
    {
      return m_introducerCerts.end();
    }

    const_iterator
    introduceeBegin() const
    {
      return m_introduceeCerts.begin();
    }

    const_iterator
    introduceeEnd() const
    {
      return m_introduceeCerts.end();
    }

    void
    addIntroCertAsIntroducer(const ndn::Name& introCertName)
    {
      if(std::find(m_introduceeCerts.begin(), m_introduceeCerts.end(), introCertName) == m_introduceeCerts.end())
        m_introduceeCerts.push_back(introCertName);
    }

    void
    addIntroCertAsIntroducee(const ndn::Name& introCertName)
    {
      if(std::find(m_introducerCerts.begin(), m_introducerCerts.end(), introCertName) == m_introducerCerts.end())
        m_introducerCerts.push_back(introCertName);
    }

  private:
    ndn::Name m_nodeName;
    std::vector<ndn::Name> m_introducerCerts;
    std::vector<ndn::Name> m_introduceeCerts;
  };

};

inline void
SyncValidator::setAnchor(const ndn::IdentityCertificate& anchor)
{
  m_anchor = anchor;

  // Add anchor into trust graph if it does not exist.
  IntroNode origin(m_anchor);
  Nodes::const_iterator nodeIt = m_introNodes.find(origin.name());
  if(nodeIt == m_introNodes.end())
    m_introNodes[origin.name()] = origin;

  deriveTrustNodes();
}

inline void
SyncValidator::addParticipant(const IntroCertificate& introCert)
{
  // Check if the edge has been added before.
  ndn::Name certName = introCert.getName();
  Edges::const_iterator edgeIt = m_introCerts.find(certName);
  if(edgeIt != m_introCerts.end())
    return; // the edge has been added before.

  m_introCerts[certName] = introCert;

  // Check if the introducer has been added.
  Nodes::iterator nodeIt = m_introNodes.find(introCert.getIntroducerCertName());
  if(nodeIt == m_introNodes.end())
    {
      IntroNode node(introCert, true);
      m_introNodes[node.name()] = node;
    }
  else
    nodeIt->second.addIntroCertAsIntroducer(certName);

  // Check if the introducee has been added.
  nodeIt = m_introNodes.find(introCert.getIntroduceeCertName());
  if(nodeIt == m_introNodes.end())
    {
      IntroNode node(introCert, false);
      m_introNodes[node.name()] = node;
    }
  else
    nodeIt->second.addIntroCertAsIntroducee(certName);

  // Check if the introducer is one of the trusted nodes.
  TrustNodes::const_iterator trustNodeIt = m_trustedNodes.find(introCert.getIntroducerCertName());
  if(trustNodeIt != m_trustedNodes.end() && verifySignature(introCert, trustNodeIt->second))
    // If the introducee, add it into trusted node set.
    m_trustedNodes[introCert.getIntroduceeCertName()] = introCert.getIntroduceeCert().getPublicKeyInfo();
}

inline ndn::shared_ptr<const IntroCertificate>
SyncValidator::addParticipant(const ndn::IdentityCertificate& introducee)
{
  ndn::shared_ptr<IntroCertificate> introCert
    = ndn::shared_ptr<IntroCertificate>(new IntroCertificate(m_prefix, introducee, m_anchor.getName().getPrefix(-1)));

  m_keychain.sign(*introCert, m_anchor.getName());

  addParticipant(*introCert);

  // Publish certificate as normal data.
  ndn::Block block = introCert->wireEncode();
  m_publishCertCallback(block.wire(), block.size(), 1000);

  return introCert;
}

inline void
SyncValidator::getIntroCertNames(std::vector<ndn::Name>& list)
{
  Edges::const_iterator it = m_introCerts.begin();
  Edges::const_iterator end = m_introCerts.end();
  for(; it != end; it++)
    list.push_back(it->first);
}

inline const IntroCertificate&
SyncValidator::getIntroCertificate(const ndn::Name& name)
{
  Edges::const_iterator it = m_introCerts.find(name);
  if(it != m_introCerts.end())
    return it->second;
  else
    throw Error("No cert");
}

} // namespace Sync

#endif //SYNC_VALIDATOR_H
