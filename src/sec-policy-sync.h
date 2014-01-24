/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SEC_POLICY_SYNC_H
#define SEC_POLICY_SYNC_H

#include <ndn-cpp-dev/face.hpp>
#include <ndn-cpp-dev/security/key-chain.hpp>
#include <ndn-cpp-dev/security/verifier.hpp>
#include <ndn-cpp-dev/security/sec-policy.hpp>
#include <ndn-cpp-dev/security/identity-certificate.hpp>
#include <ndn-cpp-et/policy/sec-rule-relative.hpp>
// #include <ndn-cpp-et/policy/sec-rule-specific.hpp>
#include <map>

class SecPolicySync : public ndn::SecPolicy
{
public:
  SecPolicySync(const ndn::Name& signingIdentity,
                const ndn::Name& signingCertificateName,
                const ndn::Name& syncPrefix,
                ndn::ptr_lib::shared_ptr<ndn::Face> face,
                int m_stepLimit = 3);
  
  virtual
  ~SecPolicySync();

  bool 
  skipVerifyAndTrust (const ndn::Data& data);

  bool
  requireVerify (const ndn::Data& data);

  ndn::ptr_lib::shared_ptr<ndn::ValidationRequest>
  checkVerificationPolicy(const ndn::ptr_lib::shared_ptr<ndn::Data>& data, 
                          int stepCount, 
                          const ndn::OnVerified& onVerified,
                          const ndn::OnVerifyFailed& onVerifyFailed);

  bool 
  checkSigningPolicy(const ndn::Name& dataName, 
                     const ndn::Name& certificateName);
    
  ndn::Name 
  inferSigningIdentity(const ndn::Name& dataName);

  void
  addTrustAnchor(const ndn::IdentityCertificate& identityCertificate, bool isIntroducer);

  void
  addSyncDataRule(const ndn::Name& prefix, 
                  const ndn::IdentityCertificate& identityCertificate,
                  bool isIntroducer);

private:

  ndn::ptr_lib::shared_ptr<ndn::ValidationRequest>
  prepareIntroducerRequest(const ndn::Name& keyName,
                           ndn::ptr_lib::shared_ptr<ndn::Data> data, 
                           const int & stepCount, 
                           const ndn::OnVerified& onVerified,
                           const ndn::OnVerifyFailed& onVerifyFailed);
  
  ndn::ptr_lib::shared_ptr<const std::vector<ndn::Name> >
  getAllIntroducerName();

  ndn::ptr_lib::shared_ptr<ndn::ValidationRequest>
  prepareRequest(const ndn::Name& keyName, 
                 bool forIntroducer,
                 ndn::ptr_lib::shared_ptr<ndn::Data> data,
                 const int & stepCount, 
                 const ndn::OnVerified& onVerified,
                 const ndn::OnVerifyFailed& onVerifyFailed);

  void
  OnIntroCertInterest(const ndn::ptr_lib::shared_ptr<const ndn::Name>& prefix, 
                      const ndn::ptr_lib::shared_ptr<const ndn::Interest>& interest, 
                      ndn::Transport& transport, 
                      uint64_t registeredPrefixId);

  void
  OnIntroCertRegisterFailed(const ndn::ptr_lib::shared_ptr<const ndn::Name>& prefix);

  void
  onIntroCertVerified(const ndn::ptr_lib::shared_ptr<ndn::Data>& introCertificateData,
                      bool forIntroducer,
                      ndn::ptr_lib::shared_ptr<ndn::Data> originalData,
                      const ndn::OnVerified& onVerified,
                      const ndn::OnVerifyFailed& onVerifyFailed);

  void 
  onIntroCertVerifyFailed(const ndn::ptr_lib::shared_ptr<ndn::Data>& introCertificateData,
                          ndn::Name interestPrefix,
                          bool forIntroducer,
                          ndn::ptr_lib::shared_ptr<const std::vector<ndn::Name> > introNameList,
                          int nextIntroducerIndex,
                          ndn::ptr_lib::shared_ptr<ndn::Data> originalData,
                          const ndn::OnVerified& onVerified,
                          const ndn::OnVerifyFailed& onVerifyFailed);

  void 
  onIntroCertData(const ndn::ptr_lib::shared_ptr<const ndn::Interest> &interest,
                  const ndn::ptr_lib::shared_ptr<ndn::Data>& introCertificateData,                  
                  int stepCount,
                  const ndn::OnVerified& introCertVerified,
                  const ndn::OnVerifyFailed& introCertVerifyFailed);

  void
  onIntroCertTimeout(const ndn::ptr_lib::shared_ptr<const ndn::Interest>& interest, 
                     int retry,                      
                     int stepCount,
                     const ndn::OnVerified& introCertVerified,
                     const ndn::OnVerifyFailed& introCertVerifyFailed);



private:
  ndn::Name m_signingIdentity;
  ndn::Name m_signingCertificateName;
  ndn::Name m_syncPrefix;
  ndn::Name m_introCertPrefix;
  int m_stepLimit;
  ndn::ptr_lib::shared_ptr<ndn::SecRuleRelative> m_syncDataPolicy; 
  std::map<ndn::Name, ndn::PublicKey> m_trustedIntroducers;
  std::map<ndn::Name, ndn::PublicKey> m_trustedProducers;
  // std::map<ndn::Name, SecRuleSyncSpecific> m_chatDataRules;
  std::map<ndn::Name, ndn::Data> m_introCert;

  ndn::ptr_lib::shared_ptr<ndn::KeyChain> m_keyChain;
  ndn::ptr_lib::shared_ptr<ndn::Face> m_face;

};

#endif
