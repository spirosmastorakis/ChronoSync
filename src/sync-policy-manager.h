/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SYNC_POLICY_MANAGER_H
#define SYNC_POLICY_MANAGER_H

#include <ndn-cpp/face.hpp>
#include <ndn-cpp/security/identity/identity-manager.hpp>
#include <ndn-cpp/security/policy/policy-manager.hpp>
#include <ndn-cpp/security/certificate/identity-certificate.hpp>
#include <ndn-cpp-et/regex/regex.hpp>
#include <ndn-cpp-et/policy-manager/identity-policy-rule.hpp>
#include <map>

#include "specific-policy-rule.h"

static ndn::ptr_lib::shared_ptr<ndn::ValidationRequest> SYNC_POLICY_MANAGER_NULL_VALIDATION_REQUEST_PTR;

class SyncPolicyManager : public ndn::PolicyManager
{
public:
  SyncPolicyManager(const ndn::Name& signingIdentity,
                    const ndn::Name& signingCertificateName,
                    const ndn::Name& syncPrefix,
                    int m_stepLimit = 3);
  
  virtual
  ~SyncPolicyManager();

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
  addChatDataRule(const ndn::Name& prefix, 
                  const ndn::IdentityCertificate& identityCertificate,
                  bool isIntroducer);

  // inline void 
  // setFace(ndn::ndn::ptr_lib::shared_ptr<Face> face) 
  // { face_ = face; }

private:
  void
  connectToDaemon();

  void
  onConnectionData(const ndn::ptr_lib::shared_ptr<const ndn::Interest>& interest,
                   const ndn::ptr_lib::shared_ptr<ndn::Data>& data);
 
  void
  onConnectionDataTimeout(const ndn::ptr_lib::shared_ptr<const ndn::Interest>& interest);

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
                          ndn::ptr_lib::shared_ptr<ndn::Name> interestPrefixName,
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
                  const ndn::OnVerified& onRecursiveVerified,
                  const ndn::OnVerifyFailed& onRecursiveVerifyFailed,
                  ndn::ptr_lib::shared_ptr<ndn::Data> originalData,
                  const ndn::OnVerifyFailed& onVerifyFailed);

  void
  onIntroCertTimeout(const ndn::ptr_lib::shared_ptr<const ndn::Interest>& interest, 
                     int retry,                      
                     int stepCount,
                     const ndn::OnVerified& onRecursiveVerified,
                     const ndn::OnVerifyFailed& onRecursiveVerifyFailed,
                     ndn::ptr_lib::shared_ptr<ndn::Data> originalData,
                     const ndn::OnVerifyFailed& onVerifyFailed);



private:
  ndn::Name m_signingIdentity;
  ndn::Name m_signingCertificateName;
  ndn::Name m_syncPrefix;
  int m_stepLimit;
  ndn::ptr_lib::shared_ptr<ndn::Regex> m_syncPrefixRegex;
  ndn::ptr_lib::shared_ptr<ndn::Regex> m_wotPrefixRegex;
  ndn::ptr_lib::shared_ptr<ndn::IdentityPolicyRule> m_chatDataPolicy; 
  std::map<std::string, ndn::PublicKey> m_trustedIntroducers;
  std::map<std::string, ndn::PublicKey> m_trustedProducers;
  std::map<std::string, SpecificPolicyRule> m_chatDataRules;
  std::map<std::string, ndn::Data> m_introCert;

  ndn::ptr_lib::shared_ptr<ndn::IdentityManager> m_identityManager;
  ndn::ptr_lib::shared_ptr<ndn::Transport> m_transport;
  ndn::ptr_lib::shared_ptr<ndn::Face> m_face;

};

#endif
