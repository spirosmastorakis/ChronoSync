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

#include <ndn.cxx/security/policy/policy-manager.h>
#include <ndn.cxx/security/policy/identity-policy-rule.h>
#include <ndn.cxx/security/certificate/identity-certificate.h>
#include <ndn.cxx/regex/regex.h>
#include <ndn.cxx/wrapper/wrapper.h>
#include "specific-policy-rule.h"


class SyncPolicyManager : public ndn::security::PolicyManager
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

  ndn::Ptr<ndn::security::ValidationRequest>
  checkVerificationPolicy(ndn::Ptr<ndn::Data> data, 
                          const int& stepCount, 
                          const ndn::DataCallback& verifiedCallback,
                          const ndn::UnverifiedCallback& unverifiedCallback);

  bool 
  checkSigningPolicy(const ndn::Name& dataName, 
                     const ndn::Name& certificateName);
    
  ndn::Name 
  inferSigningIdentity(const ndn::Name& dataName);

  void
  addTrustAnchor(const ndn::security::IdentityCertificate& identityCertificate, bool isIntroducer);

  void
  addChatDataRule(const ndn::Name& prefix, 
                  const ndn::security::IdentityCertificate& identityCertificate,
                  bool isIntroducer);

  inline void 
  setWrapper(ndn::Wrapper* handler)
  { m_handler = handler; }

private:
  ndn::Ptr<ndn::security::ValidationRequest>
  prepareIntroducerRequest(const ndn::Name& keyName,
                           ndn::Ptr<ndn::Data> data, 
                           const int & stepCount, 
                           const ndn::DataCallback& verifiedCallback,
                           const ndn::UnverifiedCallback& unverifiedCallback);
  
  ndn::Ptr<const std::vector<ndn::Name> >
  getAllIntroducerName();

  ndn::Ptr<ndn::security::ValidationRequest>
  prepareRequest(const ndn::Name& keyName, 
                 bool forIntroducer,
                 ndn::Ptr<ndn::Data> data,
                 const int & stepCount, 
                 const ndn::DataCallback& verifiedCallback,
                 const ndn::UnverifiedCallback& unverifiedCallback);

  void
  onIntroCertVerified(ndn::Ptr<ndn::Data> introCertificateData,
                      bool forIntroducer,
                      ndn::Ptr<ndn::Data> originalData,
                      const ndn::DataCallback& verifiedCallback,
                      const ndn::UnverifiedCallback& unverifiedCallback);

  void 
  onIntroCertUnverified(ndn::Ptr<ndn::Data> introCertificateData,
                        ndn::Ptr<ndn::Name> interestPrefixName,
                        bool forIntroducer,
                        ndn::Ptr<const std::vector<ndn::Name> > introNameList,
                        const int& nextIntroducerIndex,
                        ndn::Ptr<ndn::Data> originalData,
                        const ndn::DataCallback& verifiedCallback,
                        const ndn::UnverifiedCallback& unverifiedCallback);

  void
  onIntroCertTimeOut(ndn::Ptr<ndn::Closure> closure, 
                     ndn::Ptr<ndn::Interest> interest, 
                     int retry, 
                     const ndn::UnverifiedCallback& unverifiedCallback,
                     ndn::Ptr<ndn::Data> data);



private:
  ndn::Name m_signingIdentity;
  ndn::Name m_signingCertificateName;
  ndn::Name m_syncPrefix;
  int m_stepLimit;
  ndn::Ptr<ndn::Regex> m_syncPrefixRegex;
  ndn::Ptr<ndn::Regex> m_wotPrefixRegex;
  ndn::Ptr<ndn::security::IdentityPolicyRule> m_chatDataPolicy; 
  std::map<ndn::Name, ndn::security::Publickey> m_trustedIntroducers;
  std::map<ndn::Name, ndn::security::Publickey> m_trustedProducers;
  std::map<ndn::Name, SpecificPolicyRule> m_chatDataRules;

  ndn::Wrapper* m_handler;
};

#endif
