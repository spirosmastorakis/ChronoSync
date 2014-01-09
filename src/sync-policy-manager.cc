/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "sync-intro-certificate.h"
#include "sync-logging.h"
#include <ndn-cpp/security/verifier.hpp>
#include <ndn-cpp/security/signature/signature-sha256-with-rsa.hpp>

#include "sync-policy-manager.h"

using namespace ndn;
using namespace ndn::ptr_lib;
using namespace std;

INIT_LOGGER("SyncPolicyManager");

SyncPolicyManager::SyncPolicyManager(const Name& signingIdentity,
				     const Name& signingCertificateName,
				     const Name& syncPrefix,
                                     shared_ptr<Face> face,
                                     int stepLimit)
  : m_signingIdentity(signingIdentity)
  , m_signingCertificateName(signingCertificateName.getPrefix(signingCertificateName.size()-1))
  , m_syncPrefix(syncPrefix)
  , m_stepLimit(stepLimit)
  , m_keyChain(new KeyChain())
{  
  Name wotPrefix = syncPrefix;
  wotPrefix.append("WOT");
  m_syncPrefixRegex = Regex::fromName(syncPrefix);
  m_wotPrefixRegex = Regex::fromName(wotPrefix);
  m_chatDataPolicy = make_shared<IdentityPolicyRule>("^[^<%F0.>]*<%F0.>([^<chronos>]*)<chronos><>",
                                                              "^([^<KEY>]*)<KEY>(<>*)[<dsk-.*><ksk-.*>]<ID-CERT>$",
                                                              "==", "\\1", "\\1", true);  
}
  
SyncPolicyManager::~SyncPolicyManager()
{}

bool 
SyncPolicyManager::skipVerifyAndTrust (const Data& data)
{ return false; }

bool
SyncPolicyManager::requireVerify (const Data& data)
{ return true; }

shared_ptr<ValidationRequest>
SyncPolicyManager::checkVerificationPolicy(const shared_ptr<Data>& data, 
					   int stepCount, 
					   const OnVerified& onVerified,
					   const OnVerifyFailed& onVerifyFailed)
{
  if(stepCount > m_stepLimit)
    {
      onVerifyFailed(data);
      return SYNC_POLICY_MANAGER_NULL_VALIDATION_REQUEST_PTR;
    }

  try{
    SignatureSha256WithRsa sig(data->getSignature());

    const Name& keyLocatorName = sig.getKeyLocator().getName();
  
    // if data is intro cert
    if(m_wotPrefixRegex->match(data->getName()))
      {
        // _LOG_DEBUG("Intro Cert");
        Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocatorName);
        map<string, PublicKey>::const_iterator it = m_trustedIntroducers.find(keyName.toUri());
        if(m_trustedIntroducers.end() != it)
          {
            if(Verifier::verifySignature(*data, sig, it->second))
              onVerified(data);
            else
              onVerifyFailed(data);
            return SYNC_POLICY_MANAGER_NULL_VALIDATION_REQUEST_PTR;
          }
        else
          return prepareRequest(keyName, true, data, stepCount, onVerified, onVerifyFailed);
      }

    // if data is sync data or chat data
    if(m_syncPrefixRegex->match(data->getName()) || m_chatDataPolicy->satisfy(*data))
      {
        Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocatorName);

        map<string, PublicKey>::const_iterator it = m_trustedIntroducers.find(keyName.toUri());
        if(m_trustedIntroducers.end() != it)
          {
            if(Verifier::verifySignature(*data, sig, it->second))
              onVerified(data);
            else
              onVerifyFailed(data);
            return SYNC_POLICY_MANAGER_NULL_VALIDATION_REQUEST_PTR;
          }

        it = m_trustedProducers.find(keyName.toUri());
        if(m_trustedProducers.end() != it)
          {
            if(Verifier::verifySignature(*data, sig, it->second))
              onVerified(data);
            else
              onVerifyFailed(data);
            return SYNC_POLICY_MANAGER_NULL_VALIDATION_REQUEST_PTR;
          }

        return prepareRequest(keyName, false, data, stepCount, onVerified, onVerifyFailed);
      }
  }catch(SignatureSha256WithRsa::Error &e){
    _LOG_DEBUG("SyncPolicyManager Error: " << e.what());
    onVerifyFailed(data);
    return SYNC_POLICY_MANAGER_NULL_VALIDATION_REQUEST_PTR;
  }catch(KeyLocator::Error &e){
    _LOG_DEBUG("SyncPolicyManager Error: " << e.what());
    onVerifyFailed(data);
    return SYNC_POLICY_MANAGER_NULL_VALIDATION_REQUEST_PTR;
  }
    
  onVerifyFailed(data);
  return SYNC_POLICY_MANAGER_NULL_VALIDATION_REQUEST_PTR;
}

bool 
SyncPolicyManager::checkSigningPolicy(const Name& dataName, 
				      const Name& certificateName)
{ 
  return true;
}
    
Name 
SyncPolicyManager::inferSigningIdentity(const ndn::Name& dataName)
{ return m_signingIdentity; }

void
SyncPolicyManager::addTrustAnchor(const IdentityCertificate& identityCertificate, bool isIntroducer)
{
  // _LOG_DEBUG("Add intro/producer: " << identityCertificate.getPublicKeyName());
  if(isIntroducer)
    m_trustedIntroducers.insert(pair <string, PublicKey > (identityCertificate.getPublicKeyName().toUri(),
                                                           identityCertificate.getPublicKeyInfo()));
  else
    m_trustedProducers.insert(pair <string, PublicKey > (identityCertificate.getPublicKeyName().toUri(),
                                                         identityCertificate.getPublicKeyInfo()));
}

void
SyncPolicyManager::addChatDataRule(const Name& prefix, 
                                   const IdentityCertificate& identityCertificate,
                                   bool isIntroducer)
{
  addTrustAnchor(identityCertificate, isIntroducer);
}


shared_ptr<const vector<Name> >
SyncPolicyManager::getAllIntroducerName()
{
  shared_ptr<vector<Name> > nameList = make_shared<vector<Name> >();
  
  map<string, PublicKey>::iterator it =  m_trustedIntroducers.begin();
  for(; it != m_trustedIntroducers.end(); it++)
    nameList->push_back(Name(it->first));
  
  return nameList;
}

shared_ptr<ValidationRequest>
SyncPolicyManager::prepareRequest(const Name& keyName, 
				  bool forIntroducer,
				  shared_ptr<Data> data,
				  const int & stepCount, 
				  const OnVerified& onVerified,
				  const OnVerifyFailed& onVerifyFailed)
{
  shared_ptr<Name> interestPrefixName = make_shared<Name>(m_syncPrefix);
  interestPrefixName->append("WOT").append(keyName).append("INTRO-CERT");

  shared_ptr<const vector<Name> > nameList = getAllIntroducerName();
  if(0 == nameList->size())
    {
      onVerifyFailed(data);
      return SYNC_POLICY_MANAGER_NULL_VALIDATION_REQUEST_PTR;
    }

  Name interestName = *interestPrefixName;
  interestName.append(nameList->at(0));

  if(forIntroducer)
    interestName.append("INTRODUCER");

  shared_ptr<ndn::Interest> interest = make_shared<ndn::Interest>(interestName);
  // _LOG_DEBUG("send interest for intro cert: " << interest->getName());

  OnVerified requestedCertVerifiedCallback = boost::bind(&SyncPolicyManager::onIntroCertVerified, 
                                                         this, 
                                                         _1,
                                                         forIntroducer, 
                                                         data,
                                                         onVerified,
                                                         onVerifyFailed);
                                                             
  OnVerifyFailed requestedCertUnverifiedCallback = boost::bind(&SyncPolicyManager::onIntroCertVerifyFailed, 
                                                               this, 
                                                               _1, 
                                                               interestPrefixName,
                                                               forIntroducer,
                                                               nameList,
                                                               1,
                                                               data,
                                                               onVerified,
                                                               onVerifyFailed);

    
  shared_ptr<ValidationRequest> nextStep = make_shared<ValidationRequest>(interest, 
                                                                          requestedCertVerifiedCallback,
                                                                          requestedCertUnverifiedCallback,
                                                                          1,
                                                                          m_stepLimit-1);
  return nextStep;
}

void
SyncPolicyManager::OnIntroCertInterest(const shared_ptr<const Name>& prefix, 
                                       const shared_ptr<const ndn::Interest>& interest, 
                                       Transport& transport, 
                                       uint64_t registeredPrefixId)
{
  map<string, Data>::const_iterator it = m_introCert.find(prefix->toUri());

  if(m_introCert.end() != it)
    m_face->put(it->second);
}

void
SyncPolicyManager::OnIntroCertRegisterFailed(const shared_ptr<const Name>& prefix)
{
}

void
SyncPolicyManager::onIntroCertVerified(const shared_ptr<Data>& introCertificateData,
				       bool forIntroducer,
				       shared_ptr<Data> originalData,
				       const OnVerified& onVerified,
				       const OnVerifyFailed& onVerifyFailed)
{
  shared_ptr<SyncIntroCertificate> introCertificate = make_shared<SyncIntroCertificate>(*introCertificateData);
  if(forIntroducer)
    {
      m_trustedIntroducers.insert(pair <string, PublicKey > (introCertificate->getPublicKeyName().toUri(),
                                                             introCertificate->getPublicKeyInfo()));
      SyncIntroCertificate syncIntroCertificate(m_syncPrefix,
                                                introCertificate->getPublicKeyName(),
                                                m_keyChain->getDefaultKeyNameForIdentity(m_signingIdentity),
                                                introCertificate->getNotBefore(),
                                                introCertificate->getNotAfter(),
                                                introCertificate->getPublicKeyInfo(),
                                                SyncIntroCertificate::INTRODUCER);

      Name certName = m_keyChain->getDefaultCertificateNameForIdentity(m_signingIdentity);
      _LOG_DEBUG("Publish Intro Certificate on Verified: " << syncIntroCertificate.getName());
      m_keyChain->sign(syncIntroCertificate, certName);

      m_face->put(syncIntroCertificate);

      // Name prefix = syncIntroCertificate.getName().getPrefix(syncIntroCertificate.getName().size()-1);

      // map<string, Data>::const_iterator it = m_introCert.find(prefix.toEscapedString());
      // if(m_introCert.end() != it)
      //   {
      //     it->second = syncIntroCertificate;
      //   }
      // else
      //   {         
      //     m_introCert.insert(pair <string, Data> (prefix.toEscapedString(), syncIntroCertificate));
      //     m_face->registerPrefix(prefix, 
      //                           boost::bind(&SyncPolicyManager::onIntroCertInterest, this, _1, _2, _3, _4), 
      //                           boost::bind(&SyncPolicyManager::onIntroCertRegisterFailed, this, _1));
      //   }
    }
  else
    {
      m_trustedProducers.insert(pair <string, PublicKey > (introCertificate->getPublicKeyName().toUri(), 
                                                           introCertificate->getPublicKeyInfo()));
      SyncIntroCertificate syncIntroCertificate(m_syncPrefix,
                                                introCertificate->getPublicKeyName(),
                                                m_keyChain->getDefaultKeyNameForIdentity(m_signingIdentity),
                                                introCertificate->getNotBefore(),
                                                introCertificate->getNotAfter(),
                                                introCertificate->getPublicKeyInfo(),
                                                SyncIntroCertificate::PRODUCER);

      Name certName = m_keyChain->getDefaultCertificateNameForIdentity(m_signingIdentity);
      _LOG_DEBUG("Publish Intro Certificate on Verified: " << syncIntroCertificate.getName());
      m_keyChain->sign(syncIntroCertificate, certName);
      
      m_face->put(syncIntroCertificate);

      // Name prefix = syncIntroCertificate.getName().getPrefix(syncIntroCertificate.getName().size()-1);

      // map<string, Data>::const_iterator it = m_introCert.find(prefix.toEscapedString());
      // if(m_introCert.end() != it)
      //   {
      //     it->second = syncIntroCertificate;
      //   }
      // else
      //   {
      //     m_introCert.insert(pair <string, Data> (prefix.toEscapedString(), syncIntroCertificate));
      //     m_face->registerPrefix(prefix, 
      //                           boost::bind(&SyncPolicyManager::onIntroCertInterest, this, _1, _2, _3, _4), 
      //                           boost::bind(&SyncPolicyManager::onIntroCertRegisterFailed, this, _1));
      //   }
    }

  try{
    SignatureSha256WithRsa sig(originalData->getSignature());
    if(Verifier::verifySignature(*originalData, sig, introCertificate->getPublicKeyInfo()))      
      onVerified(originalData);    
    else
      onVerifyFailed(originalData);
  }catch(SignatureSha256WithRsa::Error &e){
    onVerifyFailed(originalData);
  }catch(KeyLocator::Error &e){
    onVerifyFailed(originalData);
  }
}

void 
SyncPolicyManager::onIntroCertVerifyFailed(const shared_ptr<Data>& introCertificateData,
                                           shared_ptr<Name> interestPrefixName,
                                           bool forIntroducer,
                                           shared_ptr<const vector<Name> > introNameList,
                                           int nextIntroducerIndex,
                                           shared_ptr<Data> originalData,
                                           const OnVerified& onVerified,
                                           const OnVerifyFailed& onVerifyFailed)
{
  Name interestName = *interestPrefixName;
  if(nextIntroducerIndex < introNameList->size())
    interestName.append(introNameList->at(nextIntroducerIndex));
  else
    onVerifyFailed(originalData);

  if(forIntroducer)
    interestName.append("INTRODUCER");
  
  shared_ptr<ndn::Interest> interest = make_shared<ndn::Interest>(interestName);

  OnVerified onRecursiveVerified = boost::bind(&SyncPolicyManager::onIntroCertVerified, 
                                      this, 
                                      _1,
                                      forIntroducer, 
                                      originalData,
                                      onVerified,
                                      onVerifyFailed);

  OnVerifyFailed onRecursiveVerifyFailed = boost::bind(&SyncPolicyManager::onIntroCertVerifyFailed, 
                                              this, 
                                              _1,
                                              interestPrefixName,
                                              forIntroducer,
                                              introNameList,
                                              nextIntroducerIndex + 1,
                                              originalData, 
                                              onVerified,
                                              onVerifyFailed);
        
  m_face->expressInterest(*interest, 
                          boost::bind(&SyncPolicyManager::onIntroCertData,
                                      this,
                                      _1,
                                      _2,     
                                      m_stepLimit-1,
                                      onRecursiveVerified,
                                      onRecursiveVerifyFailed,
                                      originalData,
                                      onVerifyFailed),
                          boost::bind(&SyncPolicyManager::onIntroCertTimeout, 
                                      this,
                                      _1,
                                      1,
                                      m_stepLimit-1,
                                      onRecursiveVerified,
                                      onRecursiveVerifyFailed,
                                      originalData,
                                      onVerifyFailed));
}

void
SyncPolicyManager::onIntroCertData(const shared_ptr<const ndn::Interest> &interest,
                                   const shared_ptr<Data>& introCertificateData,
                                   int stepCount,
                                   const OnVerified& onRecursiveVerified,
                                   const OnVerifyFailed& onRecursiveVerifyFailed,
                                   shared_ptr<Data> originalData,
                                   const OnVerifyFailed& onVerifyFailed)
{
  shared_ptr<ValidationRequest> nextStep = checkVerificationPolicy(introCertificateData, stepCount, onRecursiveVerified, onRecursiveVerifyFailed);
  if (nextStep)
    m_face->expressInterest
      (*nextStep->interest_, 
       boost::bind(&SyncPolicyManager::onIntroCertData, 
                   this, 
                   _1, 
                   _2,
                   nextStep->stepCount_,
                   nextStep->onVerified_, 
                   nextStep->onVerifyFailed_,
                   introCertificateData,
                   onRecursiveVerifyFailed), 
       boost::bind(&SyncPolicyManager::onIntroCertTimeout, 
                   this, 
                   _1, 
                   nextStep->retry_, 
                   nextStep->stepCount_, 
                   nextStep->onVerified_, 
                   nextStep->onVerifyFailed_,
                   introCertificateData,
                   onRecursiveVerifyFailed));
}

void
SyncPolicyManager::onIntroCertTimeout(const shared_ptr<const ndn::Interest>& interest, 
				      int retry, 
                                      int stepCount,
                                      const OnVerified& onRecursiveVerified,
                                      const OnVerifyFailed& onRecursiveVerifyFailed,
                                      shared_ptr<Data> originalData,
                                      const OnVerifyFailed& onVerifyFailed)
{
  if(retry > 0)
    {
      m_face->expressInterest(*interest, 
                              boost::bind(&SyncPolicyManager::onIntroCertData, 
                                          this,
                                          _1,
                                          _2,
                                          stepCount,
                                          onRecursiveVerified,
                                          onRecursiveVerifyFailed,
                                          originalData,
                                          onVerifyFailed),
                              boost::bind(&SyncPolicyManager::onIntroCertTimeout, 
                                          this,
                                          _1,
                                          retry - 1,
                                          stepCount,
                                          onRecursiveVerified,
                                          onRecursiveVerifyFailed,
                                          originalData,
                                          onVerifyFailed));
    }
  else
    onVerifyFailed(originalData);
}
