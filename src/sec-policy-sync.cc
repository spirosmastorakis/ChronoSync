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
#include <ndn-cpp-dev/security/verifier.hpp>
#include <ndn-cpp-dev/security/signature-sha256-with-rsa.hpp>

#include "sec-policy-sync.h"

using namespace ndn;
using namespace ndn::ptr_lib;
using namespace std;

INIT_LOGGER("SecPolicySync");

SecPolicySync::SecPolicySync(const Name& signingIdentity,
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
  m_introCertPrefix = syncPrefix;
  m_introCertPrefix.append("WOT");

  m_syncDataPolicy = make_shared<SecRuleRelative>("^[^<%F0\\.>]*<%F0\\.>([^<chronos>]*)<chronos><>",
                                                  "^([^<KEY>]*)<KEY>(<>*)[<dsk-.*><ksk-.*>]<ID-CERT>$",
                                                  "==", "\\1", "\\1", true);  
}
  
SecPolicySync::~SecPolicySync()
{}

bool 
SecPolicySync::skipVerifyAndTrust (const Data& data)
{ return false; }

bool
SecPolicySync::requireVerify (const Data& data)
{ return true; }

shared_ptr<ValidationRequest>
SecPolicySync::checkVerificationPolicy(const shared_ptr<Data>& data, 
                                       int stepCount, 
                                       const OnVerified& onVerified,
                                       const OnVerifyFailed& onVerifyFailed)
{
  if(stepCount > m_stepLimit)
    {
      onVerifyFailed(data);
      return shared_ptr<ValidationRequest>();
    }

  try{
    SignatureSha256WithRsa sig(data->getSignature());
    const Name& keyLocatorName = sig.getKeyLocator().getName();

    // if data is intro cert
    if(m_introCertPrefix.isPrefixOf(data->getName()))
      {
        Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocatorName);
        map<Name, PublicKey>::const_iterator it = m_trustedIntroducers.find(keyName);
        if(m_trustedIntroducers.end() != it)
          {
            if(Verifier::verifySignature(*data, sig, it->second))
              onVerified(data);
            else
              onVerifyFailed(data);
            return shared_ptr<ValidationRequest>();
          }
        else
          return prepareRequest(keyName, true, data, stepCount, onVerified, onVerifyFailed);
      }
  
    // if data is diff data or sync data
    if(m_syncPrefix.isPrefixOf(data->getName()) || m_syncDataPolicy->satisfy(*data))
      {
        Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocatorName);

        map<Name, PublicKey>::const_iterator it = m_trustedIntroducers.find(keyName);
        if(m_trustedIntroducers.end() != it)
          {
            if(Verifier::verifySignature(*data, sig, it->second))
              onVerified(data);
            else
              onVerifyFailed(data);
            return shared_ptr<ValidationRequest>();
          }

        it = m_trustedProducers.find(keyName);
        if(m_trustedProducers.end() != it)
          {
            if(Verifier::verifySignature(*data, sig, it->second))
              onVerified(data);
            else
              onVerifyFailed(data);
            return shared_ptr<ValidationRequest>();
          }

        return prepareRequest(keyName, false, data, stepCount, onVerified, onVerifyFailed);
      }

  }catch(SignatureSha256WithRsa::Error &e){
    _LOG_DEBUG("SecPolicySync Error: " << e.what());
    onVerifyFailed(data);
    return shared_ptr<ValidationRequest>();
  }catch(KeyLocator::Error &e){
    _LOG_DEBUG("SecPolicySync Error: " << e.what());
    onVerifyFailed(data);
    return shared_ptr<ValidationRequest>();
  }
    
  onVerifyFailed(data);
  return shared_ptr<ValidationRequest>();
}

bool 
SecPolicySync::checkSigningPolicy(const Name& dataName, 
                                  const Name& certificateName)
{ 
  return true;
}
    
Name 
SecPolicySync::inferSigningIdentity(const ndn::Name& dataName)
{ return m_signingIdentity; }

void
SecPolicySync::addTrustAnchor(const IdentityCertificate& identityCertificate, bool isIntroducer)
{
  Name publicKeyName = identityCertificate.getPublicKeyName();

  _LOG_DEBUG("Add intro/producer: " << publicKeyName);

  if(isIntroducer)
    m_trustedIntroducers[publicKeyName] = identityCertificate.getPublicKeyInfo();
  else
    m_trustedProducers[publicKeyName] = identityCertificate.getPublicKeyInfo();
}

void
SecPolicySync::addSyncDataRule(const Name& prefix, 
                               const IdentityCertificate& identityCertificate,
                               bool isIntroducer)
{ addTrustAnchor(identityCertificate, isIntroducer); }


shared_ptr<const vector<Name> >
SecPolicySync::getAllIntroducerName()
{
  shared_ptr<vector<Name> > nameList = make_shared<vector<Name> >();
  
  map<Name, PublicKey>::iterator it =  m_trustedIntroducers.begin();
  for(; it != m_trustedIntroducers.end(); it++)
    nameList->push_back(it->first);
  
  return nameList;
}

shared_ptr<ValidationRequest>
SecPolicySync::prepareRequest(const Name& keyName, 
                              bool forIntroducer,
                              shared_ptr<Data> data,
                              const int & stepCount, 
                              const OnVerified& onVerified,
                              const OnVerifyFailed& onVerifyFailed)
{
  Name interestPrefix = m_syncPrefix;
  interestPrefix.append("WOT").append(keyName.wireEncode()).append("INTRO-CERT");

  shared_ptr<const vector<Name> > nameList = getAllIntroducerName();
  if(0 == nameList->size())
    {
      onVerifyFailed(data);
      return shared_ptr<ValidationRequest>();
    }

  Name interestName = interestPrefix;
  interestName.append(nameList->at(0).wireEncode());

  if(forIntroducer)
    interestName.append("INTRODUCER");

  shared_ptr<ndn::Interest> interest = make_shared<ndn::Interest>(interestName);

  OnVerified introCertVerified = func_lib::bind(&SecPolicySync::onIntroCertVerified, 
                                                this, 
                                                _1,
                                                forIntroducer,
                                                data,
                                                onVerified,
                                                onVerifyFailed);
                                                             
  OnVerifyFailed introCertVerifyFailed = func_lib::bind(&SecPolicySync::onIntroCertVerifyFailed, 
                                                        this, 
                                                        _1, 
                                                        interestPrefix,
                                                        forIntroducer,
                                                        nameList,
                                                        1,
                                                        data,
                                                        onVerified,
                                                        onVerifyFailed);

    
  shared_ptr<ValidationRequest> nextStep = make_shared<ValidationRequest>(interest, 
                                                                          introCertVerified,
                                                                          introCertVerifyFailed,
                                                                          1,
                                                                          m_stepLimit-1);
  return nextStep;
}

void
SecPolicySync::OnIntroCertInterest(const shared_ptr<const Name>& prefix, 
                                   const shared_ptr<const ndn::Interest>& interest, 
                                   Transport& transport, 
                                   uint64_t registeredPrefixId)
{
  map<Name, Data>::const_iterator it = m_introCert.find(*prefix);

  if(m_introCert.end() != it)
    m_face->put(it->second);
}

void
SecPolicySync::OnIntroCertRegisterFailed(const shared_ptr<const Name>& prefix)
{
}

void
SecPolicySync::onIntroCertVerified(const shared_ptr<Data>& introCertificateData,
                                   bool forIntroducer,
                                   shared_ptr<Data> originalData,
                                   const OnVerified& onVerified,
                                   const OnVerifyFailed& onVerifyFailed)
{
  shared_ptr<SyncIntroCertificate> introCertificate = make_shared<SyncIntroCertificate>(*introCertificateData);
  Name subjectKeyName = introCertificate->getPublicKeyName();

  if(forIntroducer)
    {
      //Add the intro cert subject as trusted introducer.
      m_trustedIntroducers[subjectKeyName] = introCertificate->getPublicKeyInfo();

      //Generate another intro cert for the cert subject.
      SyncIntroCertificate syncIntroCertificate(m_syncPrefix,
                                                subjectKeyName,
                                                m_keyChain->getDefaultKeyNameForIdentity(m_signingIdentity),
                                                introCertificate->getNotBefore(),
                                                introCertificate->getNotAfter(),
                                                introCertificate->getPublicKeyInfo(),
                                                SyncIntroCertificate::INTRODUCER);
      m_keyChain->signByIdentity(syncIntroCertificate, m_signingIdentity);
      m_face->put(syncIntroCertificate);

      // Name prefix = syncIntroCertificate.getName().getPrefix(syncIntroCertificate.getName().size()-1);

      // map<string, Data>::const_iterator it = m_introCert.find(prefix);
      // if(m_introCert.end() != it)
      //   {
      //     it->second = syncIntroCertificate;
      //   }
      // else
      //   {         
      //     m_introCert.insert(pair <Name, Data> (prefix, syncIntroCertificate));
      //     m_face->registerPrefix(prefix, 
      //                           boost::bind(&SecPolicySync::onIntroCertInterest, this, _1, _2, _3, _4), 
      //                           boost::bind(&SecPolicySync::onIntroCertRegisterFailed, this, _1));
      //   }
    }
  else
    {
      //Add the intro cert subject as trusted producer.
      m_trustedProducers[subjectKeyName] = introCertificate->getPublicKeyInfo();

      //Generate another intro cert for the cert subject.
      SyncIntroCertificate syncIntroCertificate(m_syncPrefix,
                                                subjectKeyName,
                                                m_keyChain->getDefaultKeyNameForIdentity(m_signingIdentity),
                                                introCertificate->getNotBefore(),
                                                introCertificate->getNotAfter(),
                                                introCertificate->getPublicKeyInfo(),
                                                SyncIntroCertificate::PRODUCER);
      m_keyChain->signByIdentity(syncIntroCertificate, m_signingIdentity);
      m_face->put(syncIntroCertificate);

      // Name prefix = syncIntroCertificate.getName().getPrefix(syncIntroCertificate.getName().size()-1);

      // map<string, Data>::const_iterator it = m_introCert.find(prefix);
      // if(m_introCert.end() != it)
      //   {
      //     it->second = syncIntroCertificate;
      //   }
      // else
      //   {
      //     m_introCert.insert(pair <Name, Data> (prefix, syncIntroCertificate));
      //     m_face->registerPrefix(prefix, 
      //                           boost::bind(&SecPolicySync::onIntroCertInterest, this, _1, _2, _3, _4), 
      //                           boost::bind(&SecPolicySync::onIntroCertRegisterFailed, this, _1));
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
SecPolicySync::onIntroCertVerifyFailed(const shared_ptr<Data>& introCertificateData,
                                       Name interestPrefix,
                                       bool forIntroducer,
                                       shared_ptr<const vector<Name> > introNameList,
                                       int nextIntroducerIndex,
                                       shared_ptr<Data> originalData,
                                       const OnVerified& onVerified,
                                       const OnVerifyFailed& onVerifyFailed)
{
  Name interestName = interestPrefix;
  if(nextIntroducerIndex < introNameList->size())
    interestName.append(introNameList->at(nextIntroducerIndex).wireEncode());
  else
    onVerifyFailed(originalData);

  if(forIntroducer)
    interestName.append("INTRODUCER");
  
  ndn::Interest interest(interestName);

  OnVerified introCertVerified = func_lib::bind(&SecPolicySync::onIntroCertVerified, 
                                                this, 
                                                _1,
                                                forIntroducer, 
                                                originalData,
                                                onVerified,
                                                onVerifyFailed);

  OnVerifyFailed introCertVerifyFailed = func_lib::bind(&SecPolicySync::onIntroCertVerifyFailed, 
                                                        this, 
                                                        _1,
                                                        interestPrefix,
                                                        forIntroducer,
                                                        introNameList,
                                                        nextIntroducerIndex + 1,
                                                        originalData, 
                                                        onVerified,
                                                        onVerifyFailed);
        
  m_face->expressInterest(interest, 
                          func_lib::bind(&SecPolicySync::onIntroCertData,
                                         this,
                                         _1,
                                         _2,     
                                         m_stepLimit-1,
                                         introCertVerified,
                                         introCertVerifyFailed),
                          func_lib::bind(&SecPolicySync::onIntroCertTimeout, 
                                         this,
                                         _1,
                                         1,
                                         m_stepLimit-1,
                                         introCertVerified,
                                         introCertVerifyFailed)
                          );
}

void
SecPolicySync::onIntroCertData(const shared_ptr<const ndn::Interest> &interest,
                               const shared_ptr<Data>& introCertificateData,
                               int stepCount,
                               const OnVerified& introCertVerified,
                               const OnVerifyFailed& introCertVerifyFailed)
{
  shared_ptr<ValidationRequest> nextStep = checkVerificationPolicy(introCertificateData, stepCount, introCertVerified, introCertVerifyFailed);
  if (nextStep)
    m_face->expressInterest(*nextStep->interest_, 
                            func_lib::bind(&SecPolicySync::onIntroCertData, 
                                           this, 
                                           _1, 
                                           _2,
                                           nextStep->stepCount_,
                                           nextStep->onVerified_, 
                                           nextStep->onVerifyFailed_), 
                            func_lib::bind(&SecPolicySync::onIntroCertTimeout, 
                                           this, 
                                           _1, 
                                           nextStep->retry_, 
                                           nextStep->stepCount_, 
                                           nextStep->onVerified_, 
                                           nextStep->onVerifyFailed_)
                            );
}

void
SecPolicySync::onIntroCertTimeout(const shared_ptr<const ndn::Interest>& interest, 
                                  int retry, 
                                  int stepCount,
                                  const OnVerified& introCertVerified,
                                  const OnVerifyFailed& introCertVerifyFailed)
{
  if(retry > 0)
    m_face->expressInterest(*interest, 
                            func_lib::bind(&SecPolicySync::onIntroCertData, 
                                           this,
                                           _1,
                                           _2,
                                           stepCount,
                                           introCertVerified,
                                           introCertVerifyFailed),
                            func_lib::bind(&SecPolicySync::onIntroCertTimeout, 
                                           this,
                                           _1,
                                           retry - 1,
                                           stepCount,
                                           introCertVerified,
                                           introCertVerifyFailed)
                            );
  else
    introCertVerifyFailed(shared_ptr<Data>());
}
